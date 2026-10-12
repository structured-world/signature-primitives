"""Merge reviewed Dependabot heads using metadata, never executable PR content."""

import argparse
import base64
import json
import os
import re
import subprocess
import tomllib
import urllib.parse

CRITICAL = {"hashbrown", "allocator-api2"}
CODEX = "chatgpt-codex-connector[bot]"


class GitHubError(RuntimeError):
    pass


def review_clear(sha, pushed, reactions, reviews, unresolved, writable):
    if unresolved:
        return False
    latest = {}
    for review in sorted(reviews, key=lambda r: r.get("submitted_at") or ""):
        if review["state"] in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED"):
            latest[review["user"]["login"]] = review
    if any(r["state"] == "CHANGES_REQUESTED" for r in latest.values()):
        return False
    signals = [r for r in reactions if r["user"]["login"] == CODEX
               and r["content"] in ("+1", "eyes")]
    if signals:
        last = max(signals, key=lambda r: (r["created_at"], r["content"] == "eyes"))
        # Missing push evidence fails closed; author timestamps are not push times.
        if last["content"] == "eyes" and (not pushed or last["created_at"] >= pushed):
            return False
        if last["content"] == "+1" and pushed and last["created_at"] > pushed:
            return True
    return any(r["state"] == "APPROVED" and r["commit_id"] == sha
               and r.get("author_association") in ("OWNER", "MEMBER", "COLLABORATOR")
               and writable(r["user"]["login"])
               for r in latest.values())


def contract_changed(filename, before, after):
    def critical(data):
        doc = tomllib.loads(data.decode("utf-8"))
        if filename.endswith("Cargo.lock"):
            return sorted(json.dumps(p, sort_keys=True) for p in doc.get("package", [])
                          if p["name"] in CRITICAL)
        found = []

        def walk(node, path=()):
            if not isinstance(node, dict):
                return
            for key, value in node.items():
                if key in CRITICAL or (isinstance(value, dict) and value.get("package") in CRITICAL):
                    found.append((path + (key,), json.dumps(value, sort_keys=True)))
                walk(value, path + (key,))
        walk(doc)
        return sorted(found)
    return critical(before) != critical(after)


class GitHub:
    def __init__(self, repository, token):
        self.repository = repository
        self.token = token

    def request(self, path, method="GET", body=None, token=None, paginate=False):
        # gh owns authentication, TLS and API transport; no credential enters argv.
        command = ["gh", "api", path, "--method", method,
                   "-H", "X-GitHub-Api-Version: 2022-11-28"]
        if body is not None:
            command.extend(["--input", "-"])
        if paginate:
            command.extend(["--paginate", "--slurp"])
        environment = os.environ.copy()
        environment["GH_TOKEN"] = self.token if token is None else token
        result = subprocess.run(command, input=None if body is None else json.dumps(body),
                                text=True, capture_output=True, env=environment, timeout=30)
        if result.returncode:
            raise GitHubError(result.stderr)
        return json.loads(result.stdout)

    def repo(self, path):
        return f"repos/{self.repository}/{path}"

    def pages(self, path):
        separator = "&" if "?" in path else "?"
        # gh follows server Link URLs, including activity's before/after cursors.
        for values in self.request(f"{path}{separator}per_page=100", paginate=True):
            yield from values

    def content(self, path, sha):
        encoded = urllib.parse.quote(path, safe="/")
        result = self.request(self.repo(f"contents/{encoded}?ref={sha}"))
        if result["encoding"] != "base64":
            raise ValueError("Unexpected file encoding")
        return base64.b64decode(result["content"])

    def unresolved(self, number):
        owner, name = self.repository.split("/")
        cursor = None
        while True:
            result = self.request("graphql", "POST", {
                "query": """query($owner:String!,$name:String!,$number:Int!,$cursor:String){
                  repository(owner:$owner,name:$name){pullRequest(number:$number){
                    reviewThreads(first:100,after:$cursor){nodes{isResolved}
                      pageInfo{hasNextPage endCursor}}}}}""",
                "variables": {"owner": owner, "name": name, "number": number, "cursor": cursor}})
            if result.get("errors"):
                raise ValueError("Cannot verify review threads")
            threads = result["data"]["repository"]["pullRequest"]["reviewThreads"]
            if any(not t["isResolved"] for t in threads["nodes"]):
                return True
            if not threads["pageInfo"]["hasNextPage"]:
                return False
            cursor = threads["pageInfo"]["endCursor"]

    def writable(self, login):
        user = urllib.parse.quote(login, safe="")
        permission = self.request(self.repo(f"collaborators/{user}/permission"))
        # The API maps maintain to write and triage to read, including custom roles.
        return permission["permission"] in ("admin", "write")

    def inspect(self, number):
        pr = self.request(self.repo(f"pulls/{number}"))
        if (pr["user"]["login"] != "dependabot[bot]" or pr["state"] != "open"
                or pr["draft"] or pr["base"]["ref"] != "main"
                or pr["head"]["repo"]["full_name"] != self.repository):
            return pr, "ineligible"
        if any(re.search(r"(?<![\w-])" + re.escape(name) + r"(?![\w-])", pr["title"])
               for name in CRITICAL):
            return pr, "manual contract review"
        for file in self.pages(self.repo(f"pulls/{number}/files")):
            name = file["filename"]
            if not name.endswith(("Cargo.toml", "Cargo.lock")):
                continue
            before = b"" if file["status"] == "added" else self.content(name, pr["base"]["sha"])
            after = b"" if file["status"] == "removed" else self.content(name, pr["head"]["sha"])
            if contract_changed(name, before, after):
                return pr, "manual contract review"
        # Native branch protection enforces every required check and base freshness.
        if pr["mergeable_state"] != "clean":
            return pr, "waiting for mandatory CI/base qualification"
        ref = urllib.parse.quote("refs/heads/" + pr["head"]["ref"], safe="")
        # Live responses for our pinned 2022-11-28 API expose timestamp here.
        # The docs' pushed_at example differs; the positive activity regression
        # preserves the observed wire contract rather than commit-author dates.
        pushed = next((a["timestamp"] for a in self.pages(self.repo(f"activity?ref={ref}"))
                       if a["after"] == pr["head"]["sha"]), None)
        reactions = list(self.pages(self.repo(f"issues/{number}/reactions")))
        reviews = list(self.pages(self.repo(f"pulls/{number}/reviews")))
        if not review_clear(pr["head"]["sha"], pushed, reactions, reviews,
                            self.unresolved(number), self.writable):
            return pr, "waiting for fresh clean review"
        return pr, "ready"

    def merge(self, pr, token):
        # The native merge operation atomically refuses a head changed since inspection.
        return self.request(self.repo(f"pulls/{pr['number']}/merge"), "PUT",
                            {"sha": pr["head"]["sha"], "merge_method": "squash"}, token=token)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--github-output", action="store_true")
    options = parser.parse_args()
    repository = os.environ["GITHUB_REPOSITORY"]
    if repository != "structured-world/signature-primitives":
        raise ValueError("Unsupported repository")
    api = GitHub(repository, os.environ["GH_TOKEN"])
    numbers = [p["number"] for p in api.pages(api.repo("pulls?state=open&base=main"))
               if p["user"]["login"] == "dependabot[bot]"]
    eligible = 0
    for number in numbers:
        pr, verdict = api.inspect(number)
        print(f"PR #{number} {pr['head']['sha'][:12]}: {verdict}", flush=True)
        if verdict == "ready":
            eligible += 1
        if verdict == "ready" and not options.dry_run:
            try:
                result = api.merge(pr, os.environ["MERGE_TOKEN"])
            except GitHubError as error:
                if not any(f"HTTP {code}" in str(error) for code in (405, 409)):
                    raise
                print(f"PR #{number}: branch/check state changed; waiting for next event")
                continue
            if not result["merged"]:
                raise ValueError("GitHub refused merge")
            print(f"PR #{number}: merged {result['sha']}", flush=True)
    if options.github_output:
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
            output.write(f"eligible_count={eligible}\n")


if __name__ == "__main__":
    main()
