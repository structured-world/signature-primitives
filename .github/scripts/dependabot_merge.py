"""Merge green Dependabot heads using metadata, never executable PR content."""

import argparse
import base64
import json
import os
import re
import subprocess
import tomllib
import urllib.parse

CRITICAL = {"hashbrown", "allocator-api2"}
READY = "ready"
UPDATE = "base update needed"


class GitHubError(RuntimeError):
    pass


def candidate_state(pr, repository):
    if (pr["user"]["login"] != "dependabot[bot]" or pr["state"] != "open"
            or pr["draft"] or pr["base"]["ref"] != "main"
            or pr["head"]["repo"]["full_name"] != repository):
        return "ineligible"
    if any(re.search(r"(?<![\w-])" + re.escape(name) + r"(?![\w-])", pr["title"])
           for name in CRITICAL):
        return "manual contract review"
    # Strict repository rules enforce the required CI contexts and fresh base.
    if pr["mergeable_state"] == "behind":
        return UPDATE
    if pr["mergeable_state"] == "clean":
        return READY
    return "waiting for mandatory CI/base qualification"


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
        self.contents = {}

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
        print(f"GitHub {method} {path}", flush=True)
        result = subprocess.run(command, input=None if body is None else json.dumps(body),
                                text=True, capture_output=True, env=environment, timeout=30)
        if result.returncode:
            raise GitHubError(result.stderr)
        return json.loads(result.stdout)

    def repo(self, path):
        return f"repos/{self.repository}/{path}"

    def pages(self, path):
        separator = "&" if "?" in path else "?"
        for values in self.request(f"{path}{separator}per_page=100", paginate=True):
            yield from values

    def content(self, path, sha):
        key = (path, sha)
        if key in self.contents:
            return self.contents[key]
        encoded = urllib.parse.quote(path, safe="/")
        result = self.request(self.repo(f"contents/{encoded}?ref={sha}"))
        if result["encoding"] != "base64":
            raise ValueError("Unexpected file encoding")
        value = base64.b64decode(result["content"])
        self.contents[key] = value
        return value

    def inspect(self, number):
        print(f"Inspect PR #{number}", flush=True)
        pr = self.request(self.repo(f"pulls/{number}"))
        state = candidate_state(pr, self.repository)
        if state not in (READY, UPDATE):
            return pr, state
        for file in self.pages(self.repo(f"pulls/{number}/files")):
            name = file["filename"]
            if not name.endswith(("Cargo.toml", "Cargo.lock")):
                continue
            before = b"" if file["status"] == "added" else self.content(name, pr["base"]["sha"])
            after = b"" if file["status"] == "removed" else self.content(name, pr["head"]["sha"])
            if contract_changed(name, before, after):
                return pr, "manual contract review"
        return pr, state

    def merge(self, pr, token):
        # The native merge operation atomically refuses a head changed since inspection.
        return self.request(self.repo(f"pulls/{pr['number']}/merge"), "PUT",
                            {"sha": pr["head"]["sha"], "merge_method": "squash"}, token=token)

    def update(self, pr, token, bot):
        # Dependabot owns the rebase and subsequent CI. The source/base marker
        # suppresses duplicate commands while that asynchronous work is pending.
        body = ("@dependabot rebase\n\n"
                f"<!-- rebase head={pr['head']['sha']} base={pr['base']['sha']} -->")
        for comment in self.pages(self.repo(f"issues/{pr['number']}/comments")):
            if comment["user"]["login"] == bot and comment["body"] == body:
                print(f"PR #{pr['number']}: rebase already requested", flush=True)
                return None
        return self.request(self.repo(f"issues/{pr['number']}/comments"), "POST",
                            {"body": body}, token=token)

    def apply(self, plan, token, bot):
        number = plan["number"]
        if plan["verdict"] not in (READY, UPDATE):
            raise ValueError("Invalid action plan")
        pr = self.request(self.repo(f"pulls/{number}"))
        state = candidate_state(pr, self.repository)
        if (pr["head"]["sha"] != plan["head"] or pr["base"]["sha"] != plan["base"]
                or state != plan["verdict"]):
            print(f"PR #{number}: source/base/check state changed; wait for next event", flush=True)
            return
        # Identical immutable content SHAs reuse the completed contract analysis;
        # the live PR and native atomic head guard still authorize the mutation.
        result = self.merge(pr, token) if state == READY else self.update(pr, token, bot)
        if state == UPDATE:
            if result is not None:
                print(f"PR #{number}: native rebase requested", flush=True)
        elif not result["merged"]:
            raise ValueError("GitHub refused merge")
        else:
            print(f"PR #{number}: merged {result['sha']}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--github-output", action="store_true")
    options = parser.parse_args()
    repository = os.environ["GITHUB_REPOSITORY"]
    if repository != "structured-world/signature-primitives":
        raise ValueError("Unsupported repository")
    api = GitHub(repository, os.environ["GH_TOKEN"])
    print("Inspecting Dependabot source/base and required-check state", flush=True)
    plans = []
    if options.dry_run:
        numbers = [p["number"] for p in api.pages(api.repo("pulls?state=open&base=main"))
                   if p["user"]["login"] == "dependabot[bot]"]
        for number in numbers:
            pr, verdict = api.inspect(number)
            print(f"PR #{number} {pr['head']['sha'][:12]}: {verdict}", flush=True)
            if verdict in (READY, UPDATE):
                plans.append({"number": number, "head": pr["head"]["sha"],
                              "base": pr["base"]["sha"], "verdict": verdict})
    else:
        plans = json.loads(os.environ["MERGE_PLAN"])
    for plan in [] if options.dry_run else plans:
        try:
            api.apply(plan, os.environ["MERGE_TOKEN"], os.environ["MERGE_BOT"])
        except GitHubError as error:
            # Native protection refuses changed heads/bases/checks atomically.
            if not any(f"HTTP {code}" in str(error) for code in (405, 409, 422)):
                raise
            print(f"PR #{plan['number']}: branch/check state changed; wait for next event", flush=True)
            continue
    if options.github_output:
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
            output.write(f"action_count={len(plans)}\n")
            output.write("plan=" + json.dumps(plans, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
