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
        for values in self.request(f"{path}{separator}per_page=100", paginate=True):
            yield from values

    def content(self, path, sha):
        encoded = urllib.parse.quote(path, safe="/")
        result = self.request(self.repo(f"contents/{encoded}?ref={sha}"))
        if result["encoding"] != "base64":
            raise ValueError("Unexpected file encoding")
        return base64.b64decode(result["content"])

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
        # Native branch protection enforces every required check and base freshness;
        # Dependabot never updates a branch that is only behind, so it is updated here.
        if pr["mergeable_state"] == "behind":
            return pr, UPDATE
        if pr["mergeable_state"] != "clean":
            return pr, "waiting for mandatory CI/base qualification"
        return pr, READY

    def merge(self, pr, token):
        # The native merge operation atomically refuses a head changed since inspection.
        return self.request(self.repo(f"pulls/{pr['number']}/merge"), "PUT",
                            {"sha": pr["head"]["sha"], "merge_method": "squash"}, token=token)

    def update(self, pr, token):
        # The native update refuses a head changed since inspection; the App's
        # push starts CI, whose completion brings the new head back here.
        return self.request(self.repo(f"pulls/{pr['number']}/update-branch"), "PUT",
                            {"expected_head_sha": pr["head"]["sha"]}, token=token)


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
    actions = 0
    for number in numbers:
        pr, verdict = api.inspect(number)
        print(f"PR #{number} {pr['head']['sha'][:12]}: {verdict}", flush=True)
        if verdict not in (READY, UPDATE):
            continue
        actions += 1
        if options.dry_run:
            continue
        token = os.environ["MERGE_TOKEN"]
        try:
            result = api.merge(pr, token) if verdict == READY else api.update(pr, token)
        except GitHubError as error:
            # 405/409 refuse a merge, 422 an update, of a head or base changed since inspection.
            if not any(f"HTTP {code}" in str(error) for code in (405, 409, 422)):
                raise
            print(f"PR #{number}: branch/check state changed; waiting for next event")
            continue
        if verdict == UPDATE:
            print(f"PR #{number}: base update started", flush=True)
            continue
        if not result["merged"]:
            raise ValueError("GitHub refused merge")
        print(f"PR #{number}: merged {result['sha']}", flush=True)
    if options.github_output:
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
            output.write(f"action_count={actions}\n")


if __name__ == "__main__":
    main()
