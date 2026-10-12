"""Admit publication only after push CI succeeds on the checked-out main SHA."""

import json
import os
import subprocess
import time


def ci_state(runs, sha):
    # Never borrow approval from another commit, branch, event or workflow.
    matching = [run for run in runs if run["headSha"] == sha
                and run["headBranch"] == "main" and run["event"] == "push"
                and run["workflowName"] == "ci"]
    if not matching:
        return "pending"
    run = max(matching, key=lambda value: value["databaseId"])
    if run["status"] != "completed":
        return "pending"
    return "success" if run["conclusion"] == "success" else "failure"


def main():
    sha = os.environ["GITHUB_SHA"]
    repository = os.environ["GITHUB_REPOSITORY"]
    if repository != "structured-world/signature-primitives" or os.environ["GITHUB_REF"] != "refs/heads/main":
        raise RuntimeError("Publication requires the source repository's main ref")
    if os.environ["GITHUB_EVENT_NAME"] not in ("push", "workflow_dispatch"):
        raise RuntimeError("Unsupported publication trigger")
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if actual != sha:
        raise RuntimeError("Checkout does not match the publication SHA")
    deadline = time.monotonic() + 1200
    while time.monotonic() < deadline:
        output = subprocess.check_output([
            "gh", "run", "list", "--repo", repository, "--workflow", "ci.yml",
            "--commit", sha, "--branch", "main", "--event", "push", "--limit", "100",
            "--json", "databaseId,headSha,headBranch,event,workflowName,status,conclusion",
        ], text=True, timeout=30)
        state = ci_state(json.loads(output), sha)
        if state == "success":
            print(f"PASS: successful push CI for {sha}")
            return
        if state == "failure":
            raise RuntimeError("Exact-SHA CI did not succeed")
        time.sleep(10)
    raise RuntimeError("Timed out waiting for exact-SHA CI")


if __name__ == "__main__":
    main()
