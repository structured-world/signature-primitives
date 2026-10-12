"""Release approval cannot be inherited from unrelated or unfinished CI."""

import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("release_ci", Path(__file__).parent.parent / "scripts/release_ci.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ReleaseCiTests(unittest.TestCase):
    def run_data(self, **changes):
        return {"databaseId": 10, "headSha": "exact", "headBranch": "main",
                "event": "push", "workflowName": "ci", "status": "completed",
                "conclusion": "success", **changes}

    def test_requires_exact_push_main_ci(self):
        # Each identity component binds approval to the publication source.
        self.assertEqual(module.ci_state([self.run_data()], "exact"), "success")
        for change in [{"headSha": "other"}, {"headBranch": "feature"},
                       {"event": "pull_request"}, {"workflowName": "other"}]:
            self.assertEqual(module.ci_state([self.run_data(**change)], "exact"), "pending")

    def test_terminal_failures_and_pending_runs_do_not_approve(self):
        # Cancelled, skipped or failed CI cannot mint release approval.
        self.assertEqual(module.ci_state([], "exact"), "pending")
        self.assertEqual(module.ci_state([self.run_data(status="in_progress")], "exact"), "pending")
        for conclusion in ["failure", "cancelled", "skipped", "timed_out", "neutral"]:
            self.assertEqual(module.ci_state([self.run_data(conclusion=conclusion)], "exact"), "failure")

    def test_latest_run_wins(self):
        # A new exact-commit CI run must finish rather than reuse an older pass.
        older = self.run_data()
        newer = self.run_data(databaseId=11, status="in_progress", conclusion="")
        self.assertEqual(module.ci_state([newer, older], "exact"), "pending")


if __name__ == "__main__":
    unittest.main()
