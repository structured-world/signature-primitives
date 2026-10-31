"""Merge policy tests use synthetic GitHub records, without credentials/network."""

import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "dependabot_merge.py"
SPEC = importlib.util.spec_from_file_location("dependabot_merge", SCRIPT)
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


class ContractTests(unittest.TestCase):
    def test_grouped_and_aliased_manifest_updates_are_manual(self):
        # A grouped update cannot hide an allocator under an alias.
        before = b'[dependencies]\na = { package="allocator-api2", version="=0.2.21" }\nother="1"\n'
        after = before.replace(b"0.2.21", b"0.4.0").replace(b'other="1"', b'other="2"')
        self.assertTrue(POLICY.contract_changed("Cargo.toml", before, after))
        self.assertFalse(POLICY.contract_changed("Cargo.toml", before,
                                               before.replace(b'other="1"', b'other="2"')))

    def test_lockfile_capacity_dependency_changes_are_manual(self):
        # Transitive lockfile changes also require the audited implementation review.
        old = b'[[package]]\nname="hashbrown"\nversion="0.16.1"\nchecksum="old"\n'
        self.assertTrue(POLICY.contract_changed("Cargo.lock", old, old.replace(b"old", b"new")))
        self.assertFalse(POLICY.contract_changed("Cargo.lock", old, old))

    def test_missing_manifest_and_malformed_data_do_not_fall_back(self):
        # Adding/removing a critical declaration is manual; parse failures stop processing.
        self.assertTrue(POLICY.contract_changed("Cargo.toml", b"", b'[dependencies]\nhashbrown="1"'))
        with self.assertRaises(ValueError):
            POLICY.contract_changed("Cargo.toml", b"", b"broken = [")


class NativeBoundaryTests(unittest.TestCase):
    def dependabot(self, state):
        # A repository-local update in the given native merge state.
        api = POLICY.GitHub("structured-world/signature-primitives", "read-credential")
        pr = {"number": 42, "user": {"login": "dependabot[bot]"}, "state": "open",
              "draft": False, "title": "bump checkout", "mergeable_state": state,
              "base": {"ref": "main", "sha": "b" * 40},
              "head": {"repo": {"full_name": api.repository}, "ref": "dependabot/example",
                       "sha": "a" * 40}}
        api.request = lambda *_: pr
        api.pages = lambda _: []
        return api

    def test_green_required_checks_decide_the_merge(self):
        # A clean state is every required check passing on an up-to-date head.
        self.assertEqual(self.dependabot("clean").inspect(42)[1], POLICY.READY)
        for state in ("blocked", "unstable", "dirty", "unknown"):
            self.assertEqual(self.dependabot(state).inspect(42)[1],
                             "waiting for mandatory CI/base qualification")

    def test_an_update_behind_main_is_brought_up_to_date(self):
        # Strict required checks keep a behind head unmergeable until the
        # explicitly requested native Dependabot rebase completes.
        self.assertEqual(self.dependabot("behind").inspect(42)[1], POLICY.UPDATE)

    def test_unready_heads_do_not_download_contract_files(self):
        # A completion event for another PR cannot cause TOML downloads for
        # heads whose required checks are still pending or failing.
        api = self.dependabot("blocked")
        api.pages = lambda _: self.fail("unready head downloaded contract files")
        self.assertNotEqual(api.inspect(42)[1], POLICY.READY)

    def test_pagination_follows_native_link_cursors(self):
        # Listings use Link cursors, not numbered page parameters.
        api = POLICY.GitHub("structured-world/signature-primitives", "read-credential")
        response = POLICY.subprocess.CompletedProcess([], 0, '[[{"n":1}],[{"n":2}]]', '')
        with patch.object(POLICY.subprocess, "run", return_value=response) as run:
            self.assertEqual(list(api.pages("repos/example/pulls")), [{"n": 1}, {"n": 2}])
            self.assertIn("--paginate", run.call_args.args[0])
            self.assertIn("--slurp", run.call_args.args[0])

    def test_merge_binds_the_inspected_head_and_uses_only_the_merge_token(self):
        # A push between inspection and merge must be rejected by GitHub's sha guard.
        api = POLICY.GitHub("structured-world/signature-primitives", "read-credential")
        calls = []
        api.request = lambda *args, **kwargs: calls.append((args, kwargs))
        pr = {"number": 42, "head": {"sha": "a" * 40}}
        api.merge(pr, "merge-credential")
        args, kwargs = calls[0]
        self.assertEqual(args[1], "PUT")
        self.assertEqual(args[2], {"sha": pr["head"]["sha"], "merge_method": "squash"})
        self.assertEqual(kwargs["token"], "merge-credential")

    def test_base_update_binds_the_inspected_head_and_uses_only_the_merge_token(self):
        # Rebase requests carry the inspected source pair and use only the App
        # credential; branch mutation is performed by Dependabot itself.
        api = POLICY.GitHub("structured-world/signature-primitives", "read-credential")
        calls = []
        api.request = lambda *args, **kwargs: calls.append((args, kwargs))
        api.pages = lambda _: []
        pr = {"number": 42, "head": {"sha": "a" * 40}, "base": {"sha": "b" * 40}}
        api.update(pr, "merge-credential", "release-bot[bot]")
        args, kwargs = calls[0]
        self.assertTrue(args[0].endswith("issues/42/comments"))
        self.assertEqual(args[1], "POST")
        self.assertTrue(args[2]["body"].startswith("@dependabot rebase\n"))
        self.assertIn(pr["head"]["sha"], args[2]["body"])
        self.assertIn(pr["base"]["sha"], args[2]["body"])
        self.assertEqual(kwargs["token"], "merge-credential")

    def test_behind_updates_request_native_rebase_without_a_merge_commit(self):
        # Updating a Dependabot branch must not insert main merge commits into
        # the history analyzed by release-plz.
        api = self.dependabot("behind")
        calls = []
        api.request = lambda *args, **kwargs: calls.append((args, kwargs))
        pr = {"number": 42, "head": {"sha": "a" * 40}, "base": {"sha": "b" * 40}}
        api.update(pr, "merge-credential", "release-bot[bot]")
        self.assertEqual(calls[0][0][1], "POST")
        self.assertTrue(calls[0][0][0].endswith("issues/42/comments"))

    def test_non_bot_and_fork_inputs_never_reach_mutation(self):
        # Only repository-local Dependabot PRs can enter privileged processing.
        api = POLICY.GitHub("structured-world/signature-primitives", "read-credential")
        pr = {"number": 42, "user": {"login": "someone"}, "state": "open", "draft": False,
              "base": {"ref": "main"}, "head": {"repo": {"full_name": api.repository}}}
        api.request = lambda *_: pr
        self.assertEqual(api.inspect(pr["number"])[1], "ineligible")
        pr["user"]["login"] = "dependabot[bot]"
        pr["head"]["repo"]["full_name"] = "someone/fork"
        self.assertEqual(api.inspect(pr["number"])[1], "ineligible")

    def test_live_plan_revalidation_reuses_immutable_contract_analysis(self):
        # Apply refreshes the PR, not its already-qualified immutable files.
        api = self.dependabot("clean")
        pr = api.request("unused")
        api.pages = lambda _: self.fail("contract files downloaded twice")
        merged = []
        api.merge = lambda current, token: merged.append((current, token)) or {"merged": True, "sha": "result"}
        plan = {"number": 42, "head": pr["head"]["sha"], "base": pr["base"]["sha"], "verdict": POLICY.READY}
        api.apply(plan, "merge-credential", "release-bot[bot]")
        self.assertEqual(merged, [(pr, "merge-credential")])
        for field in ("head", "base", "verdict"):
            changed = {**plan, field: "changed" if field != "verdict" else POLICY.UPDATE}
            api.apply(changed, "merge-credential", "release-bot[bot]")
        self.assertEqual(len(merged), 1)
        for state in ("blocked", "behind", "unknown"):
            pr["mergeable_state"] = state
            api.apply(plan, "merge-credential", "release-bot[bot]")
        self.assertEqual(len(merged), 1)

    def test_duplicate_rebase_requires_the_actual_app_author(self):
        # Another user's matching text cannot suppress a real rebase request.
        api = self.dependabot("behind")
        pr = api.request("unused")
        calls = []
        body = "@dependabot rebase\n\n" + f"<!-- rebase head={pr['head']['sha']} base={pr['base']['sha']} -->"
        api.pages = lambda _: [{"user": {"login": "release-bot[bot]"}, "body": body}]
        api.request = lambda *args, **kwargs: calls.append((args, kwargs))
        self.assertIsNone(api.update(pr, "merge-credential", "release-bot[bot]"))
        self.assertEqual(calls, [])
        api.pages = lambda _: [{"user": {"login": "other-user"}, "body": body}]
        api.update(pr, "merge-credential", "release-bot[bot]")
        self.assertEqual(len(calls), 1)

    def test_immutable_content_cache_is_keyed_by_path_and_sha(self):
        # Multiple PRs can share a base blob, but a new SHA cannot reuse it.
        api = POLICY.GitHub("structured-world/signature-primitives", "read-credential")
        calls = []
        api.request = lambda path: calls.append(path) or {"encoding": "base64", "content": "YQ==\n"}
        self.assertEqual(api.content("Cargo.toml", "old"), b"a")
        self.assertEqual(api.content("Cargo.toml", "old"), b"a")
        self.assertEqual(len(calls), 1)
        api.content("Cargo.toml", "new")
        api.content("Cargo.lock", "new")
        self.assertEqual(len(calls), 3)

    def test_cli_plan_is_serialized_once_and_apply_does_not_rescan(self):
        # Exercise both actual entrypoint phases: job outputs carry the checked
        # SHAs, and the second phase performs live revalidation without a new scan.
        api = self.dependabot("clean")
        pr = api.request("unused")
        with tempfile.TemporaryDirectory(prefix="primitives-dependabot-") as directory:
            output = pathlib.Path(directory) / "output"
            env = {"GITHUB_REPOSITORY": api.repository, "GH_TOKEN": "read-credential",
                   "GITHUB_OUTPUT": str(output)}
            with patch.object(POLICY, "GitHub", return_value=api), patch.dict(os.environ, env, clear=True), \
                    patch.object(sys, "argv", ["script", "--dry-run", "--github-output"]), \
                    patch.object(api, "pages", return_value=[pr]), \
                    patch.object(api, "inspect", return_value=(pr, POLICY.READY)) as inspect:
                POLICY.main()
                inspect.assert_called_once_with(pr["number"])
            fields = dict(line.split("=", 1) for line in output.read_text().splitlines())
            self.assertEqual(fields["action_count"], "1")
            plans = json.loads(fields["plan"])
            self.assertEqual(plans, [{"number": pr["number"], "head": pr["head"]["sha"],
                                      "base": pr["base"]["sha"], "verdict": POLICY.READY}])
            env.update(MERGE_PLAN=fields["plan"], MERGE_TOKEN="merge-credential", MERGE_BOT="release-bot[bot]")
            with patch.object(POLICY, "GitHub", return_value=api), patch.dict(os.environ, env, clear=True), \
                    patch.object(sys, "argv", ["script"]), patch.object(api, "pages") as pages, \
                    patch.object(api, "inspect") as inspect, patch.object(api, "apply") as apply:
                POLICY.main()
                pages.assert_not_called()
                inspect.assert_not_called()
                apply.assert_called_once_with(plans[0], "merge-credential", "release-bot[bot]")


if __name__ == "__main__":
    unittest.main()
