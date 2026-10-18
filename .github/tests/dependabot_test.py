"""Merge policy tests use synthetic GitHub records, without credentials/network."""

import importlib.util
import pathlib
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
        # Strict required checks keep a behind update unmergeable; Dependabot never rebases it.
        self.assertEqual(self.dependabot("behind").inspect(42)[1], POLICY.UPDATE)

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
        # A push between inspection and update must be refused by GitHub's sha guard.
        api = POLICY.GitHub("structured-world/signature-primitives", "read-credential")
        calls = []
        api.request = lambda *args, **kwargs: calls.append((args, kwargs))
        pr = {"number": 42, "head": {"sha": "a" * 40}}
        api.update(pr, "merge-credential")
        args, kwargs = calls[0]
        self.assertTrue(args[0].endswith("pulls/42/update-branch"))
        self.assertEqual(args[1], "PUT")
        self.assertEqual(args[2], {"expected_head_sha": pr["head"]["sha"]})
        self.assertEqual(kwargs["token"], "merge-credential")

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


if __name__ == "__main__":
    unittest.main()
