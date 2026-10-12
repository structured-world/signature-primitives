"""Merge policy tests use synthetic GitHub records, without credentials/network."""

import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "dependabot_merge.py"
SPEC = importlib.util.spec_from_file_location("dependabot_merge", SCRIPT)
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.sha = "a" * 40
        self.push = "2026-10-12T10:00:00Z"
        self.thumb = {"user": {"login": "chatgpt-codex-connector[bot]"},
                      "content": "+1", "created_at": "2026-10-12T10:01:00Z"}

    def clear(self, reactions=None, reviews=None, unresolved=False):
        return POLICY.review_clear(self.sha, self.push, reactions or [],
                                   reviews or [], unresolved)

    def test_absence_and_stale_or_unlocatable_push_refuse(self):
        # Neither absence of findings nor an old thumbs-up is a clean review.
        self.assertFalse(self.clear())
        self.assertTrue(self.clear([self.thumb]))
        old = dict(self.thumb, created_at="2026-10-12T09:59:59Z")
        self.assertFalse(self.clear([old]))
        self.assertFalse(POLICY.review_clear(self.sha, None, [self.thumb], [], False))

    def test_spoofed_reviewer_and_unresolved_threads_refuse(self):
        # Login substring matching would let an ordinary user fake a bot verdict.
        fake = dict(self.thumb, user={"login": "my-codex-helper"})
        self.assertFalse(self.clear([fake]))
        self.assertFalse(self.clear([self.thumb], unresolved=True))

    def test_in_progress_and_requested_changes_refuse(self):
        # A known review in progress blocks merge, including after an approval.
        eyes = dict(self.thumb, content="eyes", created_at="2026-10-12T10:02:00Z")
        self.assertFalse(self.clear([self.thumb, eyes]))
        requested = {"user": {"login": "maintainer"}, "state": "CHANGES_REQUESTED",
                     "submitted_at": self.push, "commit_id": self.sha}
        self.assertFalse(self.clear([self.thumb], [requested]))

    def test_trusted_approval_is_bound_to_the_exact_head(self):
        # A collaborator's approval is valid only for the commit it reviewed.
        approved = {"user": {"login": "maintainer"}, "state": "APPROVED",
                    "submitted_at": self.push, "commit_id": self.sha,
                    "author_association": "COLLABORATOR"}
        self.assertTrue(self.clear(reviews=[approved]))
        self.assertFalse(self.clear(reviews=[dict(approved, commit_id="b" * 40)]))
        self.assertFalse(self.clear(reviews=[dict(approved, author_association="NONE")]))


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

    def test_non_bot_and_fork_inputs_never_reach_review_or_mutation(self):
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
