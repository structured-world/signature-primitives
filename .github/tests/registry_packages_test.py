"""Registry qualification follows the same revision's publication selection."""

import pathlib
import runpy
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SELECT = runpy.run_path(str(ROOT / "scripts/release-packages.py"))["selected_packages"]


class RegistryPackages(unittest.TestCase):
    def test_disabled_packages_are_not_missing_registry_releases(self):
        # An explicitly unpublished sibling cannot block delivery of an active
        # crate, while an omitted package keeps release-plz's active default.
        metadata = {"packages": [
            {"name": "core", "version": "0.15.0", "publish": None},
            {"name": "asic", "version": "0.15.0", "publish": None},
            {"name": "pending", "version": "0.15.0", "publish": None},
            {"name": "private", "version": "0.15.0", "publish": []},
        ]}
        config = {"package": [
            {"name": "asic", "release": True},
            {"name": "pending", "release": False},
        ]}
        self.assertEqual(SELECT(metadata, config), [
            {"name": "core", "version": "0.15.0"},
            {"name": "asic", "version": "0.15.0"},
        ])

    def test_empty_release_selection_does_not_qualify_a_delivery(self):
        # The delivery gate cannot report success without an actual selected
        # package. It must not quietly turn publication mistakes green.
        metadata = {"packages": [{"name": "pending", "version": "0.15.0", "publish": None}]}
        with self.assertRaisesRegex(ValueError, "no packages selected"):
            SELECT(metadata, {"package": [{"name": "pending", "release": False}]})


if __name__ == "__main__":
    unittest.main()
