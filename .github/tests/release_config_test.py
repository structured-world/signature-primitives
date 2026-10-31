"""The published coordinated group has one OIDC-only release configuration."""

import pathlib
import tomllib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


class ReleaseConfiguration(unittest.TestCase):
    def test_all_public_packages_retain_their_release_contract(self):
        # Removing bootstrap branches must not drop a sibling, change an existing
        # tag namespace or allow ordinary feature commits to publish versions.
        workspace = tomllib.loads((ROOT / "Cargo.toml").read_text())
        names = set()
        for member in workspace["workspace"]["members"]:
            manifest = tomllib.loads((ROOT / member / "Cargo.toml").read_text())
            if manifest["package"].get("publish", True) is not False:
                names.add(manifest["package"]["name"])
        config = tomllib.loads((ROOT / "release-plz.toml").read_text())
        self.assertIs(config["workspace"]["release_always"], False)
        self.assertIs(config["workspace"]["git_release_enable"], True)
        packages = config["package"]
        self.assertEqual({package["name"] for package in packages}, names)
        for package in packages:
            self.assertIsNot(package.get("release"), False)
            self.assertEqual(package["version_group"], "primitives")
            expected = "v{{ version }}" if package["name"] == "structured-cms" else package["name"] + "-v{{ version }}"
            if package["name"] in {"structured-asn1", "structured-pkix"}:
                self.assertNotIn("git_tag_name", package)
            else:
                self.assertEqual(package["git_tag_name"], expected)
            self.assertEqual(set(package["changelog_include"]), names - {package["name"]})


if __name__ == "__main__":
    unittest.main()
