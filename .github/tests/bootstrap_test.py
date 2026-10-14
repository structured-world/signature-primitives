"""First-publication selection cannot grant the CMS token existing packages."""

import pathlib
import tomllib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class BootstrapPackages(unittest.TestCase):
    def test_exact_package_partition_and_release_commit_gate(self):
        # Parse the committed TOML rather than a second hand-written model of
        # the configuration. A future package must be classified explicitly.
        names = set()
        workspace = tomllib.loads((ROOT / "Cargo.toml").read_text())
        for member in workspace["workspace"]["members"]:
            manifest = tomllib.loads((ROOT / member / "Cargo.toml").read_text())
            if manifest["package"].get("publish", True) is not False:
                names.add(manifest["package"]["name"])
        self.assertEqual(names, {"structured-asn1", "structured-pkix", "structured-cms"})
        for filename, expected in [
            ("release-core.toml", names - {"structured-cms"}),
            ("release-cms.toml", {"structured-cms"}),
        ]:
            config = tomllib.loads((ROOT / ".github" / filename).read_text())
            self.assertIs(config["workspace"]["release_always"], False)
            self.assertIs(config["workspace"]["git_release_enable"], True)
            disabled = {package["name"] for package in config["package"]
                        if package.get("release") is False}
            self.assertEqual(names - disabled, expected)
            self.assertEqual(disabled | expected, names)


if __name__ == "__main__":
    unittest.main()
