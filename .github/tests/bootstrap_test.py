"""First-publication selection cannot grant the XAdES token existing packages."""

import pathlib
import tomllib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class BootstrapPackages(unittest.TestCase):
    def test_coordinated_packages_include_each_others_changes(self):
        # One workspace version also ships sibling-only changes. Each package
        # must explain the commit responsible for that coordinated release.
        normal = tomllib.loads((ROOT / "release-plz.toml").read_text())
        names = {package["name"] for package in normal["package"]}
        for package in normal["package"]:
            with self.subTest(package=package["name"]):
                self.assertEqual(set(package["changelog_include"]),
                                 names - {package["name"]})

    def test_cms_tag_pattern_survives_bootstrap_to_workspace_transition(self):
        # The first CMS version is already tagged v0.2.0. Release-plz defaults
        # differ for one versus several public packages; neither mode may
        # change the existing CMS baseline when bootstrap access is removed.
        normal = tomllib.loads((ROOT / "release-plz.toml").read_text())
        cms = next(package for package in normal["package"]
                   if package["name"] == "structured-cms")
        self.assertEqual(cms["git_tag_name"], "v{{ version }}")
        core = tomllib.loads((ROOT / ".github/release-core.toml").read_text())
        core_cms = next(p for p in core["package"] if p["name"] == "structured-cms")
        self.assertEqual(core_cms["git_tag_name"], cms["git_tag_name"])
        xades = next(p for p in normal["package"] if p["name"] == "structured-xades")
        bootstrap = tomllib.loads((ROOT / ".github/release-xades.toml").read_text())
        self.assertEqual(xades["git_tag_name"], "structured-xades-v{{ version }}")
        self.assertEqual(bootstrap["workspace"]["git_tag_name"], xades["git_tag_name"])

    def test_exact_package_partition_and_release_commit_gate(self):
        # Parse the committed TOML rather than a second hand-written model of
        # the configuration. A future package must be classified explicitly.
        names = set()
        workspace = tomllib.loads((ROOT / "Cargo.toml").read_text())
        for member in workspace["workspace"]["members"]:
            manifest = tomllib.loads((ROOT / member / "Cargo.toml").read_text())
            if manifest["package"].get("publish", True) is not False:
                names.add(manifest["package"]["name"])
        existing = {"structured-asn1", "structured-pkix", "structured-cms"}
        self.assertEqual(names, existing | {"structured-xades"})
        for filename, expected in [
            ("release-core.toml", existing),
            ("release-xades.toml", {"structured-xades"}),
            ("../release-plz.toml", names),
        ]:
            config = tomllib.loads((ROOT / ".github" / filename).read_text())
            # Only the explicitly credential-selected first XAdES publication
            # may run without a version PR; ordinary releases retain that gate.
            self.assertIs(config["workspace"]["release_always"], filename == "release-xades.toml")
            self.assertIs(config["workspace"]["git_release_enable"], True)
            disabled = {package["name"] for package in config["package"]
                        if package.get("release") is False}
            self.assertEqual(names - disabled, expected)
            self.assertEqual(disabled | expected, names)


if __name__ == "__main__":
    unittest.main()
