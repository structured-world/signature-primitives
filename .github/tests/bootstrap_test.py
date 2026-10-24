"""First-publication selection cannot grant the LTV token existing packages."""

import pathlib
import tomllib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class BootstrapPackages(unittest.TestCase):
    def test_cades_first_publication_has_one_package_and_release_commit_gate(self):
        # A temporary new-crate token cannot publish existing siblings or
        # publish an ordinary feature commit instead of an approved release.
        config = tomllib.loads((ROOT / ".github/release-cades.toml").read_text())
        self.assertIs(config["workspace"]["release_always"], False)
        self.assertEqual(config["workspace"]["git_tag_name"], "structured-cades-v{{ version }}")
        disabled = {package["name"] for package in config["package"] if package.get("release") is False}
        self.assertEqual(disabled, {"structured-asn1", "structured-pkix", "structured-cms", "structured-ltv", "structured-xades", "structured-pades", "structured-asic"})

    def test_pades_awaits_first_publication_authorization(self):
        # Adding a workspace member must not let an older bootstrap credential
        # publish it before its own first-publication authorization.
        for filename in ["release-core.toml", "release-ltv.toml",
                         "release-dependents.toml", "release-before-cades.toml",
                         "release-cades.toml", "../release-plz.toml"]:
            with self.subTest(config=filename):
                config = tomllib.loads((ROOT / ".github" / filename).read_text())
                packages = {package["name"]: package.get("release", True)
                            for package in config["package"]}
                self.assertIs(packages.get("structured-pades"), False)
                if filename != "../release-plz.toml":
                    self.assertIs(packages.get("structured-asic"), False)

    def test_asic_uses_the_coordinated_oidc_publication(self):
        # ASiC's own first publication and publisher registration precede this
        # selection; old bootstrap tokens remain unable to publish the crate.
        config = tomllib.loads((ROOT / "release-plz.toml").read_text())
        asic = next(package for package in config["package"]
                    if package["name"] == "structured-asic")
        self.assertIsNot(asic.get("release"), False)
        self.assertEqual(asic["version_group"], "primitives")
        self.assertEqual(asic["git_tag_name"], "structured-asic-v{{ version }}")

    def test_coordinated_packages_include_each_others_changes(self):
        # One workspace version also ships sibling-only changes. Each package
        # must explain the commit responsible for that coordinated release.
        normal = tomllib.loads((ROOT / "release-plz.toml").read_text())
        # CAdES now joins the authorized coordinated publication. Every active
        # sibling must carry the same final release explanation.
        packages = [package for package in normal["package"]
                    if package.get("release") is not False]
        names = {package["name"] for package in packages}
        for package in packages:
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
        ltv = next(p for p in normal["package"] if p["name"] == "structured-ltv")
        bootstrap = tomllib.loads((ROOT / ".github/release-ltv.toml").read_text())
        self.assertEqual(ltv["git_tag_name"], "structured-ltv-v{{ version }}")
        self.assertEqual(bootstrap["workspace"]["git_tag_name"], ltv["git_tag_name"])
        # A single released package would otherwise take release-plz's
        # one-package default tag instead of the existing XAdES series.
        xades = next(p for p in normal["package"] if p["name"] == "structured-xades")
        dependents = tomllib.loads((ROOT / ".github/release-dependents.toml").read_text())
        dependent = next(p for p in dependents["package"] if p["name"] == "structured-xades")
        self.assertEqual(xades["git_tag_name"], "structured-xades-v{{ version }}")
        self.assertEqual(dependent["git_tag_name"], xades["git_tag_name"])

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
        new = {"structured-ltv"}
        cades = {"structured-cades"}
        dependents = {"structured-xades"} | cades
        pending = {"structured-pades", "structured-asic"}
        self.assertEqual(names, existing | new | dependents | pending)
        for filename, expected in [
            ("release-core.toml", existing),
            ("release-ltv.toml", new),
            ("release-dependents.toml", dependents),
            ("release-before-cades.toml", names - cades - pending),
            ("release-cades.toml", cades),
            ("../release-plz.toml", names - {"structured-pades"}),
        ]:
            config = tomllib.loads((ROOT / ".github" / filename).read_text())
            # Only the explicitly credential-selected first LTV publication
            # may run without a version PR; ordinary releases retain that gate.
            self.assertIs(config["workspace"]["release_always"], filename == "release-ltv.toml")
            self.assertIs(config["workspace"]["git_release_enable"], True)
            disabled = {package["name"] for package in config["package"]
                        if package.get("release") is False}
            self.assertEqual(names - disabled, expected)
            self.assertEqual(disabled | expected, names)


if __name__ == "__main__":
    unittest.main()
