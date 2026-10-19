"""Qualification provenance regressions, without Cargo or consumer mutation."""

from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest


QUALIFICATION = runpy.run_path(
    str(Path(__file__).with_name("qualify-xades-key.py")),
    run_name="qualification_test",
)
SOURCE_HASH = QUALIFICATION["source_hash"]


class SourceHashTests(unittest.TestCase):
    def test_compiled_readme_is_part_of_the_qualified_source(self):
        # lib.rs includes the README in its compilation. A documentation edit
        # during qualification must invalidate provenance just like Rust code.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Cargo.toml").write_text("[workspace]\n")
            (root / "Cargo.lock").write_text("version = 4\n")
            for name in ("structured-asn1", "structured-pkix", "structured-cms", "structured-ltv",
                         "structured-xades"):
                package = root / "crates" / name
                (package / "src").mkdir(parents=True)
                (package / "Cargo.toml").write_text("[package]\n")
                (package / "src/lib.rs").write_text("// synthetic compilation input\n")
            fixture = root / "scripts/fixtures/xades-native-key.rs"
            fixture.parent.mkdir(parents=True)
            fixture.write_text("// synthetic native fixture\n")
            readme = root / "crates/structured-xades/README.md"
            readme.write_text("Original crate documentation.\n")
            before = SOURCE_HASH(root)
            self.assertEqual(SOURCE_HASH(root), before)
            readme.write_text("Changed crate documentation.\n")
            self.assertNotEqual(SOURCE_HASH(root), before)


class ExportTests(unittest.TestCase):
    def fixture(self, root):
        repo = root / "repo"
        subprocess.run(["git", "init", "--quiet", "--template=", str(repo)], check=True)
        (repo / "src").mkdir()
        (repo / "src/lib.rs").write_text("// immutable source\n")
        (repo / "Cargo.toml").write_text("[package]\n")
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=Fixture",
                        "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
                        "-c", "core.hooksPath=/dev/null", "commit", "--quiet", "-m", "fixture"],
                       check=True)
        revision = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"],
                                           text=True).strip()
        output = root / "output"
        output.mkdir()
        QUALIFICATION["prepare_xml_source"](repo, revision, output)
        return repo, revision, output, output / ("xml-" + revision)

    def test_marker_does_not_authorize_changed_cached_sources(self):
        # The requested revision marker stays intact in every case; the actual
        # archive's contents, membership and file kind must still be checked.
        for mutation in ["edit", "extra", "missing", "symlink"]:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                repo, revision, output, source = self.fixture(Path(directory))
                path = source / "src/lib.rs"
                if mutation == "edit":
                    path.write_text("// edited implementation\n")
                elif mutation == "extra":
                    (source / "extra.rs").write_text("// unarchived input\n")
                elif mutation == "missing":
                    path.unlink()
                else:
                    path.unlink()
                    path.symlink_to("../Cargo.toml")
                self.assertEqual((source / ".qualification-revision").read_text(), revision)
                with self.assertRaises(RuntimeError):
                    QUALIFICATION["prepare_xml_source"](repo, revision, output)

    def test_unchanged_reuse_and_post_run_integrity(self):
        # Reuse must compare with the same archive, and mutation after admission
        # must invalidate the final qualification rather than print PASS.
        with tempfile.TemporaryDirectory() as directory:
            repo, revision, output, source = self.fixture(Path(directory))
            first = QUALIFICATION["prepare_xml_source"](repo, revision, output)
            self.assertEqual(QUALIFICATION["prepare_xml_source"](repo, revision, output), first)
            QUALIFICATION["require_export"](source, first[1])
            (source / "src/lib.rs").write_text("// changed during qualification\n")
            with self.assertRaises(RuntimeError):
                QUALIFICATION["require_export"](source, first[1])

    def test_cache_root_symlink_is_not_an_archive(self):
        # A redirected cache root must fail before any fixture compilation.
        with tempfile.TemporaryDirectory() as directory:
            repo, revision, output, source = self.fixture(Path(directory))
            moved = output / "moved"
            source.rename(moved)
            source.symlink_to(moved, target_is_directory=True)
            with self.assertRaises(RuntimeError):
                QUALIFICATION["prepare_xml_source"](repo, revision, output)


if __name__ == "__main__":
    unittest.main()
