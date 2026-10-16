"""Qualification provenance regressions, without Cargo or consumer mutation."""

from pathlib import Path
import runpy
import tempfile
import unittest


SOURCE_HASH = runpy.run_path(
    str(Path(__file__).with_name("qualify-xades-key.py")),
    run_name="qualification_test",
)["source_hash"]


class SourceHashTests(unittest.TestCase):
    def test_compiled_readme_is_part_of_the_qualified_source(self):
        # lib.rs includes the README in its compilation. A documentation edit
        # during qualification must invalidate provenance just like Rust code.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Cargo.toml").write_text("[workspace]\n")
            (root / "Cargo.lock").write_text("version = 4\n")
            for name in ("structured-asn1", "structured-pkix", "structured-cms", "structured-xades"):
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


if __name__ == "__main__":
    unittest.main()
