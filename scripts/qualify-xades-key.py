#!/usr/bin/env python3
"""Source-only native key-adapter qualification; never changes a consumer checkout.

Python 3.11+, git, stable Rust and cargo-nextest are required. The exported XML
revision and all generated manifests/build output live below this project's
target/. This is not a registry adapter or whole-profile qualification.
"""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import tomllib


def run(arguments, **kwargs):
    return subprocess.run(arguments, check=True, **kwargs)


def source_hash(root):
    digest = hashlib.sha256()
    paths = [root / "Cargo.toml", root / "Cargo.lock"]
    for package in ("structured-asn1", "structured-pkix", "structured-cms", "structured-xades"):
        directory = root / "crates" / package
        paths.append(directory / "Cargo.toml")
        paths.extend((directory / "src").rglob("*.rs"))
        # Crate documentation is a compilation input through include_str!.
        readme = directory / "README.md"
        if readme.is_file():
            paths.append(readme)
    paths.append(root / "scripts/fixtures/xades-native-key.rs")
    for path in sorted(paths):
        digest.update(str(path.relative_to(root)).encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()


def registry_graph(path):
    packages = tomllib.loads(path.read_text())["package"]
    return {(p["name"], p["version"], p.get("source"), p.get("checksum"))
            for p in packages if p.get("source", "").startswith("registry+")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xml-source", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    revision = run(["git", "-C", str(args.xml_source), "rev-parse", "--verify",
                    "--end-of-options", args.revision + "^{commit}"],
                   capture_output=True, text=True).stdout.strip()
    output = root / "target/xades-native-key-qualification"
    output.mkdir(parents=True, exist_ok=True)
    with (output / "runner.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        source = output / ("xml-" + revision)
        if not source.exists():
            with tempfile.TemporaryDirectory(prefix="export-", dir=output) as temporary:
                temporary = Path(temporary)
                archive = temporary / "source.tar"
                with archive.open("wb") as stream:
                    run(["git", "-C", str(args.xml_source), "archive", revision], stdout=stream)
                extracted = temporary / "source"
                extracted.mkdir()
                with tarfile.open(archive) as contents:
                    contents.extractall(extracted, filter="data")
                (extracted / ".qualification-revision").write_text(revision)
                os.replace(extracted, source)
        if (source / ".qualification-revision").read_text() != revision:
            raise RuntimeError("qualification source cache has another revision")
        harness = output / "harness"
        harness.mkdir(exist_ok=True)
        quoted = lambda path: json.dumps(str(path), ensure_ascii=False)
        manifest = ["[workspace]", "[package]", 'name = "xades-native-key-qualification"',
                    'version = "0.0.0"', 'edition = "2024"', "publish = false", "[dependencies]"]
        for package in ("structured-asn1", "structured-pkix", "structured-xades"):
            manifest.append(f"{package} = {{ path = {quoted(root / 'crates' / package)} }}")
        manifest += [f"xml-sec = {{ path = {quoted(source)}, default-features = false, features = "
                     '["xmldsig", "c14n", "xml-backend-roxmltree"] }',
                     'p256 = { version = "=0.14.0", features = ["ecdsa", "pkcs8"] }',
                     "[patch.crates-io]"]
        for package in ("structured-asn1", "structured-pkix", "structured-cms"):
            manifest.append(f"{package} = {{ path = {quoted(root / 'crates' / package)} }}")
        manifest += ["[[test]]", 'name = "native-key"',
                     f"path = {quoted(root / 'scripts/fixtures/xades-native-key.rs')}"]
        cargo_manifest = harness / "Cargo.toml"
        cargo_manifest.write_text("\n".join(manifest) + "\n")
        cargo_lock = harness / "Cargo.lock"
        # The library repository does not track Cargo.lock. Capture the actual
        # owner's qualified lock as an explicit source input, never invent a
        # claim that it was part of the exported commit.
        native_lock = args.xml_source / "Cargo.lock"
        native_lock_bytes = native_lock.read_bytes()
        locked_native = output / "native-Cargo.lock"
        locked_native.write_bytes(native_lock_bytes)
        shutil.copyfile(locked_native, cargo_lock)
        before = source_hash(root)
        print(f"Source-only XML revision {revision}; native lock SHA256 "
              f"{hashlib.sha256(native_lock_bytes).hexdigest()}; "
              f"primitives source SHA256 {before}", flush=True)
        # Resolve the path experiment before executing any compiled fixture.
        # Reject registry drift first, rather than discovering it after tests.
        run(["cargo", "+stable", "metadata", "--offline", "--format-version", "1",
             "--manifest-path", str(cargo_manifest)], cwd=root, stdout=subprocess.DEVNULL)
        allowed = registry_graph(locked_native) | registry_graph(root / "Cargo.lock")
        drift = registry_graph(cargo_lock) - allowed
        if drift:
            raise RuntimeError(f"qualification resolved versions outside the locked graphs: {drift}")
        run(["cargo", "+stable", "nextest", "run", "--manifest-path", str(cargo_manifest),
             "--locked", "--offline",
             "--target-dir", str(root / "target"), "--status-level", "fail",
             "--final-status-level", "fail"], cwd=root)
        if source_hash(root) != before:
            raise RuntimeError("primitives source changed during qualification")
        if native_lock.read_bytes() != native_lock_bytes:
            raise RuntimeError("native qualification lock changed during this run")
        print("Native selected-key bridge PASS; no whole XML/profile or registry qualification claimed.")


if __name__ == "__main__":
    main()
