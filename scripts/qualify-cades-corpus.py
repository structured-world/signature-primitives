#!/usr/bin/env python3
"""Pinned independent CAdES archive-time-stamp-v3 oracle; never a runtime backend.

Requires curl and cargo-nextest. Upstream data and its LGPL notice stay under
target/, outside packages. For every archive-time-stamp-v3 of each fixture this
script derives, from its own DER walker, the EN 319 122-1 V1.3.1 §5.5.3
message-imprint input and the §5.5.2 index entries that match no original
element, checks the input against the token's TSTInfo messageImprint, and runs
the structured-cms harness that must reach the same answers. No signature,
trust or level verdict is made.
"""

import hashlib
import json
import os
import runpy
import shutil
import subprocess
from pathlib import Path


REVISION = "9f3af8f2ca672b8948e0a3ee8687e53adf9f5c33"
BASE = f"https://raw.githubusercontent.com/esig/dss/{REVISION}/"
VALIDATION = "dss-cades/src/test/resources/validation/"
ARCHIVE_TIMESTAMP_V3 = "0.4.0.1733.2.4"
ATS_HASH_INDEX_V3 = "0.4.0.19122.1.5"
# TS 101 733 V2.2.1 ats-hash-index: another value syntax and another attribute
# hashing rule, which EN 319 122-1 replaced; it is not read as a v3 index.
ATS_HASH_INDEX_SUPERSEDED = "0.4.0.1733.2.5"
DIGESTS = {"2.16.840.1.101.3.4.2.1": "sha256", "2.16.840.1.101.3.4.2.2": "sha384",
           "2.16.840.1.101.3.4.2.3": "sha512", "1.3.14.3.2.26": "sha1"}
# `expect` is checked against what the independent walker finds, never taken
# from the upstream file name: "conforming" (every index entry has its element
# and an attached content's imprint matches), "defective" (some entry has no
# element), "superseded" (only the TS 101 733 index is present).
FIXTURES = {
    "single": {"file": "cades-lta-en319122.cms", "tokens": 1, "expect": "conforming",
               "sha256": "ba98415ab542ef9b1b9f190e8a80e445a68f825df6de5d6f669ab8f458edd266"},
    # Its crlsHashIndex entry hashes a CertificateList inside the
    # revocation-values attribute while the crls field is empty; §5.5.2 indexes
    # only the root SignedData crls choices, so that entry has no element.
    "rev-val-crl": {"file": "cades-ats-v3-rev-val-crl.p7s", "tokens": 1, "expect": "defective",
                    "sha256": "7e5a7d6f1ec0402777bd32bf32d5749efdcdb2f76b1a98ecf8bcd0943f009512"},
    "wrong-certificate": {"file": "cades-ats-v3-wrong-cert.p7m", "tokens": 1,
                          "expect": "defective",
                          "sha256": "532c4d16759695b968da7046d2738ed1368d7216313bc690ca0be78f37b5009c"},
    "wrong-crl": {"file": "cades-ats-v3-wrong-crl.p7s", "tokens": 1, "expect": "defective",
                  "sha256": "8aa890fc0ccb26c82c7fab53932f0fd8aa137ca4d43c94934990f163738e60c9"},
    "wrong-ocsp": {"file": "cades-ats-v3-wrong-ocsp.p7s", "tokens": 1, "expect": "defective",
                   "sha256": "b0de6f206b000266517c9a62576cafc82d75a73a46e4c0b4918aeb9846510dcc"},
    "superseded-double": {"file": "CAdESDoubleLTA.p7m", "tokens": 2, "expect": "superseded",
                      "sha256": "d63c706b978be8805b10b0041b7e49f79760c2e2ebbc5379607a22f41d70989a"},
}


def run(arguments):
    result = subprocess.run(arguments, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace"))
    return result


def fetch(path):
    # curl uses the host's normal verified TLS store; no disabled verification.
    return run(["curl", "--fail", "--silent", "--show-error", "--location",
                "--proto", "=https", "--proto-redir", "=https",
                "--max-time", "60", BASE + path]).stdout


def fixture_bytes(directory, spec):
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / Path(spec["file"]).name
    original = target.read_bytes() if target.exists() else fetch(VALIDATION + spec["file"])
    if hashlib.sha256(original).hexdigest() != spec["sha256"]:
        raise RuntimeError(f"independent fixture SHA256 mismatch: {spec['file']}")
    target.write_bytes(original)
    return target, original


class Node:
    """One definite-length TLV: its whole encoding and its contents."""

    def __init__(self, data, start):
        self.tag = data[start]
        if self.tag & 0x1f == 0x1f:
            raise RuntimeError("multi-byte tags do not occur in these fixtures")
        first = data[start + 1]
        if first < 0x80:
            length, header = first, 2
        elif first == 0x80:
            raise RuntimeError("indefinite length does not occur in these fixtures")
        else:
            count = first & 0x7f
            length = int.from_bytes(data[start + 2:start + 2 + count], "big")
            header = 2 + count
        self.encoding = data[start:start + header + length]
        self.contents = data[start + header:start + header + length]
        if len(self.encoding) != header + length:
            raise RuntimeError("truncated element")

    def children(self):
        offset, found = 0, []
        while offset < len(self.contents):
            child = Node(self.contents, offset)
            found.append(child)
            offset += len(child.encoding)
        return found


def parse(data):
    node = Node(data, 0)
    if len(node.encoding) != len(data):
        raise RuntimeError("trailing data")
    return node


def oid(node):
    if node.tag != 0x06:
        raise RuntimeError("not an object identifier")
    arcs, value = [], 0
    for byte in node.contents:
        value = (value << 7) | (byte & 0x7f)
        if not byte & 0x80:
            arcs.append(value)
            value = 0
    first = min(arcs[0] // 40, 2)
    return ".".join(str(arc) for arc in [first, arcs[0] - 40 * first] + arcs[1:])


def signed_data(content_info):
    # ContentInfo { contentType, [0] EXPLICIT SignedData }
    kind, wrapper = content_info.children()
    if oid(kind) != "1.2.840.113549.1.7.2":
        raise RuntimeError("not signed-data")
    return wrapper.children()[0]


def sections(signed):
    # SignedData { version, digestAlgorithms, encapContentInfo,
    #              [0] certificates OPTIONAL, [1] crls OPTIONAL, signerInfos }
    fields = signed.children()
    encapsulated, certificates, revocations = fields[2], [], []
    for field in fields[3:-1]:
        if field.tag == 0xa0:
            certificates = field.children()
        elif field.tag == 0xa1:
            revocations = field.children()
    return encapsulated, certificates, revocations, fields[-1].children()


def attributes(signer):
    # SignerInfo fields up to signature, then [1] unsignedAttrs OPTIONAL.
    fields = signer.children()
    if fields[-1].tag != 0xa1:
        return b"".join(field.encoding for field in fields), []
    signed_fields = b"".join(field.encoding for field in fields[:-1])
    found = []
    for attribute in fields[-1].children():
        kind, values = attribute.children()
        found.append((kind, values.children()))
    return signed_fields, found


def imprint(token):
    # TSTInfo { version, policy, messageImprint { hashAlgorithm, hashedMessage }, ... }
    encapsulated = sections(signed_data(token))[0]
    tst = parse(encapsulated.children()[1].children()[0].contents)
    algorithm, hashed = tst.children()[2].children()
    return DIGESTS[oid(algorithm.children()[0])], hashed.contents


def qualify(directory, spec):
    target, original = fixture_bytes(directory, spec)
    encapsulated, certificates, revocations, signers = sections(signed_data(parse(original)))
    if len(signers) != 1:
        raise RuntimeError("independent signer census changed")
    content_type, *wrapper = encapsulated.children()
    # Detached content is not in the fixture, so its imprint is not computed.
    content = wrapper[0].children()[0].contents if wrapper else None
    signed_fields, unsigned = attributes(signers[0])
    tokens = [value for kind, values in unsigned if oid(kind) == ARCHIVE_TIMESTAMP_V3
              for value in values]
    if len(tokens) != spec["tokens"]:
        raise RuntimeError(f"independent archive-time-stamp census changed: {len(tokens)}")
    expected = []
    for ordinal, token in enumerate(tokens):
        _, token_unsigned = attributes(sections(signed_data(token))[3][0])
        kinds = [oid(kind) for kind, _ in token_unsigned]
        indexes = [values for kind, values in token_unsigned if oid(kind) == ATS_HASH_INDEX_V3]
        if not indexes:
            if ATS_HASH_INDEX_SUPERSEDED not in kinds:
                raise RuntimeError("archive time-stamp without any hash index")
            expected.append({"index": "superseded"})
            continue
        if len(indexes) != 1 or len(indexes[0]) != 1:
            raise RuntimeError("ats-hash-index-v3 is not a single attribute value")
        index = indexes[0][0]
        algorithm_field, *lists = index.children()
        name = DIGESTS[oid(algorithm_field.children()[0])]
        digest_name, hashed = imprint(token)
        if digest_name != name:
            raise RuntimeError("index and imprint algorithms differ")
        digest = lambda data: hashlib.new(name, data).digest()
        matches = None
        if content is not None:
            # §5.5.3: eContentType, content hash, signer fields, ATSHashIndexV3.
            archive = content_type.encoding + digest(content) + signed_fields + index.encoding
            (directory / f"ats-{ordinal}-input.bin").write_bytes(archive)
            matches = digest(archive) == hashed
        # §5.5.2: hash every element present now; an entry absent from them is unmatched.
        present = [
            {digest(node.encoding) for node in certificates},
            {digest(node.encoding) for node in revocations},
            {digest(kind.encoding + value.encoding) for kind, values in unsigned for value in values},
        ]
        unmatched = [f"{name_} {position}"
                     for name_, entries, known in zip(("certificates", "revocations", "values"),
                                                      lists, present)
                     for position, entry in enumerate(entries.children())
                     if entry.contents not in known]
        (directory / f"ats-{ordinal}-index.txt").write_text("\n".join(unmatched) + "\n"
                                                            if unmatched else "")
        expected.append({"index": "v3", "imprint_matches": matches, "unmatched": unmatched})
    (directory / "expected.json").write_text(json.dumps(expected, indent=2) + "\n")
    outcome = classify(expected)
    if outcome != spec["expect"]:
        raise RuntimeError(f"{spec['file']}: independent walker found {outcome}, "
                           f"not {spec['expect']}: {expected}")
    return expected


def classify(tokens):
    if all(token["index"] == "superseded" for token in tokens):
        return "superseded"
    if any(token["index"] == "v3" and token["unmatched"] for token in tokens):
        return "defective"
    if all(token["imprint_matches"] is not False for token in tokens if token["index"] == "v3"):
        return "conforming"
    return "imprint-mismatch"


def harness_hash(root):
    digest = hashlib.sha256()
    for path in sorted([root / "scripts/fixtures/cades-dss-corpus.rs"]):
        digest.update(str(path.relative_to(root)).encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()


def qualify_shared(output):
    root = Path(__file__).resolve().parent.parent
    helpers = runpy.run_path(str(root / "scripts/qualify-xades-key.py"))
    source_hash = helpers["source_hash"]
    registry_graph = helpers["registry_graph"]
    before = source_hash(root)
    fixture_before = harness_hash(root)
    manifest = ["[workspace]", "[package]", 'name = "cades-dss-qualification"',
                'version = "0.0.0"', 'edition = "2024"', "publish = false", "[dependencies]"]
    for package in ("structured-asn1", "structured-pkix", "structured-cms"):
        path = json.dumps(str(root / "crates" / package))
        manifest.append(f"{package} = {{ path = {path}, default-features = false }}")
    manifest += ['sha2 = { version = "=0.11.1", default-features = false }']
    manifest += ["[[test]]", 'name = "archive-timestamps"',
                 "path = " + json.dumps(str(root / "scripts/fixtures/cades-dss-corpus.rs"))]
    cargo = output / "Cargo.toml"
    cargo.write_text("\n".join(manifest) + "\n")
    shutil.copyfile(root / "Cargo.lock", output / "Cargo.lock")
    run(["cargo", "metadata", "--manifest-path", str(cargo), "--offline",
         "--format-version", "1"])
    drift = registry_graph(output / "Cargo.lock") - registry_graph(root / "Cargo.lock")
    if drift:
        raise RuntimeError(f"corpus runner resolved outside the locked graph: {drift}")
    environment = dict(os.environ, CADES_DSS_CORPUS=str(output), CARGO_INCREMENTAL="0")
    subprocess.run(["cargo", "nextest", "run", "--manifest-path", str(cargo),
                    "--locked", "--offline", "--target-dir", str(root / "target"),
                    "--status-level", "fail", "--final-status-level", "fail"],
                   env=environment, check=True)
    if source_hash(root) != before or harness_hash(root) != fixture_before:
        raise RuntimeError("source changed during independent qualification")
    return before, fixture_before


def main():
    output = Path(__file__).resolve().parent.parent / "target/cades-corpus-qualification"
    output.mkdir(parents=True, exist_ok=True)
    # Preserve the original publisher notice next to all downloaded test data.
    if not (output / "LICENSE.upstream").exists():
        (output / "LICENSE.upstream").write_bytes(fetch("LICENSE"))
    results = {name: qualify(output / name, spec) for name, spec in FIXTURES.items()}
    # The attached fixture is the one whose imprint can be recomputed: it must be.
    if results["single"][0]["imprint_matches"] is not True:
        raise RuntimeError("the attached fixture's archive imprint was not recomputed")
    source, harness = qualify_shared(output)
    (output / "qualification.json").write_text(json.dumps({
        "upstream_revision": REVISION,
        "fixtures": {name: {"file": spec["file"], "sha256": spec["sha256"],
                            "tokens": results[name]} for name, spec in FIXTURES.items()},
        "source_sha256": source, "harness_sha256": harness,
        "scope": "archive-time-stamp-v3 imprint input and ats-hash-index-v3 coverage; "
                 "no signature, trust or level verdict",
    }, indent=2) + "\n")
    print(f"Independent DSS {REVISION} CAdES archive-time-stamp-v3 fixtures: "
          f"{sum(len(tokens) for tokens in results.values())} tokens, imprint input and "
          "index coverage agree with the structured-cms harness. No trust verdict.")


if __name__ == "__main__":
    main()
