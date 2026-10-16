#!/usr/bin/env python3
"""Pinned independent XMLDSig/CMS fixture oracles; never a runtime backend.

Requires curl, xmlsec1, openssl and Python lxml. Upstream data and its LGPL notice stay
under target/, outside packages. This checks mathematical XML/CMS signatures,
not trust, historical revocation or complete XAdES/archive coverage acceptance.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import runpy
import ssl
import subprocess
import xml.etree.ElementTree as ET
from lxml import etree


REVISION = "9f3af8f2ca672b8948e0a3ee8687e53adf9f5c33"
BASE = f"https://raw.githubusercontent.com/esig/dss/{REVISION}/"
FIXTURE = "dss-xades/src/test/resources/validation/xades-lta-valid.xml"
SHA256 = "d6ba7c610b283e8ccd8a0161081bc702c8ce31a1268369c2899a7c7c25cb6038"
DS = "http://www.w3.org/2000/09/xmldsig#"
XADES = "http://uri.etsi.org/01903/v1.3.2#"


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


def fixture_bytes(output):
    target = output / "xades-lta-valid.xml"
    original = target.read_bytes() if target.exists() else fetch(FIXTURE)
    if hashlib.sha256(original).hexdigest() != SHA256:
        raise RuntimeError("independent fixture SHA256 mismatch")
    # Preserve the original publisher notice next to all downloaded test data.
    if not (output / "LICENSE.upstream").exists():
        (output / "LICENSE.upstream").write_bytes(fetch("LICENSE"))
    target.write_bytes(original)
    return target, original


def verify_xml(output, target, original, tree):
    certificate = tree.find(f".//{{{DS}}}KeyInfo/{{{DS}}}X509Data/{{{DS}}}X509Certificate")
    if certificate is None:
        raise RuntimeError("fixture has no original signer certificate")
    key = output / "signer.pem"
    key.write_text(ssl.DER_cert_to_PEM_cert(base64.b64decode(certificate.text)))
    # This is historical fixture signature math, explicitly NOT certificate
    # trust or current validity. Do not export this setting to runtime policy.
    command = ["xmlsec1", "--verify", "--print-debug", "--insecure", "--pubkey-cert-pem", str(key),
               "--enabled-reference-uris", "empty,same-doc",
               "--enabled-retrieval-method-uris", "empty,same-doc",
               "--id-attr:Id", f"{XADES}:SignedProperties"]
    checked = run(command + [str(target)])
    (output / "xmlsec-valid.log").write_bytes(checked.stdout + checked.stderr)
    # Change only SignatureValue. Preserve the exact signed document spelling;
    # a serializer-induced reference failure would not exercise this oracle.
    value = tree.find(f"{{{DS}}}SignatureValue")
    if value is None or not value.text:
        raise RuntimeError("fixture has no signature value")
    encoded = value.text.encode("utf-8")
    if original.count(encoded) != 1:
        raise RuntimeError("cannot uniquely locate the original signature text")
    damaged = bytearray(base64.b64decode(value.text))
    damaged[0] ^= 1
    altered = output / "signature-bit-flipped.xml"
    altered.write_bytes(original.replace(encoded, base64.b64encode(damaged), 1))
    rejected = subprocess.run(command + [str(altered)], capture_output=True)
    log = rejected.stdout + rejected.stderr
    (output / "xmlsec-bit-flipped.log").write_bytes(log)
    # xmlsec1 verifies SignatureValue BEFORE executing references on failure.
    # Require its exact mathematical-failure category, not reference processing
    # that deliberately never happens for this modified signature.
    if rejected.returncode == 0 or b"Failure reason: SIGNATURE" not in log:
        raise RuntimeError("mutation did not isolate signature mathematics")


def verify_tokens(output, tree):
    tokens = list(tree.iter(f"{{{XADES}}}EncapsulatedTimeStamp"))
    if len(tokens) != 2:
        raise RuntimeError("fixture token census changed")
    for ordinal, token in enumerate(tokens):
        path = output / f"token-{ordinal}.der"
        path.write_bytes(base64.b64decode(token.text))
        checked = run(["openssl", "cms", "-verify", "-binary", "-inform", "DER",
                       "-in", str(path), "-noverify", "-out",
                       str(output / f"tstinfo-{ordinal}.der")])
        (output / f"cms-{ordinal}.log").write_bytes(checked.stdout + checked.stderr)


def original_inputs(output, target):
    # Test-only independent libxml2 C14N oracle, never a product dependency.
    # EN319132-1 §§5.3, 5.5.2.3: transformed references, SignedInfo,
    # SignatureValue, KeyInfo, preceding unsigned properties, other ds:Objects.
    tree = etree.parse(str(target), etree.XMLParser(resolve_entities=False, no_network=True))
    ns = {"d": DS, "x": XADES, "a": "http://uri.etsi.org/01903/v1.4.1#"}
    canonical = lambda node: etree.tostring(node, method="c14n", exclusive=True, with_comments=False)
    references = tree.xpath("//d:Signature/d:SignedInfo/d:Reference", namespaces=ns)
    if len(references) != 2:
        raise RuntimeError("independent reference census changed")
    ids = {node.get("Id"): node for node in tree.iter() if node.get("Id")}
    transforms = [node.xpath("d:Transforms/d:Transform/@Algorithm", namespaces=ns)
                  for node in references]
    if transforms != [[DS + "base64"], ["http://www.w3.org/2001/10/xml-exc-c14n#"]]:
        raise RuntimeError("independent transform contract changed")
    parts = [base64.b64decode("".join(ids[references[0].get("URI")[1:]].itertext())),
             canonical(ids[references[1].get("URI")[1:]])]
    parts += [canonical(tree.xpath("//d:Signature/d:" + name, namespaces=ns)[0])
              for name in ("SignedInfo", "SignatureValue", "KeyInfo")]
    unsigned = tree.xpath("//x:UnsignedSignatureProperties/*", namespaces=ns)
    if [etree.QName(node).localname for node in unsigned] != [
            "SignatureTimeStamp", "CertificateValues", "RevocationValues", "ArchiveTimeStamp"]:
        raise RuntimeError("independent preceding-property census changed")
    parts += [canonical(node) for node in unsigned[:-1]]
    others = tree.xpath("//d:Signature/d:Object[not(x:QualifyingProperties)]", namespaces=ns)
    if len(others) != 1:
        raise RuntimeError("independent other-object census changed")
    parts += [canonical(node) for node in others]
    signature = parts[3]
    archive = b"".join(parts)
    if hashlib.sha256(signature).hexdigest() != "b3d8aeb10b119f6513ca9c67b65e6ebe915034e3b0aec8a0c89dc42f17ec3bf7":
        raise RuntimeError("signature timestamp input differs from independent TSTInfo")
    if hashlib.sha256(archive).hexdigest() != "b49d025c7282021bfc5566a5325ef05abafce46fa810862a6fad5b0c0219c9bf":
        raise RuntimeError("archive input differs from independent TSTInfo")
    for ordinal, part in enumerate(parts):
        (output / f"part-{ordinal}.bin").write_bytes(part)
    (output / "signature-input.bin").write_bytes(signature)
    (output / "archive-input.bin").write_bytes(archive)


def harness_hash(root):
    digest = hashlib.sha256()
    paths = [root / "scripts/fixtures/xades-dss-corpus.rs",
             root / "crates/structured-xades/tests/containers.rs"]
    paths.extend((root / "crates/structured-xades/tests/support").rglob("*.rs"))
    for path in sorted(paths):
        digest.update(str(path.relative_to(root)).encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()


def qualify_shared(output):
    root = Path(__file__).resolve().parent.parent
    helpers = runpy.run_path(str(root / "scripts/qualify-xades-key.py"))
    source_hash = helpers["source_hash"]
    registry_graph = helpers["registry_graph"]
    before = source_hash(root)
    fixture_before = harness_hash(root)
    manifest = ["[workspace]", "[package]", 'name = "xades-dss-qualification"',
                'version = "0.0.0"', 'edition = "2024"', "publish = false", "[dependencies]"]
    for package in ("structured-asn1", "structured-pkix", "structured-cms", "structured-xades"):
        path = json.dumps(str(root / "crates" / package))
        manifest.append(f"{package} = {{ path = {path}, default-features = false }}")
    manifest += ['p256 = { version = "=0.14.0", default-features = false, features = ["ecdsa"] }',
                 'sha2 = { version = "=0.11.1", default-features = false }']
    manifest += ["[[test]]", 'name = "independent-tokens"',
                 "path = " + json.dumps(str(root / "scripts/fixtures/xades-dss-corpus.rs"))]
    cargo = output / "Cargo.toml"
    cargo.write_text("\n".join(manifest) + "\n")
    shutil.copyfile(root / "Cargo.lock", output / "Cargo.lock")
    run(["cargo", "metadata", "--manifest-path", str(cargo), "--offline",
         "--format-version", "1"])
    drift = registry_graph(output / "Cargo.lock") - registry_graph(root / "Cargo.lock")
    if drift:
        raise RuntimeError(f"corpus runner resolved outside the locked graph: {drift}")
    environment = dict(os.environ, XADES_DSS_CORPUS=str(output), CARGO_INCREMENTAL="0")
    subprocess.run(["cargo", "nextest", "run", "--manifest-path", str(cargo),
                    "--locked", "--offline", "--target-dir", str(root / "target"),
                    "--status-level", "fail", "--final-status-level", "fail"],
                   env=environment, check=True)
    if source_hash(root) != before or harness_hash(root) != fixture_before:
        raise RuntimeError("source changed during independent qualification")
    (output / "qualification.json").write_text(json.dumps({
        "upstream_revision": REVISION, "fixture_sha256": SHA256,
        "source_sha256": before, "harness_sha256": fixture_before,
        "xmlsec": run(["xmlsec1", "--version"]).stdout.decode().strip(),
        "openssl": run(["openssl", "version"]).stdout.decode().strip(),
        "scope": "original signature/archive inputs and XML/CMS math; no trust verdict",
    }, indent=2) + "\n")


def main():
    output = Path(__file__).resolve().parent.parent / "target/xades-corpus-qualification"
    output.mkdir(parents=True, exist_ok=True)
    target, original = fixture_bytes(output)
    tree = ET.fromstring(original)
    verify_xml(output, target, original, tree)
    verify_tokens(output, tree)
    original_inputs(output, target)
    qualify_shared(output)
    print(f"Independent DSS {REVISION} fixture SHA256 {SHA256}: "
          "XML signature + both references PASS; isolated signature mutation refused; "
          "2 CMS token signatures PASS. No trust/archive-coverage verdict.")


if __name__ == "__main__":
    main()
