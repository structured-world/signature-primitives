#!/usr/bin/env python3
"""Pinned independent XMLDSig/CMS/OCSP fixture oracles; never a runtime backend.

Requires curl, xmlsec1, openssl and Python lxml. Upstream data and its LGPL notice stay
under target/, outside packages. This checks mathematical XML/CMS/OCSP signatures and
the original bytes shared code reads, not trust, historical revocation or complete
XAdES/archive coverage acceptance.
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
VALIDATION = "dss-xades/src/test/resources/validation/"
DS = "http://www.w3.org/2000/09/xmldsig#"
XADES = "http://uri.etsi.org/01903/v1.3.2#"
EXCLUSIVE = "http://www.w3.org/2001/10/xml-exc-c14n#"
# One fixture per baseline level. EN 319 132-1 V1.3.1 table 2 permits validation
# values at B-T, so the B-LT fixture is also the B-T qualification input.
FIXTURES = {
    "b": {"file": "dss-signed.xml", "tokens": 0, "unsigned": [],
          "sha256": "5b8b3f4a9ed2d83905f42339fe2f2455679d99ff392c182d57ca91a20ab28bb2"},
    "lt": {"file": "xades-lt-with-expired-ocsp-responder.xml", "tokens": 1,
           "unsigned": ["SignatureTimeStamp", "CertificateValues", "RevocationValues"],
           "sha256": "61d53a31920f8990c8d6d6636cc91e0a4ee274a77da2e0f29cf83ce4187e856c"},
    "lta": {"file": "xades-lta-valid.xml", "tokens": 2,
            "unsigned": ["SignatureTimeStamp", "CertificateValues", "RevocationValues",
                         "ArchiveTimeStamp"],
            "sha256": "d6ba7c610b283e8ccd8a0161081bc702c8ce31a1268369c2899a7c7c25cb6038"},
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


def fixture_bytes(output, spec):
    output.mkdir(parents=True, exist_ok=True)
    target = output / spec["file"]
    target.parent.mkdir(parents=True, exist_ok=True)
    original = target.read_bytes() if target.exists() else fetch(VALIDATION + spec["file"])
    if hashlib.sha256(original).hexdigest() != spec["sha256"]:
        raise RuntimeError(f"independent fixture SHA256 mismatch: {spec['file']}")
    target.write_bytes(original)
    return target, original


def verify_xml(output, target, original, tree):
    certificate = tree.find(f".//{{{DS}}}KeyInfo/{{{DS}}}X509Data/{{{DS}}}X509Certificate")
    if certificate is None:
        raise RuntimeError("fixture has no original signer certificate")
    signer = base64.b64decode(certificate.text)
    (output / "signer.der").write_bytes(signer)
    key = output / "signer.pem"
    key.write_text(ssl.DER_cert_to_PEM_cert(signer))
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
    value = tree.find(f".//{{{DS}}}SignatureValue")
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
    return command


def verify_reference_mutation(output, original, command):
    # Change one character of the enveloped signed data, leaving SignedInfo
    # and SignatureValue intact: XMLDSig must refuse the reference digest.
    if original.count(b">Hello<") != 1:
        raise RuntimeError("cannot uniquely locate the signed data text")
    altered = output / "data-altered.xml"
    altered.write_bytes(original.replace(b">Hello<", b">Hellp<", 1))
    rejected = subprocess.run(command + [str(altered)], capture_output=True)
    log = rejected.stdout + rejected.stderr
    (output / "xmlsec-data-altered.log").write_bytes(log)
    if rejected.returncode == 0 or b"Failure reason: REFERENCE" not in log:
        raise RuntimeError("data mutation did not isolate the reference digest")


# Each negative fixture breaks exactly one stated rule while staying otherwise
# well formed. `xmlsec` is the XMLDSig outcome the oracle must report: these
# defects are XAdES-level, except a tampered reference, which XMLDSig refuses.
NEGATIVE = {
    "copied-sigtst": {"file": "xades-t-copied-sigtst.xml", "xmlsec": "valid",
                      "defect": "foreign-imprint",
                      "sha256": "f3f994b85c1553d0396c5eff791cafdeb1d2df6cf3d6978a73996ab473d7497c"},
    "no-keyinfo": {"file": "xades-level-b-with-certvals.xml", "xmlsec": None,
                   "defect": "KeyInfo",
                   "sha256": "7c85f8bc9aaddfda3d9de52c89e381b5c344fd6106b45c5e46f62003e15404f1"},
    "no-signing-time": {"file": "xades-extended-t.xml", "xmlsec": "valid",
                        "defect": "SigningTime",
                        "sha256": "b4876b64715331ee4d4759035ad7fc7495b242a82f41bfb46ccaad1b4315c973"},
    "signing-certificate-v1": {"file": "xades-with-equivalent-certs.xml", "xmlsec": "valid",
                               "defect": "SigningCertificate",
                               "sha256": "95e220374c60fe0a9ece68c9dacf4ec744db92391df9d16ec6358fedec882ba6"},
    "signed-properties-unreferenced": {"file": "dss-signed-altered-signedPropsRemoved.xml",
                                       # The reference was cut from SignedInfo after
                                       # signing, so SignatureValue no longer verifies.
                                       "xmlsec": "SIGNATURE", "defect": "SignedProperties",
                                       "sha256": "e4f8b7de169136fd2fff39415e6e753ef53ad2cbbcedebb13d44eb76b14e9bad"},
    # Signature wrapping: XMLDSig math holds, the XAdES binding must not.
    "wrapped-signed-properties": {"file": "xsw/XSW-enveloped-fake-signedProperties.xml",
                                  "xmlsec": "valid", "defect": "WrappedSignedProperties",
                                  "sha256": "ad7d46193d6d30050f5d5106aa128342c3485372ac85a91280a1c165328d4c03"},
    "unreferenced-object": {"file": "xsw/XSW-enveloping-fake-object.xml",
                            "xmlsec": "valid", "defect": "UnreferencedObject",
                            "sha256": "34a13993f34ab97ce5b60f2ed50371cdd4ea6bec6d78e4dc3396a4a912e79f73"},
    # The KeyInfo certificate bytes were altered until they no longer decode.
    "tampered-keyinfo": {"file": "xades-tampered-keyinfo.xml", "xmlsec": "error",
                         "defect": "KeyInfoCertificate",
                         "sha256": "738f026a774d062eceb0f4e7b27c5a076088c277f2c7693b919c600134ab1223"},
}


# Several signatures in one document.
MULTIPLE = {"file": "doubleSignedTest.xml",
            "sha256": "65709385b3cff732b602048c1346eed48ffd3b45de848f810fdf225c3c739494"}


def xmlsec_signature(directory, target, certificate, extra):
    key = directory / "signer.pem"
    key.write_text(ssl.DER_cert_to_PEM_cert(base64.b64decode(certificate.text)))
    result = subprocess.run(["xmlsec1", "--verify", "--print-debug", "--insecure",
                             "--pubkey-cert-pem", str(key),
                             "--id-attr:Id", f"{XADES}:SignedProperties"] + extra + [str(target)],
                            capture_output=True, cwd=directory)
    return result.returncode, result.stdout + result.stderr


def qualify_multiple(output):
    # Two signatures in one document are selected and judged separately:
    # the oracle verifies each by its Id, and only one of them carries the
    # SigningCertificateV2 that EN319132-1 table 2 requires.
    directory = output / "multiple"
    target, original = fixture_bytes(directory, MULTIPLE)
    tree = ET.fromstring(original)
    signatures = list(tree.iter(f"{{{DS}}}Signature"))
    if len(signatures) != 2:
        raise RuntimeError("independent signature census changed")
    versions = []
    for ordinal, signature in enumerate(signatures):
        certificate = signature.find(f"{{{DS}}}KeyInfo/{{{DS}}}X509Data/{{{DS}}}X509Certificate")
        code, log = xmlsec_signature(directory, target, certificate,
                                     ["--enabled-reference-uris", "empty,same-doc",
                                      "--id-attr:Id", f"{DS}:Signature",
                                      "--node-id", signature.get("Id")])
        (directory / f"xmlsec-{ordinal}.log").write_bytes(log)
        if code != 0:
            raise RuntimeError(f"signature {ordinal} does not verify")
        versions.append([len(list(signature.iter(f"{{{XADES}}}{name}")))
                         for name in ("SigningCertificateV2", "SigningCertificate")])
    if sorted(versions) != [[0, 1], [1, 0]]:
        raise RuntimeError(f"independent signing-certificate split changed: {versions}")


def xmlsec_outcome(output, target, tree):
    certificate = tree.find(f".//{{{DS}}}KeyInfo/{{{DS}}}X509Data/{{{DS}}}X509Certificate")
    signer = base64.b64decode(certificate.text)
    (output / "signer.der").write_bytes(signer)
    key = output / "signer.pem"
    key.write_text(ssl.DER_cert_to_PEM_cert(signer))
    result = subprocess.run(["xmlsec1", "--verify", "--print-debug", "--insecure",
                             "--pubkey-cert-pem", str(key),
                             "--enabled-reference-uris", "empty,same-doc",
                             "--enabled-retrieval-method-uris", "empty,same-doc",
                             "--id-attr:Id", f"{XADES}:SignedProperties", str(target)],
                            capture_output=True)
    log = result.stdout + result.stderr
    (output / "xmlsec.log").write_bytes(log)
    if result.returncode == 0:
        return "valid"
    for reason in ("SIGNATURE", "REFERENCE"):
        if f"Failure reason: {reason}".encode() in log:
            return reason
    return "error"


def defect_present(tree, defect):
    references = tree.findall(f".//{{{DS}}}SignedInfo/{{{DS}}}Reference")
    if defect == "KeyInfo":
        # EN319132-1 table 2 and requirement a): ds:KeyInfo/X509Data is mandatory.
        return tree.find(f".//{{{DS}}}KeyInfo") is None
    if defect == "SigningTime":
        return not list(tree.iter(f"{{{XADES}}}SigningTime"))
    if defect == "SigningCertificate":
        return (bool(list(tree.iter(f"{{{XADES}}}SigningCertificate")))
                and not list(tree.iter(f"{{{XADES}}}SigningCertificateV2")))
    if defect == "SignedProperties":
        # EN319132-1 §4.3: one ds:Reference must cover the SignedProperties.
        return (tree.find(f".//{{{XADES}}}SignedProperties") is not None
                and not [node for node in references
                         if node.get("Type", "").endswith("#SignedProperties")])
    referenced = {node.get("URI", "")[1:] for node in references
                  if node.get("URI", "").startswith("#")}
    if defect == "WrappedSignedProperties":
        # EN319132-1 §4.3/§4.4: the signed SignedProperties is the child of the
        # one QualifyingProperties; a copy elsewhere cannot carry the properties.
        inside = {node.get("Id") for node in tree.iterfind(
            f".//{{{XADES}}}QualifyingProperties/{{{XADES}}}SignedProperties")}
        signed = {node.get("Id") for node in tree.iter(f"{{{XADES}}}SignedProperties")
                  if node.get("Id") in referenced}
        return bool(signed) and not (signed & inside)
    if defect == "UnreferencedObject":
        # A ds:Object reached by no SignedInfo or Manifest reference is unsigned.
        for manifest in tree.iter(f"{{{DS}}}Manifest"):
            referenced |= {node.get("URI", "")[1:] for node in manifest.iter(f"{{{DS}}}Reference")
                           if node.get("URI", "").startswith("#")}
        objects = [node for node in tree.iter(f"{{{DS}}}Object")
                   if node.find(f"{{{XADES}}}QualifyingProperties") is None]
        return any(node.get("Id") not in referenced
                   and not any(child.get("Id") in referenced for child in node)
                   for node in objects)
    raise RuntimeError(f"unknown defect {defect}")


def qualify_negative(output):
    for name, spec in NEGATIVE.items():
        directory = output / "negative" / name
        target, original = fixture_bytes(directory, spec)
        tree = ET.fromstring(original)
        if spec["defect"] not in ("foreign-imprint", "KeyInfoCertificate") and not defect_present(
                tree, spec["defect"]):
            raise RuntimeError(f"{name}: stated defect {spec['defect']} is absent")
        if spec["xmlsec"] is not None:
            outcome = xmlsec_outcome(directory, target, tree)
            if outcome != spec["xmlsec"]:
                raise RuntimeError(f"{name}: xmlsec reported {outcome}, not {spec['xmlsec']}")
        if spec["defect"] == "KeyInfoCertificate":
            decoded = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout",
                                      "-in", str(directory / "signer.der")], capture_output=True)
            if decoded.returncode == 0:
                raise RuntimeError(f"{name}: the KeyInfo certificate still decodes")
        if spec["defect"] == "foreign-imprint":
            # Token 0 is the signed AllDataObjectsTimeStamp, token 1 the
            # SignatureTimeStamp carrying a copy of a foreign token.
            verify_tokens(directory, tree, 2)
            signature_input(directory, target)


def verify_census(tree, spec):
    # EN 319 132-1 V1.3.1 table 2: KeyInfo, SigningTime and SigningCertificateV2
    # are mandatory at every level; the version 1 SigningCertificate is forbidden.
    for name in ("SigningTime", "SigningCertificateV2"):
        if len(list(tree.iter(f"{{{XADES}}}{name}"))) != 1:
            raise RuntimeError(f"fixture lacks exactly one {name}")
    if list(tree.iter(f"{{{XADES}}}SigningCertificate")):
        raise RuntimeError("fixture carries the forbidden SigningCertificate")
    unsigned = tree.find(f".//{{{XADES}}}UnsignedSignatureProperties")
    names = [] if unsigned is None else [child.tag.split("}")[1] for child in unsigned]
    if names != spec["unsigned"]:
        raise RuntimeError(f"independent unsigned-property census changed: {names}")


def signing_certificate(output, tree):
    # EN319132-1 §5.2.2: the signed digest and IssuerSerialV2 of the one
    # SigningCertificateV2 entry, for the shared readers to bind to the signer.
    entries = list(tree.iter(f"{{{XADES}}}SigningCertificateV2"))[0].findall(f"{{{XADES}}}Cert")
    if len(entries) != 1:
        raise RuntimeError("independent signing-certificate census changed")
    method = entries[0].find(f"{{{XADES}}}CertDigest/{{{DS}}}DigestMethod").get("Algorithm")
    value = entries[0].find(f"{{{XADES}}}CertDigest/{{{DS}}}DigestValue").text
    (output / "cert-digest-method.txt").write_text(method)
    (output / "cert-digest.bin").write_bytes(base64.b64decode(value))
    hint = entries[0].find(f"{{{XADES}}}IssuerSerialV2")
    (output / "issuer-serial.der").write_bytes(base64.b64decode(hint.text))


def verify_tokens(output, tree, count):
    tokens = list(tree.iter(f"{{{XADES}}}EncapsulatedTimeStamp"))
    if len(tokens) != count:
        raise RuntimeError("fixture token census changed")
    for ordinal, token in enumerate(tokens):
        path = output / f"token-{ordinal}.der"
        path.write_bytes(base64.b64decode(token.text))
        checked = run(["openssl", "cms", "-verify", "-binary", "-inform", "DER",
                       "-in", str(path), "-noverify", "-out",
                       str(output / f"tstinfo-{ordinal}.der")])
        (output / f"cms-{ordinal}.log").write_bytes(checked.stdout + checked.stderr)


def verify_validation_values(output, tree):
    # Certificates and OCSP responses exactly as incorporated. OpenSSL checks
    # each response signature with a key from the same CertificateValues; the
    # responder chain, its expiry and status usability are deliberately unchecked.
    certificates = [base64.b64decode(node.text)
                    for node in tree.iter(f"{{{XADES}}}EncapsulatedX509Certificate")]
    bundle = output / "certificate-values.pem"
    bundle.write_text("".join(ssl.DER_cert_to_PEM_cert(value) for value in certificates))
    for ordinal, value in enumerate(certificates):
        (output / f"certificate-{ordinal}.der").write_bytes(value)
    responses = list(tree.iter(f"{{{XADES}}}EncapsulatedOCSPValue"))
    if len(responses) != 1:
        raise RuntimeError("independent OCSP census changed")
    for ordinal, response in enumerate(responses):
        path = output / f"ocsp-{ordinal}.der"
        path.write_bytes(base64.b64decode(response.text))
        checked = run(["openssl", "ocsp", "-respin", str(path), "-resp_text",
                       "-VAfile", str(bundle), "-no_cert_verify"])
        log = checked.stdout + checked.stderr
        (output / f"ocsp-{ordinal}.log").write_bytes(log)
        if b"Response verify OK" not in log or b"Cert Status: good" not in log:
            raise RuntimeError("OCSP signature or recorded status differs")


def canonical(node):
    return etree.tostring(node, method="c14n", exclusive=True, with_comments=False)


def parse(target):
    # Test-only independent libxml2 C14N oracle, never a product dependency.
    return etree.parse(str(target), etree.XMLParser(resolve_entities=False, no_network=True))


def signature_input(output, target):
    # EN319132-1 §5.3: the signature timestamp covers the canonicalized
    # SignatureValue under its own CanonicalizationMethod.
    tree = parse(target)
    ns = {"d": DS, "x": XADES}
    methods = tree.xpath("//x:SignatureTimeStamp/d:CanonicalizationMethod/@Algorithm",
                         namespaces=ns)
    if methods != [EXCLUSIVE]:
        raise RuntimeError("independent signature-timestamp C14N changed")
    value = canonical(tree.xpath("//d:Signature/d:SignatureValue", namespaces=ns)[0])
    (output / "signature-value.bin").write_bytes(value)
    (output / "signature-input.bin").write_bytes(value)


def archive_inputs(output, target):
    # EN319132-1 §§5.3, 5.5.2.3: transformed references, SignedInfo,
    # SignatureValue, KeyInfo, preceding unsigned properties, other ds:Objects.
    tree = parse(target)
    ns = {"d": DS, "x": XADES, "a": "http://uri.etsi.org/01903/v1.4.1#"}
    references = tree.xpath("//d:Signature/d:SignedInfo/d:Reference", namespaces=ns)
    if len(references) != 2:
        raise RuntimeError("independent reference census changed")
    ids = {node.get("Id"): node for node in tree.iter() if node.get("Id")}
    transforms = [node.xpath("d:Transforms/d:Transform/@Algorithm", namespaces=ns)
                  for node in references]
    if transforms != [[DS + "base64"], [EXCLUSIVE]]:
        raise RuntimeError("independent transform contract changed")
    parts = [base64.b64decode("".join(ids[references[0].get("URI")[1:]].itertext())),
             canonical(ids[references[1].get("URI")[1:]])]
    parts += [canonical(tree.xpath("//d:Signature/d:" + name, namespaces=ns)[0])
              for name in ("SignedInfo", "SignatureValue", "KeyInfo")]
    unsigned = tree.xpath("//x:UnsignedSignatureProperties/*", namespaces=ns)
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
    for package in ("structured-asn1", "structured-pkix", "structured-cms", "structured-ltv",
                    "structured-xades"):
        path = json.dumps(str(root / "crates" / package))
        manifest.append(f"{package} = {{ path = {path}, default-features = false }}")
    manifest += ['p256 = { version = "=0.14.0", default-features = false, features = ["ecdsa"] }',
                 'sha1 = { version = "=0.11.0", default-features = false }',
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
        "upstream_revision": REVISION,
        "fixtures": {level: {"file": spec["file"], "sha256": spec["sha256"]}
                     for level, spec in FIXTURES.items()},
        "negative": {name: {"file": spec["file"], "sha256": spec["sha256"],
                            "defect": spec["defect"], "xmlsec": spec["xmlsec"]}
                     for name, spec in NEGATIVE.items()},
        "multiple": {"file": MULTIPLE["file"], "sha256": MULTIPLE["sha256"]},
        "source_sha256": before, "harness_sha256": fixture_before,
        "xmlsec": run(["xmlsec1", "--version"]).stdout.decode().strip(),
        "openssl": run(["openssl", "version"]).stdout.decode().strip(),
        "scope": "original signature/timestamp/archive inputs, validation values and "
                 "XML/CMS/OCSP math; no trust verdict",
    }, indent=2) + "\n")


def main():
    output = Path(__file__).resolve().parent.parent / "target/xades-corpus-qualification"
    output.mkdir(parents=True, exist_ok=True)
    # Preserve the original publisher notice next to all downloaded test data.
    if not (output / "LICENSE.upstream").exists():
        (output / "LICENSE.upstream").write_bytes(fetch("LICENSE"))
    for level, spec in FIXTURES.items():
        directory = output / level
        target, original = fixture_bytes(directory, spec)
        tree = ET.fromstring(original)
        verify_census(tree, spec)
        command = verify_xml(directory, target, original, tree)
        if level == "b":
            verify_reference_mutation(directory, original, command)
        signing_certificate(directory, tree)
        verify_tokens(directory, tree, spec["tokens"])
    signature_input(output / "lt", output / "lt" / FIXTURES["lt"]["file"])
    verify_validation_values(output / "lt", ET.fromstring(
        (output / "lt" / FIXTURES["lt"]["file"]).read_bytes()))
    archive_inputs(output / "lta", output / "lta" / FIXTURES["lta"]["file"])
    qualify_negative(output)
    qualify_multiple(output)
    qualify_shared(output)
    print(f"Independent DSS {REVISION} B-B/B-LT/B-LTA fixtures: "
          "XML signatures + references PASS; isolated signature and data mutations refused; "
          "3 CMS token signatures and 1 OCSP response signature PASS; "
          f"{len(NEGATIVE)} negative fixtures show their stated defect; "
          "two signatures in one document verified separately. "
          "No trust/archive-coverage verdict.")


if __name__ == "__main__":
    main()
