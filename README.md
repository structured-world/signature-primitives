# Signature primitives

**Rust libraries for validating digital signatures: ASN.1, X.509 certificates, CMS, RFC 3161 timestamps, long-term validation, XAdES, CAdES, PAdES and ASiC.**

[![CI and release](https://github.com/structured-world/signature-primitives/actions/workflows/release-plz.yml/badge.svg?branch=main)](https://github.com/structured-world/signature-primitives/actions/workflows/release-plz.yml)
[![Rust 1.92+](https://img.shields.io/badge/Rust-1.92%2B-93450a?logo=rust)](https://github.com/structured-world/signature-primitives/blob/main/Cargo.toml)
[![Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Checking an electronic signature takes more than one cryptographic call. You
parse the signed structure, find the signer's certificate, build and validate a
certification path, check revocation, verify timestamps, and for archived
documents prove that all of this still holds years later. These crates give you
those building blocks as plain Rust libraries: pure Rust, `no_std` friendly, and
with no hidden network, file or clock access.

They are the foundation for signature validators, document-signing services,
timestamp and archive checks, and AdES tooling. XAdES, CAdES and PAdES share
the long-term validation core.

## Which crate do I need?

| Crate | What it does | crates.io | Docs |
| --- | --- | --- | --- |
| [**structured-asn1**](crates/structured-asn1/README.md) | Fast BER/DER parsing that borrows the input instead of copying it | [![version](https://img.shields.io/crates/v/structured-asn1)](https://crates.io/crates/structured-asn1) | [![docs.rs](https://img.shields.io/docsrs/structured-asn1)](https://docs.rs/structured-asn1) |
| [**structured-pkix**](crates/structured-pkix/README.md) | X.509 certificates, certification path validation, CRL and OCSP | [![version](https://img.shields.io/crates/v/structured-pkix)](https://crates.io/crates/structured-pkix) | [![docs.rs](https://img.shields.io/docsrs/structured-pkix)](https://docs.rs/structured-pkix) |
| [**structured-cms**](crates/structured-cms/README.md) | CMS SignedData, digital envelopes, PKCS#12/PKCS#8 key containers, attribute certificates and RFC 3161 timestamp tokens | [![version](https://img.shields.io/crates/v/structured-cms)](https://crates.io/crates/structured-cms) | [![docs.rs](https://img.shields.io/docsrs/structured-cms)](https://docs.rs/structured-cms) |
| [**structured-ltv**](crates/structured-ltv/README.md) | Long-term validation shared by every AdES format: who must be validated, which revocation data is needed, timestamp times and archive coverage | [![version](https://img.shields.io/crates/v/structured-ltv)](https://crates.io/crates/structured-ltv) | [![docs.rs](https://img.shields.io/docsrs/structured-ltv)](https://docs.rs/structured-ltv) |
| [**structured-xades**](crates/structured-xades/README.md) | XAdES signatures, including baseline levels B-B, B-T, B-LT and B-LTA | [![version](https://img.shields.io/crates/v/structured-xades)](https://crates.io/crates/structured-xades) | [![docs.rs](https://img.shields.io/docsrs/structured-xades)](https://docs.rs/structured-xades) |
| [**structured-cades**](crates/structured-cades/README.md) | Source-bound CAdES baseline composition, original CMS timestamp/archive inputs and validation material | [![version](https://img.shields.io/crates/v/structured-cades)](https://crates.io/crates/structured-cades) | [![docs.rs](https://img.shields.io/docsrs/structured-cades)](https://docs.rs/structured-cades) |
| [**structured-pades**](crates/structured-pades/README.md) | Asynchronous original-range PDF signatures, revisions, DSS/VRI, DocMDP/FieldMDP and PAdES baseline composition | [![version](https://img.shields.io/crates/v/structured-pades)](https://crates.io/crates/structured-pades) | [![docs.rs](https://img.shields.io/docsrs/structured-pades)](https://docs.rs/structured-pades) |
| [**structured-asic**](crates/structured-asic/README.md) | Original-range ZIP/ZIP64 ASiC containers, producing XML/member binding, CAdES/XAdES and time-assertion composition | [![version](https://img.shields.io/crates/v/structured-asic)](https://crates.io/crates/structured-asic) | [![docs.rs](https://img.shields.io/docsrs/structured-asic)](https://docs.rs/structured-asic) |
| [**structured-dstu4145**](crates/structured-dstu4145/README.md) | Fixed-storage DSTU 4145 verification, explicit-DKE GOST 34.311 and streaming Kupyna | [![version](https://img.shields.io/crates/v/structured-dstu4145)](https://crates.io/crates/structured-dstu4145) | [![docs.rs](https://img.shields.io/docsrs/structured-dstu4145)](https://docs.rs/structured-dstu4145) |

Each crate builds on the ones above it:

```text
structured-asn1 → structured-pkix → structured-cms → structured-ltv
                                                      ├─ structured-xades
                                                      ├─ structured-cades
                                                      ├─ structured-pades (also uses structured-cades)
                                                      └─ structured-asic (also uses structured-cades and structured-xades)
```

Use only as much of the stack as you need: certificate parsing alone needs just
`structured-asn1` and `structured-pkix`.
The optional DSTU backend also builds on those two crates and implements their
digest/work contracts; it introduces no format-specific provider dispatcher.

## Install

The published crates are released together; keep them on the same version.
Registry badges link to the available versions. All nine crates require GitHub
Actions Trusted Publishing for new versions, using this repository's
`release-plz.yml` workflow and `release` environment. Coordinated publication
follows the merge of a release-plz release PR and successful CI for its exact
main commit, without stored cargo tokens. The release workflow calls the same
CI used for pull requests and waits through native job dependencies, not a
polling process. The next release PR is prepared only after publication finishes.

```toml
[dependencies]
structured-asn1 = "0.20"
structured-pkix = "0.20"   # certificates, paths, CRL, OCSP
structured-cms = "0.20"    # CMS signatures, RFC 3161 timestamps, ERS
structured-ltv = "0.20"    # long-term validation
structured-xades = "0.20"  # XAdES
structured-cades = "0.20"  # CAdES
structured-pades = "0.20"  # PDF signatures and PAdES
structured-asic = "0.20"   # ASiC containers
structured-dstu4145 = "0.20" # optional Ukrainian verification backend
```

Rust 1.92 or newer. Everything works with `no_std + alloc`; enable the `std`
feature in ordinary applications.

## Quick start

Read a DER value without copying it:

```rust
use std::sync::Arc;
use structured_asn1::{Parser, Tag, universal};
use structured_asn1::memory::{Memory, MemoryAccount};

fn main() -> Result<(), structured_asn1::Error> {
    // SEQUENCE { INTEGER 1 }
    let bytes = [0x30, 0x03, 0x02, 0x01, 0x01];
    // Upper bounds for memory and parsing work, so hostile input cannot run away.
    let memory = Memory::new(Arc::new(MemoryAccount::new(1024, 1024)));
    let parser = Parser::der(memory);

    let mut reader = parser.read(&bytes, 0)?;
    let sequence = reader.expect(Tag::constructed(universal::SEQUENCE))?;
    let mut inside = reader.enter(&sequence)?;
    let integer = inside.expect(Tag::primitive(universal::INTEGER))?;

    assert_eq!(integer.contents(), &[1]);
    Ok(())
}
```

Next steps: [parse a certificate](crates/structured-pkix/README.md#quick-start),
[validate a certificate chain](crates/structured-pkix/README.md#check-an-already-supplied-chain),
[check CRL and OCSP evidence](crates/structured-pkix/README.md#crl-delta-crl-and-ocsp-evidence),
[add long-term validation to a signature format](crates/structured-ltv/README.md).

## Why these libraries

X.509 alternative signatures are available through `structured_pkix::hybrid`
for certificates, CRLs and two-key PKCS#10 requests. They retain independent
native/alternative results and stream the exact transformed DER input to an
injected verifier, including pure ML-DSA. Explicit hybrid path validation
reuses the ordinary constraints processor and caller-selected trust anchors.

- **The signed bytes stay exact.** ASN.1 values (certificates, CRLs, OCSP, CMS,
  timestamps) borrow the original input, so their signatures are checked over
  the bytes that were actually signed, never over a re-encoding. For XAdES, the
  XML is canonicalized by the XML adapter you supply.
- **You choose the cryptography.** The format and validation crates use your
  provider (RustCrypto, a hardware module, a platform API). The optional
  `structured-dstu4145` backend supplies Ukrainian verification and streaming
  hashes; Kupyna uses RustCrypto's cores.
- **You own trust and time.** Trust anchors, validation time and fetched
  revocation data come from your application; the libraries never reach the
  network, the file system or the clock.
- **Safe on hostile input.** Parsing inside these crates runs under explicit
  memory and work limits, and running out of budget is reported separately from
  a malformed or invalid signature. Your own adapters and callbacks (an XML
  parser, a crypto provider) bound their own work.
- **Facts, not verdicts.** The crates report what holds and what does not;
  whether a signature is acceptable stays your policy decision.
- **Runs anywhere.** `no_std + alloc`, including WebAssembly and bare-metal
  targets.

## Implemented mechanisms

The coordinated `0.20.0` release provides these public mechanisms. Detailed
contracts and examples live in each crate's README and API documentation.

| Area | Available mechanisms |
| --- | --- |
| [ASN.1 and resources](crates/structured-asn1/README.md) | Borrowed BER/DER readers, original spans, scoped nested and lazy reads, fallible accounted containers, streaming digest contracts and asynchronous original-range sources |
| [PKIX](crates/structured-pkix/README.md) | Certificates and supplied/built certification paths, names and constraints, certificate policies, CRL/delta-CRL and OCSP, algorithm/key/signature profiles and separate strict/inspection outcomes |
| [Alternative signatures](https://docs.rs/structured-pkix/0.20.0/structured_pkix/hybrid/) | Certificate, CRL and two-key PKCS#10 components; exact streamed alternative signing inputs; independent native/alternative results and explicit hybrid path requirements, including pure ML-DSA profiles |
| [CMS and personal containers](crates/structured-cms/README.md) | SignedData, signed/unsigned attributes, ESS certificate binding, countersignatures, envelope recipient mechanisms, attribute certificates and credentials, PKCS#12/PKCS#8 processing and retained wiping plaintext ownership |
| [RFC 3161 timestamps](https://docs.rs/structured-cms/0.20.0/structured_cms/timestamp/) | Request/response and token inspection, original source maps, imprint and selected-TSA checks, synchronous/asynchronous execution, token accuracy and explicit caller-authenticated TSA-policy accuracy |
| [Long-term validation](crates/structured-ltv/README.md) | Complete participant and timestamp census, path/status closure, exact validation-material indexing, incorporation, proof/time intervals and archive-material coverage |
| [CAdES](crates/structured-cades/README.md) | Source-bound B-B/B-T/B-LT/B-LTA composition, original content/signature/archive inputs, historical archive forms, credential/material obligations and ERS binding |
| [Evidence records](https://docs.rs/structured-cms/0.20.0/structured_cms/evidence/) | RFC 4998 reduced hash trees, proof of existence, timestamp/hash-tree renewal, original object and validation-material binding, and CAdES evidence-record composition |
| [XAdES](crates/structured-xades/README.md) | B-B/B-T/B-LT/B-LTA composition over caller-owned XML, countersignatures and nested timestamps, authenticated references, credential/status/material checks and original archive input selection |
| [PDF and PAdES](crates/structured-pades/README.md) | Asynchronous range-based PDF reading, classic/stream/hybrid xrefs, object streams, structural filters, incremental revisions, exact ByteRange/Contents, revision-bound DSS/VRI, document timestamps, baseline composition and normative DocMDP/FieldMDP permission facts |
| [ASiC](crates/structured-asic/README.md) | ASiC-S/E, ZIP/ZIP64, bounded stored/DEFLATE member decoding with CRC, complete member/manifest census, producing XML/member identity, CAdES/XAdES/timestamp/ERS binding, archive predecessor graphs and ODF/OCF package facts |
| [Ukrainian cryptography](crates/structured-dstu4145/README.md) | Verification-only DSTU 4145, polynomial/optimal-normal-basis domains, compressed public-key validation, raw/prehashed verification, explicit-DKE streaming GOST 34.311 and streaming Kupyna 256/384/512 or explicit output widths |

XAdES timestamp pools require an explicit `TokenProfile::{Cms,Etsi}`.
`Cms` reads BER envelopes while separately preserving the XML encoding
declaration and its admission result; `Etsi` enforces declaration-driven
admission. CER canonical conformance remains explicitly unchecked in CMS mode.
Signed attributes and TSTInfo retain their independent DER requirements.

The optional DSTU `rustcrypto` feature implements
`signature::hazmat::PrehashVerifier` without a second provider dispatcher.
Resource-aware adapters use the accounted key interface, preserving original
and current work ceilings and typed failures. DSTU verification is variable-time
over public operands; signing and key generation are not provided.

These are reusable mechanisms, not a complete application or a bundled XML
security engine. Supply XML parsing, canonicalization and XMLDSig evidence
through the XML owner, and supply cryptographic providers, trusted roots,
validation time and acquisition through your application. PDF rendering,
visual change interpretation, deployment policy and reports stay external.
Inspection, format conformance, computed mathematics, historical protection
and application trust are separate results. A readable timestamp or a claimed
baseline level is not itself successful validation.

## Standards

ITU-T X.690 (BER/DER), RFC 5280 (X.509 certificates and CRLs), RFC 6960 (OCSP),
RFC 9618 (certificate policies), RFC 5652 (CMS), RFC 3161 (timestamps),
RFC 4998 (evidence records), RFC 7292/5958 (personal/key containers),
ETSI EN 319 102-1 (AdES validation), EN 319 122-1 (CAdES),
EN 319 132-1 (XAdES), EN 319 142-1 (PAdES), EN 319 162-1/-2 (ASiC),
ISO 32000-1 (PDF), DSTU 4145, GOST 34.311 and DSTU 7564.

## Contributing

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache-2.0](LICENSE).

## Support the Project

If these libraries are useful in your stack, please support continued
implementation, interoperability testing and maintenance.

![USDT TRC-20 donation QR code](assets/usdt-qr.svg)

USDT (TRC-20, TRON): `TFDsezHa1cBkoeZT5q2T49Wp66K8t2DmdA`
