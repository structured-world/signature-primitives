# Signature primitives

**Rust libraries for validating digital signatures: ASN.1, X.509 certificates, CMS, RFC 3161 timestamps, long-term validation, XAdES, CAdES and PAdES.**

[![CI](https://github.com/structured-world/signature-primitives/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/structured-world/signature-primitives/actions/workflows/ci.yml)
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
| [**structured-pades**](crates/structured-pades/README.md) | Asynchronous original-range PDF signatures, revisions, DSS/VRI, DocMDP/FieldMDP and PAdES baseline composition | Initial publication pending | Source documentation |

Each crate builds on the ones above it:

```text
structured-asn1 → structured-pkix → structured-cms → structured-ltv
                                                      ├─ structured-xades
                                                      ├─ structured-cades
                                                      └─ structured-pades (also uses structured-cades)
```

Use only as much of the stack as you need: certificate parsing alone needs just
`structured-asn1` and `structured-pkix`.

## Install

The published crates are released together; keep them on the same version.
`structured-cades` is enabled for its initial CI publication and joins that
coordinated release. Check its registry badge for an actually released version;
its first-publication/OIDC procedure is documented in the crate README.

```toml
[dependencies]
structured-asn1 = "0.8"
structured-pkix = "0.8"   # certificates, paths, CRL, OCSP
structured-cms = "0.8"    # CMS signatures, RFC 3161 timestamps
structured-ltv = "0.8"    # long-term validation
structured-xades = "0.8"  # XAdES
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

- **The signed bytes stay exact.** ASN.1 values (certificates, CRLs, OCSP, CMS,
  timestamps) borrow the original input, so their signatures are checked over
  the bytes that were actually signed, never over a re-encoding. For XAdES, the
  XML is canonicalized by the XML adapter you supply.
- **You choose the cryptography.** No crypto engine is bundled. You plug in the
  provider you already trust (RustCrypto, a hardware module, a platform API).
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

## Standards

ITU-T X.690 (BER/DER), RFC 5280 (X.509 certificates and CRLs), RFC 6960 (OCSP),
RFC 9618 (certificate policies), RFC 5652 (CMS), RFC 3161 (timestamps),
ETSI EN 319 102-1 (AdES validation) and ETSI EN 319 132-1 (XAdES baseline).

## Contributing

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache-2.0](LICENSE).
