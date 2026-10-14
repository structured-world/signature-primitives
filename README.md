# Signature primitives — Rust ASN.1 and X.509 libraries

[![CI](https://github.com/structured-world/signature-primitives/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/structured-world/signature-primitives/actions/workflows/ci.yml)
[![Rust 1.92+](https://img.shields.io/badge/Rust-1.92%2B-93450a?logo=rust)](https://github.com/structured-world/signature-primitives/blob/main/Cargo.toml)
[![Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Read ASN.1 BER/DER and X.509 certificates in Rust while preserving the original
signed bytes. Build certification paths using your own cryptographic provider,
trust inputs and resource budgets. Both libraries support **`no_std + alloc`**.

Since version 0.1.1, PKIX also checks an already supplied leaf-first certificate chain
through `structured_pkix::path::validate`, returning typed static facts or
located rejections; see the [supplied-chain contract](crates/structured-pkix/README.md#check-an-already-supplied-chain).

PKIX also provides caller-supplied CRL, delta-CRL and OCSP evidence
processing, with exact signature provenance and explicit issuer, request and
time facts, published since version 0.1.3; see the
[revocation contract](crates/structured-pkix/README.md#crl-delta-crl-and-ocsp-evidence).

## Choose a crate

| Crate | Use it for | crates.io | API docs |
| --- | --- | --- | --- |
| [**structured-asn1**](crates/structured-asn1/README.md) | Borrowed BER/DER parsing, OIDs, exact byte ranges and shared memory/work budgets | [![version](https://img.shields.io/crates/v/structured-asn1)](https://crates.io/crates/structured-asn1) [![downloads](https://img.shields.io/crates/d/structured-asn1)](https://crates.io/crates/structured-asn1) | [![docs.rs](https://img.shields.io/docsrs/structured-asn1)](https://docs.rs/structured-asn1) |
| [**structured-pkix**](crates/structured-pkix/README.md) | Borrowed X.509 certificates, names, extensions, UTC time and provider-neutral path validation | [![version](https://img.shields.io/crates/v/structured-pkix)](https://crates.io/crates/structured-pkix) [![downloads](https://img.shields.io/crates/d/structured-pkix)](https://crates.io/crates/structured-pkix) | [![docs.rs](https://img.shields.io/docsrs/structured-pkix)](https://docs.rs/structured-pkix) |

Downloads are cumulative per crate. The two crates share a coordinated release
version and can be used separately. CMS, timestamp and XML advanced-signature
mechanisms will be listed when their standalone contracts and integrations are
verified.

The current source adds [structured-cms](crates/structured-cms/README.md):
provider-neutral CMS SignedData, ESS certificate binding and RFC 3161 request
and timestamp checks with original signed bytes and retained source mappings.
This new package is not yet published; it is not available through the registry
installation examples below. Its runtime contains no cryptographic engine.

## Install

For ASN.1 parsing:

```toml
[dependencies]
structured-asn1 = "0.1"
```

For certificate processing, add PKIX as well:

```toml
[dependencies]
structured-asn1 = "0.1"
structured-pkix = "0.1"
```

Rust **1.92 or newer** is required. Default features use `no_std + alloc`;
enable `std` when integrating into a standard-library application. The `alloc`
feature is also available explicitly. Neither library performs network or
filesystem I/O.

## Quick start: read DER without copying the value

```rust
use std::sync::Arc;
use structured_asn1::{Parser, Tag, universal};
use structured_asn1::memory::{Memory, MemoryAccount};

fn main() -> Result<(), structured_asn1::Error> {
    // SEQUENCE { INTEGER 1 }; limits are bytes of storage and work units.
    let bytes = [0x30, 0x03, 0x02, 0x01, 0x01];
    let memory = Memory::new(Arc::new(MemoryAccount::new(1024, 1024)));
    let parser = Parser::der(memory);
    let mut reader = parser.read(&bytes, 0)?;
    let sequence = reader.expect(Tag::constructed(universal::SEQUENCE))?;
    let mut inside = reader.enter(&sequence)?;
    let integer = inside.expect(Tag::primitive(universal::INTEGER))?;

    assert_eq!(integer.contents(), &[1]);
    assert_eq!(integer.span().start, 2);
    assert_eq!(integer.span().length, 3);
    Ok(())
}
```

Continue with the [ASN.1 guide](crates/structured-asn1/README.md) or the
[certificate parsing example](crates/structured-pkix/README.md#quick-start).

## Why use these libraries?

- **Keep the signed bytes.** Values borrow the input; certificate signature
  verification receives the original encoded TBS bytes rather than a re-encoding.
- **Bound shared processing.** An explicit `Memory` account admits allocation
  capacity and input-dependent work. Owned results retain their storage charge
  until deallocation; nested parsing keeps cumulative session limits.
- **Distinguish failure from a verdict.** Resource exhaustion remains separate
  from malformed input, missing fields and semantic mismatches.
- **Choose your provider and trust model.** Applications supply cryptographic
  verification, trust anchors, validation time and externally acquired data.

Parsing a certificate does not establish trust. Applications remain responsible
for their acceptance policy and for accounting work inside injected callbacks.
Raw slices and ordinary Rust formatting/equality traits also leave caller-owned
traversal and output storage to the application. See the package guides for the
resource and time contracts.

## Releases

`structured-asn1` and `structured-pkix` use one release-plz version group.
Release-plz prepares a version/changelog PR using the organization release bot;
merging that PR publishes the packages after CI succeeds on its exact main commit.
Dependencies are published before their dependants. Git tags and release notes
retain each package's name, even though both packages share their version.

Registry publishing uses OIDC, bound to this repository, `release-plz.yml` and
the `release` environment. No long-lived crates.io token is stored in GitHub.
The workflow's manual run verifies token exchange without uploading
a new version. First-time publication of a new package still requires an owner
to bootstrap it and register its trusted publisher on crates.io.

## Dependency updates

All seven CI checks and CLA are required for `main`. Trusted default-branch
automation merges repository-local Dependabot PRs after mandatory CI and a
fresh positive review, with no unresolved threads or active changes requested.
Codex's positive verdict must strictly follow the current head's recorded push;
a collaborator approval must identify that exact commit and the reviewer must
currently have write or admin access. Missing review evidence
keeps the PR waiting. The merge operation also binds the inspected SHA.

`hashbrown` and `allocator-api2` changes require manual contract review, including
grouped updates and manifest/lockfile changes. Their audited capacity/layout
contracts cannot be qualified by CI alone. Other updates are checked on PR/CI
and review events, with an hourly backstop for verdict reactions that emit no Actions event.
The merge App token is scoped to this repository and created only when a
qualified update is ready; the automation never executes PR code with it.

## Development

Run `cargo nextest run --workspace`, `cargo test --workspace --doc`, and
`cargo clippy --workspace --all-targets -- -D warnings`.
Check alloc-only builds using `cargo check --workspace --no-default-features`
and the `wasm32-unknown-unknown` and `thumbv7em-none-eabihf` targets.
Verify distributable archives with `bash scripts/check-packages.sh`; it uses
fresh temporary package state so earlier same-version workspace archives cannot
substitute stale source during verification.
Release-trigger regressions use GitHub's expression evaluator: run
`npm ci --prefix .github/tests --ignore-scripts` followed by
`npm run check --prefix .github/tests`. CI runs the same checks before a main
commit can approve publication, including manual/fork refusals and preservation
of separate main-push validation runs.

## License

Apache-2.0. Contributions are accepted under the
[Structured World Contributor License Agreement](https://sw.foundation/cla);
see [CONTRIBUTING.md](CONTRIBUTING.md).
