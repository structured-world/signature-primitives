# structured-pkix — X.509 certificates and PKIX paths in Rust

[![crates.io](https://img.shields.io/crates/v/structured-pkix)](https://crates.io/crates/structured-pkix)
[![downloads](https://img.shields.io/crates/d/structured-pkix)](https://crates.io/crates/structured-pkix)
[![docs.rs](https://img.shields.io/docsrs/structured-pkix)](https://docs.rs/structured-pkix)
[![CI](https://github.com/structured-world/signature-primitives/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/structured-world/signature-primitives/actions/workflows/ci.yml)
[![Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/structured-world/signature-primitives/blob/main/LICENSE)

Parse X.509 certificates and build certification paths in Rust while borrowing
the original DER input. Read names, extensions and validity times, and retain
the exact bytes covered by each certificate signature. Signature verification
is supplied through `path::Verify`, so applications choose their crypto provider.

**`no_std + alloc` by default · Rust 1.92+ · No issuer fetching or implicit I/O**

## Install

```toml
[dependencies]
structured-asn1 = "0.1"
structured-pkix = "0.1"
```

`structured-asn1` supplies the parser and shared resource account used below.
Both crates share a coordinated version. Optional `std` and explicit `alloc`
features are available; the default build already uses `no_std + alloc`.

## Quick start

This function reads a complete DER certificate supplied by your application.
The storage budget below is 1 MiB and the work budget is one million units;
choose limits appropriate for your workload.

```rust
use std::sync::Arc;
use structured_asn1::Parser;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_pkix::Certificate;

fn inspect_certificate(der: &[u8]) -> Result<(), structured_pkix::Error> {
    let memory = Memory::new(Arc::new(MemoryAccount::new(
        1024 * 1024,
        1_000_000,
    )));
    let parser = Parser::der(memory);
    let certificate = Certificate::read(&parser, der, 0)?;

    assert_eq!(certificate.as_bytes(), der);
    let original_tbs = certificate.signed_bytes();
    assert!(!original_tbs.is_empty());
    // Give original_tbs, the signature and issuer key to your crypto provider.
    Ok(())
}
```

Keep the parser and input alive while using the borrowed certificate. For a
certificate embedded in a larger ASN.1 structure, use `Certificate::read_element`
with its parent reader to preserve the envelope's shared limits and offsets.

## Parsing and path validation

Parsing exposes certificate facts; it does not establish application trust.
For certification-path processing, supply the certificates, trust anchors,
validation interval, resource limits and a `path::Verify` implementation.
See the [path API](https://docs.rs/structured-pkix/latest/structured_pkix/path/)
and [certificate API](https://docs.rs/structured-pkix/latest/structured_pkix/struct.Certificate.html).

Applications own trust decisions, external data acquisition and the accounting
of work inside their injected verification and recognizer callbacks. Merely
passing an execution account does not bound arbitrary external callback code.

## UTC time and leap seconds

UTC arithmetic uses `temporal::LeapTable`, a borrowed application-supplied table
with explicit coverage. The library neither embeds leap-second announcements
nor obtains them from a clock or network. Inserted seconds remain distinct from
their neighbours; deleted seconds and results outside known coverage produce
typed uncertainty. Applications own the authenticity and freshness of these
facts. Parsing preserves subnanosecond precision so rounding through a leap
boundary uses the same table as elapsed-time arithmetic.

Certificate `Time::instant()` preserves the UTC label; `Time::seconds()` is
only its POSIX projection and maps an inserted second to the preceding
ordinary second's label. Use the lossless label for comparisons. Strict DER
GeneralizedTime accepts inserted-second labels; UTCTime retains its separate
00–59 seconds grammar. An accepted label does not authenticate its occurrence.

## Deferred decoding and resource accounting

`general_name::read` reads names carried by other schemas using the parent
reader. Extension values, policy qualifiers and qualified-statement decoders
retain the document's parsing budget, depth and original offsets.
Their accessors take the current execution `Memory` explicitly: a new request
pays for deferred scans, scratch and returned storage. Previously retained
storage keeps its original account. Parser session ceilings remain cumulative
across these requests; selecting a new execution domain does not reset them.

Extension lookup and typed decoders return `Result<Option<…>>`: absence is
distinct from malformed content and resource refusal. Qualified-statement
lookup and policy/key-purpose membership also take the current `Memory` and
can fail. `InfoAccess::locations_for` yields borrowed `Result` items; after
one resource error it ends permanently. Raw slices and ordinary iteration
borrow stored values without copying; callers account their own traversal.

`Extensions::criticals(&Memory)` admits every visited metadata entry, including
noncritical entries, and yields `Result` items with the same single-error
termination. `AlgorithmIdentifier::matches(other, &Memory)` admits deferred OID
and parameter comparisons; a resource refusal stays distinct from a mismatch.
DER ordering and GeneralizedTime decoding take the producing `Reader`, preserving
both its original cumulative ceiling and its current execution account.
Mailbox validation uses allocation-free ASCII SMTP syntax without normalizing
the borrowed spelling.

## License and source

Published on [crates.io](https://crates.io/crates/structured-pkix) as part of
[signature-primitives](https://github.com/structured-world/signature-primitives).
Licensed under Apache-2.0; third-party data notices remain with their source data.
