# structured-asn1 — borrowed ASN.1 BER/DER parsing in Rust

[![crates.io](https://img.shields.io/crates/v/structured-asn1)](https://crates.io/crates/structured-asn1)
[![downloads](https://img.shields.io/crates/d/structured-asn1)](https://crates.io/crates/structured-asn1)
[![docs.rs](https://img.shields.io/docsrs/structured-asn1)](https://docs.rs/structured-asn1)
[![CI](https://github.com/structured-world/signature-primitives/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/structured-world/signature-primitives/actions/workflows/ci.yml)
[![Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/structured-world/signature-primitives/blob/main/LICENSE)

A Rust ASN.1 reader for BER and DER that borrows encoded values and preserves
their exact byte ranges. Useful for format parsers that must verify digital
signatures over the bytes received. Nested readers share depth, element, length
and work limits; resource exhaustion is distinct from malformed input.

**`no_std + alloc` by default · Rust 1.92+ · No cryptographic backend or I/O**

## Install

These snippets target the coordinated 0.2 API family. They require that version
to be published on crates.io; check the version badge above before installing.
For the older 0.1 release, use its [versioned API guide](https://docs.rs/structured-asn1/0.1.6).

```toml
[dependencies]
structured-asn1 = "0.2"
```

Enable the optional `std` feature for a standard-library integration, or name
`alloc` explicitly for an alloc-only feature graph. See the
[API reference](https://docs.rs/structured-asn1) for parser limits and value types.

## Quick start

```rust
use std::sync::Arc;
use structured_asn1::{Parser, Tag, universal};
use structured_asn1::memory::{Memory, MemoryAccount};

fn main() -> Result<(), structured_asn1::Error> {
    // SEQUENCE { INTEGER 1 }; shared limits: storage bytes and work units.
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

The value is a view into `bytes`. Choose `Parser::ber` for BER input, or use
`Parser::new` to supply encoding and parser-local `Limits` explicitly. Borrowed
values require the document to remain alive.

## Scratch belonging to a parse

The source API adds `Reader::execution()` and the sealed `memory::Work` contract.
Use `reader.execution().vector()` (with `Work` imported) when temporary schema
processing belongs to the original parser session. Allocator growth, copies,
sorting and explicit `charge_work` then admit both the parser-local and current
aggregate work limits before execution. The borrowed scratch cannot outlive the
reader/account. Reader paths and diagnostic copies also reserve their local work
before allocation, while their containers charge aggregate work once.

`Memory::vector()` remains the independently owned result boundary. Its capacity
charge survives the parser; moving it does not reserve again. The default
`OwnedVec<T>` still uses this owner, while parser-bound scratch uses the additional
execution type parameter. These additions are not in crates.io 0.1.4.

## Explicit INTEGER recovery

`Reader::integer` and `read_integer` are strict: X.690 §8.3.2 requires minimal
sign octets already under BER. The source version adds
`Reader::integer_reading(&Element)` for schema readers that retain a uniquely
readable value together with its nonminimal-encoding fault. This addition is
not in crates.io 0.1.3.

`IntegerReading::as_bytes()` keeps the original contents; `value()` borrows a
minimal suffix for bounded numeric conversion. `fault()` retains the original
located `IntegerNotMinimal`, and `into_parts()` moves that diagnostic without
an allocating clone. Recovery never repairs the received signed bytes or claims
BER/DER conformance. Primitive implicit tags remain supported; empty and
constructed contents remain errors. The producing Reader admits padding work
through both local and current aggregate ceilings before scanning, and diagnostic
storage remains charged until drop. Resource refusal never becomes a recovered
value without its fault.

## OIDs and retained memory

OID identity uses its encoded bytes. `Oid::text(&Memory)` and
`Arc::text(&Memory)` materialize exact decimal text with fallible work and
capacity admission. Returned text retains its storage charge until released;
OID and arc values do not implement `Display`. Borrowed arc iteration leaves
its traversal admission to the caller.

The source version also adds `OwnedOid::parse(text, &Memory)` for strict
dotted-decimal identifiers with arbitrary-width arcs, and
`OwnedOid::from_oid(oid, &Memory)` for fallible retained copies. Its validated
immutable `as_oid()` view is constant-time and does not rescan the encoding.
The independent result keeps its capacity charge; these additions are not
available in the initial crates.io 0.1.0 release.

Owned vectors, maps and strings retain allocated capacity on their original
resource account. Container construction, growth and copies operate in that
declared domain. Map lookup/removal and `try_iter(&Memory)` may instead use a
current execution account; iteration prepays control buckets, including sparse
holes. Rebuilding a collection in another domain requires an explicit fallible
copy; retained allocations are never silently rebound.

`OwnedMap::try_retain(&current_work, predicate)` filters in place without copying
keys or allocating another table. It admits the sparse control scan before
calling the predicate and erase metadata before removing an entry. The first
resource or predicate error stops further callbacks; earlier removals/value
edits remain, while later entries are retained. `RetainError` preserves those
two error classes. The original allocation/account stay attached, and future
growth still uses the original execution; the predicate funds its own work.

The source uses allocator-api2 0.4.0 for vectors and hashbrown 0.17.1 for maps.
Hashbrown's published allocator interface still requires allocator-api2 0.2.21;
that interface forwards to the same account allocator. Both container families
share capacity, work, growth-peak and rollback rules. These dependency updates
are not in registry version 0.1.2.

Raw byte views and ordinary formatting/equality traits leave application-owned
traversal and output storage to the caller. An explicit budget bounds admitted
mechanism work; it does not automatically account arbitrary caller code.

## Related crate

For X.509 certificate parsing and provider-neutral path validation, use
[structured-pkix](https://crates.io/crates/structured-pkix). This crate reads
encoding structure; it does not decide certificate trust or signature validity.

## License and source

Licensed under Apache-2.0. Source, issues and contribution instructions are in
[signature-primitives](https://github.com/structured-world/signature-primitives).
