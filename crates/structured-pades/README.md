# structured-pades

Original-source PDF signature reading and provider-neutral PAdES baseline
composition for ETSI EN 319 142-1 V1.2.1 and ISO 32000-1:2008.

## Source and execution

Implement `range::RangeSource` over immutable, caller-identified original ranges.
Its asynchronous `read_at` may suspend without materializing the whole document;
`range::Slice` provides a resident-input convenience. `Document::read` retains
the snapshot, cross-reference history and funded structural index. Physical file
locations and logical decoded-stream locations remain distinct throughout.

Classic, stream and hybrid cross references, object streams, incremental updates
and linearized files use the same resolver. Structural stream decoding includes
Flate, LZW, ASCIIHex, ASCII85, RunLength, TIFF and PNG predictors. Unsupported
filters, external stream acquisition and encrypted input report typed capability
errors. This is a signature mechanism, with no renderer or document writer.

All document-derived storage and work use the shared fallible execution contract.
Retained allocation charges follow their owners; each new query also admits work
against its current operation and original source. Caller limits only tighten
the absolute depth ceiling. Source failures, changed snapshots, resource refusal,
ambiguous syntax and unsupported capabilities are distinct outcomes.

## Validation flow

1. Obtain the complete signature catalogue and inspect original `Contents`,
   ordered `ByteRange`, object identity and whole-revision coverage.
2. Read its original CMS container and prepare the CAdES and PAdES requirements.
   Verify mathematics with the selected common provider, bind the actual signer
   certificate and checked path, and form `basic::Basic`.
3. Inspect every signature, document and VRI timestamp occurrence, including bad
   or unreadable slots. Check exact original inputs and actual TSA identities.
   The baseline timestamp/material composition preserves all participant and
   credential obligations, rather than selecting only successful occurrences.
4. Parse revision-qualified DSS/VRI material and use `material::ParsedHistory`
   with the common PKIX/status/material index. Nominal SHA-1 VRI names associate
   source objects; they do not establish authentication or trust.
5. Compose B-B, B-T, B-LT and B-LTA through `baseline`. Archive assessment can
   name an original DTS ordinal explicitly or assess the last written occurrence
   as current. A bad last occurrence never falls back to a successful earlier
   one. Later material cannot repair an earlier protected input.

`permissions` separately assesses original DocMDP/FieldMDP permissions against
complete structural changes, including form filling, annotations and named
template instantiation. Unknown change semantics produce an indeterminate result,
never positive permission. Rendering and visual risk interpretation remain external.

Format conformance, mathematical evidence, incorporation, historical protection,
algorithm longevity and application trust are independent facts. In particular,
an available timestamp or claimed VRI generation time is not proof of historical
trust. Where the selected standard does not define a VRI timestamp hash input,
inspection retains the occurrence without inventing a successful imprint check.

The runtime is pure Rust and supports `no_std + alloc`. It injects existing
CMS/PKIX/LTV operations rather than implementing a cryptographic backend.
Application trust sources, deployment policy, reports, network/file acquisition
and UI remain caller-owned.

## Install

The crate is available on [crates.io](https://crates.io/crates/structured-pades)
and follows the coordinated version of the shared primitives:

```toml
structured-pades = "0.15"
```

Subsequent releases use GitHub Actions Trusted Publishing through the repository's
`release-plz.yml` workflow and `release` environment.

## Verification

The public native tests build real P-256 CMS signatures, RFC 3161 tokens,
certification paths and CRLs, then exercise all baseline levels, credentials,
multiple approval signatures and multiple document timestamps. Hostile-input
cases exercise source changes, suspension, cancellation, source/current budget
boundaries, malformed histories and partial-allocation rollback.

With `qpdf` and OpenSSL installed, run the independent interoperability checks:

```sh
cargo nextest run --locked -p structured-pades --features interop-tests --test native
```

The tools must accept the generated incremental PDF, detached CMS and timestamp
inputs and reject mutated signed input. They are opt-in test oracles, not runtime
dependencies. Their outputs live under Cargo's target directory.

Licensed under Apache-2.0.
