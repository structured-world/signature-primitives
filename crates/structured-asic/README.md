# structured-asic

Original-range ASiC-S and ASiC-E mechanisms for ETSI EN 319 162-1 and
EN 319 162-2 V1.1.1. Format, mathematical, incorporation and historical facts
remain separate from application trust and acceptance.

## Original input and execution

Implement `structured_asn1::range::RangeSource` over immutable caller-owned
ranges. Reads may suspend and return short positive results; the parser keeps
the original document/generation/length identity and bounded scratch. A resident
slice is a convenience, not a whole-file materialization requirement.

`Session` retains cumulative original work, entry and decode allowances. Every
new operation also uses its current `Work`. All attacker-controlled traversal,
copying, decompression and allocation are admitted before work; retained actual
capacity charges follow their allocations. Snapshot changes, acquisition,
unsupported methods, syntax and resource refusal keep distinct typed causes.

`zip::Archive` preserves every central-directory occurrence, exact UTF-8 filename,
duplicate, overlap and local/header/descriptor discrepancy. Stored and raw
DEFLATE streams enforce complete extent, decoded size and CRC. ZIP64 and signed
or unsigned descriptors use the same original-source core. There is no OS
extraction, path normalization, filename case folding or implicit resource fetch.

## Inspection and composition

1. Read the full original archive and `layout::Census`. Select the explicit
   general, Part 1 baseline or Part 2 additional-container route. Layout facts
   cannot establish MIME association, authenticated coverage or a signature level.
2. Inspect complete original `mimetype` bytes with `Member::read_media`.
   `package` separately inspects source-produced ODF file declarations and OCF
   rootfiles. ODF full-path is an exact ZIP filename, not a percent-decoded URI.
   Root media equality checks the complete CRC-checked original member.
3. Supply the existing XML owner through `xml::producer::Factory`. The complete
   funded member moves into its actual parsed owner; the asynchronous visitor
   borrows that owner through completion. Only this closed scope creates retained
   manifest/package facts. An independently parsed snapshot cannot be attached.
4. Use `xml::producer::signed::SignatureFactory` for owning verified XML state.
   Its separate capability preserves all original roots, nested signatures,
   direct and signed-Manifest references, missing resources and incomplete
   catalogues. `Resources` transfers actual CRC-checked funded inputs and closed
   original-member receipts. The trusted XML owner binds those inputs to its
   actual verified reference operations. A resource receipt alone proves neither
   reference digest agreement nor signature coverage.
5. Read carried CAdES/TSP/ERS from `Content` with the same producing session.
   Detached CAdES uses one original payload pass and the existing common batch,
   requiring the full original root signer census before provider initialization.
   Actual signer/certificate/path binding and B-B/B-T/B-LT/B-LTA reports reuse
   the existing common stages. XML reports are source-bound in the producing scope.
6. Resolve every ASiC manifest instruction to its exact original members.
   Alias references share a native digest state and member pass, while every
   original declaration retains its own outcome. ERS uses the common asynchronous
   all-algorithm object pass, reduced-tree, timestamp and renewal implementation.
7. `archive::Graph` retains all original A.7 archive manifests and derives their
   order from explicit predecessor links. Each renewal preserves previous
   objects, manifests and timestamps. Exact token/input receipts and all object
   digests are independent of graph geometry, historical material, longevity and
   trust. A missing or bad latest occurrence never selects an older success.

XML parsing, namespace processing, canonicalization, XMLDSig and selected
cryptographic engines stay with their existing owners. A structural XML adapter
does not automatically implement owning asynchronous signature verification.
No backend or complete native XML adapter is bundled here. XMLERS is identified
as its distinct format; this crate does not substitute RFC 4998 for that grammar.
Unassessed schema-instance, encryption and extension data remain explicit facts.

The runtime supports `no_std + alloc` and has no hidden clock, file or network
access. Acquisition, path security policy, trusted roots, algorithm acceptance,
reports and UI belong to the caller.

## Install

The crate is available on [crates.io](https://crates.io/crates/structured-asic)
and follows the coordinated version of the shared primitives:

```toml
structured-asic = "0.15"
```

Subsequent releases use GitHub Actions Trusted Publishing through the repository's
`release-plz.yml` workflow and `release` environment.

## Verification

Public tests cover independently encoded stored/DEFLATE/ZIP64/descriptors,
short asynchronous reads, original identity, duplicates, negative census,
actual native P-256/SHA-256 CMS/TSP/ERS, cancellation and resource rollback.
Literal-only XML fixtures test owner contracts and are explicitly not a second
XML parser or native XMLDSig qualification.

With Python installed, the opt-in independent ZIP/zlib interoperability path is:

```sh
cargo nextest run --locked -p structured-asic --features interop-tests --test zip
```

Licensed under Apache-2.0.
