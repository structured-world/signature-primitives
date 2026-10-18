# structured-cms

CMS SignedData and RFC 3161 timestamp mechanisms over borrowed ASN.1 ranges,
explicit resource accounts and injected cryptographic providers. Applications
supply content and own trust, policy, acquisition and reporting. The library
performs no implicit I/O and includes no cryptographic engine.

The implemented surface covers SignedData rather than encrypted CMS content
types. Use the coordinated ASN.1/PKIX/CMS API family:

The registry snippets below target the first coordinated 0.2 release and resolve
only after that version is published. A source checkout alone does not establish
registry availability; see the [current registry version](https://crates.io/crates/structured-cms).

```toml
[dependencies]
structured-asn1 = "0.2"
structured-pkix = "0.2"
structured-cms = "0.2"
```

- `ContentInfo` and `SignedData` preserve original BER encodings, signer
  identifiers, certificate/revocation choices and signed attributes.
  `SignerInfo::digest_algorithm()` and `signature_algorithm()` return PKIX
  `AlgorithmReading` views: original fields and uniquely bounded malformed
  parameters remain inspectable with located faults. Only `identifier()` yields
  validated provider input. `prepare::resolve` checks both readings before any
  provider callback; inspection recovery never grants cryptographic acceptance.
  Present-empty signed or unsigned attribute sets likewise remain inspectable
  with `EmptyAttributes` faults and original ranges. `Attributes::read` remains
  strict; `read_inspection` exposes this uniquely bounded schema violation.
  Binding and preparation reject it before provider callbacks or payload work.
  Registered CMS singleton repeats and forbidden signed/unsigned placements
  retain diagnostics even without a selected certificate. For inspection,
  `Attributes::singleton_inspection_in` selects the first byte-identical instance
  and reports its repeat count under the current producing reader; conflicts
  refuse. `DuplicateAttribute` names instance repetition, while
  `AttributeCardinality` names value cardinality, including in ESS. Strict
  binding never becomes a conforming operation through this recovery.
  `SignerInfo::element()` preserves original container-local provenance.
- `prepare`, `verify` and `provider` support explicit raw-message and prehashed
  verification, full algorithm identities and a shared payload pass. Digests run
  through the provider's `structured_asn1::digest::Digest` implementation, and
  written digest identifiers resolve through `structured_pkix::algorithm::digest`
  under the encoding of the message they came from. Provider and input failures
  remain distinct from invalid or unsupported signatures.
- `ess` checks independent signing-certificate attributes; `counter` walks
  countersignatures using original parent signature content.
- `timestamp::Request` reads original TimeStampReq. `timestamp::Token` separates
  readable inspection from complete signature, ESS, TSA, imprint, request and
  time checking. The caller supplies UTC information and request windows.

Borrowed views keep original document ranges. Independently retained results use
accounted storage that remains charged until its capacity is freed. Fallible
copies reserve additional storage; moving a result does not copy it. Producing
reader operations enforce both local and aggregate work ceilings. Lazy queries
preserve original provenance and fund work through the current operation.

Constructed content can have several physical ranges. `SourceMap` retains that
mapping independently of temporary joins. Nested timestamp checking preserves
separate CMS-envelope and TSTInfo coordinate contexts. A foreign-reader refusal
occurs before map admission; it is caller misuse, not malformed document data.
Timestamp inspection preserves a uniquely readable TSTInfo followed by trailing
carried bytes, with a located `TrailingData` fault and the original source map.
Fault retention is fallible and uses the producing execution's resource limits.

`timestamp::Evidence` records successful common checks, not a trust decision.
Applications must validate the TSA certification path and status, enforce signed
ESS path restrictions and apply their algorithm/security policy. Malformed
inspection faults do not produce evidence. Content discovery, replay history,
networking, clocks and product timelines remain outside this crate.

The runtime supports `no_std + alloc`; `std` is optional. Cryptographic test
adapters are development-only oracles, not qualified production providers or
proof of their internal resource accounting.
