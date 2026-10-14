# structured-cms

CMS SignedData and RFC 3161 timestamp mechanisms over borrowed ASN.1 ranges,
explicit resource accounts and injected cryptographic providers. Applications
supply content and own trust, policy, acquisition and reporting. The library
performs no implicit I/O and includes no cryptographic engine.

This package is under development and has not been published. Its implemented
surface covers SignedData rather than encrypted CMS content types.

- `ContentInfo` and `SignedData` preserve original BER encodings, signer
  identifiers, certificate/revocation choices and signed attributes.
- `prepare`, `verify` and `provider` support explicit raw-message and prehashed
  verification, full algorithm identities and a shared payload pass. Provider
  and input failures remain distinct from invalid or unsupported signatures.
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

`timestamp::Evidence` records successful common checks, not a trust decision.
Applications must validate the TSA certification path and status, enforce signed
ESS path restrictions and apply their algorithm/security policy. Malformed
inspection faults do not produce evidence. Content discovery, replay history,
networking, clocks and product timelines remain outside this crate.

The runtime supports `no_std + alloc`; `std` is optional. Cryptographic test
adapters are development-only oracles, not qualified production providers or
proof of their internal resource accounting.
