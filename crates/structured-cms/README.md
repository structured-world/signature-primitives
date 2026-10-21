# structured-cms

CMS SignedData and RFC 3161 timestamp mechanisms over borrowed ASN.1 ranges,
explicit resource accounts and injected cryptographic providers. Applications
supply content and own trust, policy, acquisition and reporting. The library
performs no implicit I/O and includes no cryptographic engine.

The implemented surface covers SignedData rather than encrypted CMS content
types. Use the coordinated ASN.1/PKIX/CMS API family:

The snippets below target the coordinated 0.8 API family; see the
[current registry version](https://crates.io/crates/structured-cms).

```toml
[dependencies]
structured-asn1 = "0.8"
structured-pkix = "0.8"
structured-cms = "0.8"
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
- `attribute_certificate::AttributeCertificate` reads the complete v2 structure,
  retaining Holder/Issuer alternatives, attributes, extensions and the exact
  original `acinfo` signature input. `SignedData::certificate_choice_reader_in`
  opens CMS's original `[2]` CHOICE under the current operation budget. This is
  structural inspection, not RFC5755 profile validation or authorization: the
  caller checks holder binding, algorithm agreement, signature, AA trust,
  targeting, validity, critical extensions and revocation before using attributes.
- `attribute_certificate::validation` checks the AC's static profile and all
  RFC5755 §4.3 extension values, preserving audit identity, targeting/proxying
  obligations and explicit revocation requirements. `bind_holder` uses an
  explicitly selected baseCertificateID or entityName and a supplied PKC;
  `bind_authority` checks issuer DN/UID and the AA's signature-use/non-CA rules.
  `validation::aa_path::AaPath` collects every AAControls restriction below an
  explicitly selected AA CA, checks path distance and intersects attribute
  permissions without discarding original attributes. These checks retain
  original ranges and current/source limits. They do not authenticate paths,
  verify signatures, select trust or establish authorization.
- `AttributeCertificate::authenticate` composes the static profile, supplied AA
  identity/purpose, actual effective-key binding, inclusive AC/AA validity and
  signature checks. The selected verifier implements `validation::authentication::AlgorithmAgreement`
  and the existing PKIX `path::Verify` for scoped execution. Original `acinfo`
  and `SignatureValue` reach that same verifier without re-encoding; algorithm
  syntax/mismatch, unsupported capabilities and callback/resource failures stay
  distinct. Returned facts retain profile storage, the authority, effective key
  and evaluation interval. Holder/path/direct-AA trust, target/proxy effects,
  revocation and authorization remain explicit caller obligations; AKI is a hint.
- Checked AC `Profile` implements PKIX `revocation::RevocationTarget`: use the same
  authenticated CRL scope, entry, complete/delta evaluation and reason coverage
  operations as for PKC. Facts retain the actual profile and original AC, without
  constructing a public-key certificate or copying its identity. `NoRevAvail`
  remains a distinct written scheme; status evidence does not discharge other
  profile, trust, targeting or authorization obligations.
  The same profile is an OCSP target for `CertId`/lookup and
  `ScopedResponse::evaluate_with_target`; the returned binding retains this
  actual profile, not a fabricated PKC. Original issuer DER/serial and the real
  AA key identify it. Direct AA and explicit configured-responder authority are
  supported; PKC delegation cannot confer AC authority under RFC5755 §4.5.
  Nonce, time, critical demand and `NoRevAvail` outcomes stay distinct.
- `AttributeCertificate::bind_holder_digest` checks an explicitly selected whole
  certificate or effective public key against Holder `objectDigestInfo`.
  `validation::digest::ObjectDigestProvider` uses the existing incremental digest
  contract plus a required algorithm-specific key-encoding gate. Key hashing
  includes effective inherited parameters; certificate hashing includes its
  signature. Unsupported capabilities, malformed assertions, mismatches and
  processing/provider failures remain distinct. A bound receipt retains the
  original AC and selected object; it proves neither key possession nor trust.
- `attribute_certificate::clearance` reads current and historical Clearance
  encodings, preserving default classification, policy-specific bits and opaque
  security categories. Both registered OIDs are supported without assigning
  clearance levels or permissions. `attribute_certificate::controls::AaControls`
  reads the PKC extension and checks its attribute restrictions and supplied
  path distance; trust-anchor selection and complete path validation stay with
  the caller. `attribute_certificate::proxy::ProxyInfo` checks the authenticated
  sender, recipient and supplied complete forwarding path against one common
  proxy set, with unknown group membership and processing errors kept distinct.
- `attribute_certificate::target` reads RFC5755 TargetInformation and checks
  recipient names or caller-supplied group membership. Multiple Targets groups
  form one union; noncritical extensions and forbidden targetCert alternatives
  cannot produce a match. Original ranges and current/source work admission are
  preserved. Unknown membership or opaque name semantics remain unproven; this
  predicate does not authenticate the AC or authorize attribute use.
- `attribute_certificate::ietf::IetfAttrSyntax` decodes group and chargingIdentity
  assertions with their original policyAuthority and homogeneous borrowed octet,
  OID or UTF-8 values. Registered-attribute reads enforce outer singleton
  cardinality; an empty inner sequence stays empty. Short current queries retain
  original source/depth and independently owned metadata accounting. Decoding
  does not establish membership, authority trust or charging permission.
- `attribute_certificate::role::RoleSyntax` decodes the original role URI and
  optional roleAuthority names. Registered `id-at-role` reads check every value
  and preserve multiple assertions in source order, with DER and source/current
  resource admission. Authority trust, role allocation and permissions remain
  application decisions; decoding never dereferences the URI.
- `attribute_certificate::service::SvceAuthInfo` decodes service/holder names
  and optional borrowed authentication bytes. Registered authenticationInfo and
  accessIdentity reads preserve every original value; accessIdentity rejects
  authInfo even when empty. Source/current resource admission and DER apply,
  while authentication and authorization remain with the application. Debug
  formatting shows source ranges only, without credential contents.
- `timestamp::Request` reads original TimeStampReq. `timestamp::Token` separates
  readable inspection from complete signature, ESS, TSA, imprint, request and
  time checking. The caller supplies UTC information and request windows.
- `archive` reads the CAdES `ats-hash-index-v3` of an `archive-time-stamp-v3`
  (ETSI EN 319 122-1 §5.5). `check_index` matches every index entry against the
  root SignedData certificate and revocation choices and the signer's unsigned
  attribute values, hashed over their original encodings; an entry without its
  element invalidates the index, an element without an entry is reported as
  unprotected. `imprint_input` yields the §5.5.3 ranges the token's imprint is
  checked over, and `same_algorithm` the required index/imprint agreement.
- `cades::profile_faults` reports where a SignerInfo uses the freedom of the
  generic CMS and ESS schemas against the CAdES profile (EN 319 122-1
  §§5.2-5.5): an attribute in the wrong set, a single-valued attribute with
  another value count, a repeated ESS content attribute (RFC 2634 §1.3.4),
  content-hints or mime-type inside a countersignature, an `ats-hash-index-v3`
  outside an archive time-stamp token's signer,
  ESS `policies` and an implied signature policy. Level requirements and
  verdicts stay with the application.

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

The repository's `scripts/qualify-cades-corpus.py` checks SHA256-pinned public
DSS CAdES fixtures with an independent DER walker: a conforming archive
time-stamp whose imprint is recomputed, indexes naming a certificate or
revocation the signature does not hold, and a TS 101 733 index that is not read
as v3. The `archive` results must agree with it entry by entry. Upstream
payloads and their licence notice remain outside packages in `target/`.

The runtime supports `no_std + alloc`; `std` is optional. Cryptographic test
adapters are development-only oracles, not qualified production providers or
proof of their internal resource accounting.
