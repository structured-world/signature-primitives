# structured-cms

## Personal key containers

`personal::Pfx` reads PKCS#12 v3 over the same borrowed BER/DER readers as CMS.
`personal::process` first asks the selected `Backend` to authenticate the entire
original safe, then processes all plaintext, password-encrypted and public-key
enveloped members. It visits all six standard bag alternatives, unknown open
bags and nested SafeContents in source order. Public-key integrity uses the
existing original `SignedData` model; no new signature or cipher engine is added.

The module also reads PKCS#8/RFC 5958 keys and shrouded keys, PBES1/PBES2,
PBKDF2, PBMAC1 and legacy PKCS#12 protection parameters. Wide iteration/key-length
integers and written/default provenance remain explicit. RFC 9879's PBMAC1
key-length requirement and ignored outer legacy fields are handled before
provider work. `legacy_password` provides the paid BMP conversion only where
that legacy layer calls for it; PBMAC1/PBES2 use UTF-8 instead.

The backend owns password acquisition, supported algorithms, KDF/cipher costs,
key selection and trust. A missing MAC needs its explicit acceptance and never
becomes proof of authentication merely by parsing. Every returned `Plaintext`
retains its actual capacity charge and wipes initialized bytes before release;
scoped models cannot borrow a temporary plaintext buffer after the callback.
After a successful `Backend::key` inspection, `Backend::retain_key` receives
the original unpadded wiping buffer by value. A backend can retain that allocation
beyond `process` without copying or duplicating its capacity charge; one that
does not retain it drops it explicitly. Unencrypted KeyBag values stay borrowed.
Carried fragment maps and decrypted coordinate boundaries remain separate in
callback sources and retained errors. A refusal yields no completed import;
callers stage their own visitor side effects until completion.

CMS SignedData, digital-envelope and RFC 3161 timestamp mechanisms over borrowed ASN.1 ranges,
explicit resource accounts and injected cryptographic providers. Applications
supply content and own trust, policy, acquisition and reporting. The library
performs no implicit I/O and includes no cryptographic engine.

Use the coordinated ASN.1/PKIX/CMS API family. The encrypted-attribute APIs
described below are new workspace source; registry availability follows release.

The snippets below target the coordinated 0.8 API family; see the
[current registry version](https://crates.io/crates/structured-cms).

```toml
[dependencies]
structured-asn1 = "0.8"
structured-pkix = "0.8"
structured-cms = "0.8"
```

- `enveloped::EnvelopedData` reads the entire RFC5652 digital-envelope schema:
  key transport, key agreement, pre-distributed KEK, password and open recipient
  formats, original originator material and unprotected attributes. Version
  rules are checked before return; BER ciphertext and key fragments retain
  original ranges. Detached and attached-empty ciphertext remain distinct.
  Original algorithm parameter readers and `reader_in` retain source encoding,
  depth and current/original budgets. Open recipient values, sender bits and
  optional key metadata expose the same source-bound `EncodedValue::reader_in`.
  An envelope does not authenticate its
  originator or select a key, algorithm policy or cryptographic engine.
- `attribute_certificate::encrypted::Encrypted::read` preflights every original
  RFC5755 encAttrs ContentInfo before decryption. `decrypt_all` requires the
  actual AC's `usage::Checked` receipt and invokes the explicitly selected
  provider with original envelope metadata/current execution. Decrypted output
  uses that same accounted domain; unsupported, not-recipient, rejected and
  processing failures remain distinct. No engine fallback or key acquisition
  occurs. `ClearAttrs::read` enforces DER independently of the outer encoding.
  The core binds the full serial and semantic issuer DN before exposing a
  `Bound` plaintext to its scoped visitor, then records the existing AA-control
  result for every attribute. Duplicate types across plaintext/encrypted sets
  remain separate, without an implicit merge or authorization grant. Temporary
  plaintext cannot escape the callback; explicitly retained outputs own their
  charges. Errors distinguish original encrypted-source coordinates from
  zero-based plaintext coordinates; encryption supplies no invertible offset map.
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
- `timestamp::Response` reads a complete DER RFC3161 `TimeStampResp`: all six
  statuses, original UTF-8 status strings, every defined failure bit and the
  mandatory status/token association. Unknown values and malformed named-bit
  encodings refuse. `token_reader_in` preserves the actual nested token range,
  depth and current/source ceilings, without a replacement parser.
  `Response::check` and `check_with_profile` require an actual parsed request in
  `CheckContext::requested` and reuse the complete timestamp kernel for CMS,
  ESS, certificate purpose/name, imprint/nonce/policy/certReq, covered content
  and supplied timeliness facts. Read the returned timestamp's `evidence()`;
  an `Ok` result and granted status alone do not mean acceptance. Status text
  and failure flags are unauthenticated. Negative statuses invoke no provider,
  profile, extension recognizer or content source. Trust, transport, polling,
  replay history, clocks and application acceptance remain caller-owned.
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
- `validation::aa_path::validate` validates a complete caller-supplied AA path
  through an explicitly trusted AA CA. It combines the existing PKIX processor
  with the complete `AAControls` census and critical-extension handling, retaining
  policy results, the actual authority key and the evaluation interval. The
  terminal AA CA must be the separately selected trusted object; it is the local
  trust anchor, outside the prospective PKIX path;
  a one-certificate direct-AA trust input is deliberately a separate operation.
  `validate_with_key` also preserves effective inherited anchor parameters.
  `ValidatedPath::authenticate` uses that authority key and interval for the AC,
  without repeating path signatures. `Issued::allows` intersects every control
  for cleartext and caller-decrypted attribute types, preserving the excluding
  certificate and source. Exclusion means ignore that attribute for authorization,
  not discard other permitted attributes. Holder proof, target/proxy effects,
  revocation, decryption and application authorization remain caller obligations.
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
- `attribute_certificate::validation::usage` composes authenticated issuance
  with explicit direct-AA trust or an authenticated constrained AA path,
  a checked holder PKC path or original object-digest receipt, targeting,
  complete proxy-set checks and original CRL/OCSP evidence. `HolderPath::validate`
  reuses the PKIX core; `direct` and `issued` do not repeat path/AC signatures
  or status identity hashes. The returned `Checked` retains every original
  input and a complete accounted catalogue of per-attribute AA-control results.
  Written controls apply on the directly trusted route too. Excluded attributes
  remain inspectable, while unrelated permitted types stay usable.
  Status is bound to the same original AC and exact evaluation label; missing
  evidence, incomplete reason coverage, adverse/unknown OCSP status, unsuitable
  update windows and nonce failures do not produce a checked result.
  `NoStatus` completes only an authenticated `NoRevAvail` profile. An OCSP
  response without `nextUpdate` retains an explicit unqualified window rather
  than acquiring a default expiry. The caller supplies protocol authentication,
  proof of possession, trust and revocation of PKC/status authorities, UTC facts
  and additional recency/recipient policy. Decryption and application permission
  are separate; `Checked::allows` applies the same controls to decrypted types
  without claiming their `ACClearAttrs` issuer/serial binding was checked.
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
- `evidence` reads original RFC 4998 records, flat timestamp chains and reduced
  hash trees. The verifier checks exact object/group membership, the declared
  digest union, both timestamp and hash-tree renewals and actual chronology.
  One selected provider streams each object once across needed digest requests.
  History validates every TSA at the following proof and algorithm suitability
  through the next chain, with an explicit current reference for the final TSA.
  Unprotected CryptoInfos and encryption metadata never supply those facts.
  Hash-tree renewal follows §5.2's numbered step 4: unsorted
  `H(dataHash || priorSequenceHash)`. Figure 4 conflicts; reported erratum 7411
  is not an accepted correction and no alternative-success fallback exists.
  The prior input is the DER encoding of ALL preceding chains, including its
  outer sequence. A metadata projection preserves borrowed payloads, uses the
  shared string/BIT STRING and PSS field kernels, and canonicalizes known schema
  sets/defaults. An open value needing an unavailable canonical codec yields
  `UnsupportedEncoding`, distinct from malformed input or resource refusal.
  Unknown timestamp formats remain inspectable but cannot yield evidence.
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
`timestamp::CheckContext::policy_accuracy` accepts explicit caller-authenticated
accuracy bound to the selected TSA and signed policy OID (RFC 3161 §2.4.2).
Policy mismatch refuses before profile, cryptographic and content callbacks.
Token accuracy takes precedence; malformed accuracy is never replaced, and no
accuracy is inferred when neither source provides it. `RetainedFacts::accuracy`
preserves the signed field's absence; `effective_accuracy` reports the value and
its `Token` or `CallerPolicy` origin through retention and independent copying.
Both synchronous and asynchronous checks use this same resolution.
Initialize `policy_accuracy` to `None` in timestamp/ERS selection contexts when
no authenticated external accuracy is available; existing behavior is preserved.

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
