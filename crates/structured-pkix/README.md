# structured-pkix: X.509, PKIX paths and revocation evidence in Rust

[![crates.io](https://img.shields.io/crates/v/structured-pkix)](https://crates.io/crates/structured-pkix)
[![downloads](https://img.shields.io/crates/d/structured-pkix)](https://crates.io/crates/structured-pkix)
[![docs.rs](https://img.shields.io/docsrs/structured-pkix)](https://docs.rs/structured-pkix)
[![CI](https://github.com/structured-world/signature-primitives/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/structured-world/signature-primitives/actions/workflows/ci.yml)
[![Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/structured-world/signature-primitives/blob/main/LICENSE)

Parse X.509 certificates and check or build certification paths while borrowing
the original DER input. Read names, extensions and validity times, and retain
the exact bytes covered by each certificate signature. Signature verification
is supplied through `path::Verify`, so applications choose their crypto provider.

**`no_std + alloc` by default · Rust 1.92+ · No issuer fetching or implicit I/O**

## Install

These snippets target the coordinated 0.8 API family. Earlier releases keep
their versioned guides on [docs.rs](https://docs.rs/crate/structured-pkix/latest).

```toml
[dependencies]
structured-asn1 = "0.8"
structured-pkix = "0.8"
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

### Signature algorithm structure

`algorithm::signature::with_algorithm(identifier, &work, visitor)` recognizes SHA-family RSA
PKCS#1 v1.5, DSA SHA-1/224/256, ECDSA, pure Ed25519/Ed448, ML-DSA and RSASSA-PSS from
an original identifier. It visits a typed family and implied digest or borrowed
PSS fields; it does not authorize an algorithm or select a cryptographic backend.
The visitor receives `None` for unknown OIDs, including legacy OIW aliases, additional DSA profiles,
MD2/MD5 and other PQ profiles. Wrong parameters are located errors; resource refusal is terminal.
RSA SHA-224/256/384/512 accepts NULL or absence on reception. Other recognized
RSA PKCS#1 identifiers require NULL; DSA/ECDSA/EdDSA require absence. PSS signature
parameters are required and reuse the same strict kernel described below.
Original source/current ceilings apply without parameter copying or reparsing.
PSS descriptors are borrowed only during the visit, avoiding a large fixed-case
result or heap wrapper. The visitor may return original-source views or its own
owned result/error, but cannot retain a reference to the temporary descriptor.

### ML-DSA public structure

`algorithm::ml_dsa::resolve(identifier, &work)` recognizes the three pure
RFC 9881 parameter sets. `key::ml_dsa::read(spki, &work)` requires absent
parameters and exact raw public-key widths, returning original borrowed octets
and their source offset. `SignatureValue::ml_dsa_in(set, &work)` checks whole-octet
signature framing for an explicitly selected set. Both source and current
operation limits apply, including negative outcomes; none of these queries
allocates, copies payloads, creates a parser or decodes packed coefficients.

The signature visitor reports `Algorithm::MlDsa(set)`. This identifies pure
ML-DSA, with empty context for PKIX certificates/CRLs; HashML-DSA and Dilithium
are different schemes and remain unrecognized here. Framing does not establish
key/signature binding, mathematical validity, key usage, provider support or
policy permission. Those checks remain with the selected verifier.

### RSA-PSS parameters

Decoded `algorithm::pss::Parameters::profile(&work)` resolves independent message
and MGF1 digests through the shared digest core, preserving original salt/trailer
fields and source limits without a second PSS read. Unknown digests, mask functions
and non-BC trailers are unsupported; invalid known digest parameters and negative
trailers are located errors. A recognized profile does not promise provider support.
`key_profile.allows(&signature_profile, &work)` compares present restrictions using
the RFC4055 minimum-salt rule with arbitrary-width integers. `pss::profile::key_allows`
also handles original RSA key identifiers and absent PSS restrictions. It requires
the selected key's identifier, not an issuer's or a signature identifier. No inherited
restriction, modulus bound, backend conversion, cryptographic operation or policy
decision is introduced. Inspection faults remain faults after profile projection.

RSA-PSS parameter decoding is available through `algorithm::pss::read` and
`inspect` for a retained `AlgorithmIdentifier` and current `Work`. Verification
callbacks need no former reader, replacement parser, parameter copy or encoded
default. The `read_in` and `inspect_in` variants additionally check a supplied
producing reader's session. All entry points share one PSS schema kernel,
preserving source ranges, explicit/default fields, independent message/MGF hashes,
and arbitrary-width salt/trailer INTEGERs. Inspection retains DER spelling faults;
it does not establish algorithm support or signature validity. Applications apply
the distinct signature-parameter and public-key-restriction rules and select the
cryptographic provider.

Retained reads preserve the original parser's cumulative ceiling and actual
parameter depth plus the current root-operation ceiling. Inspection diagnostics
retain their current storage account after the temporary operation ends.
Absent PSS key parameters remain unrestricted PSS usage and do not inherit
restrictions; absent signature parameters must be rejected by the caller.

### RSA and EC public-key structure

`key::rsa::read(key, &execution)` reads the RFC 8017 `RSAPublicKey` carried by
an `rsaEncryption` or `id-RSASSA-PSS` key. It returns the borrowed modulus and
exponent magnitudes without their sign octet, their document offsets and the
exact modulus bit length. `key::ec::read(working_key, &execution)` reads an
`id-ecPublicKey` key: the RFC 5480 `ECParameters` choice in force, including
parameters inherited from an authority along the path and read where that
authority wrote them, and the SEC1 point split into its coordinates.
`implicitCurve` and `specifiedCurve` are reported, not refused; the point at
infinity and the hybrid form are refused.

Both readers decode the original bytes in their parser session under the
current execution. Key bytes and returned components remain borrowed; generic
nested-reader metadata uses existing accounted scratch. They establish structure
only: key-size and exponent policy, curve support and width, and whether a
point lies on its curve remain with the provider that verifies.

`PublicKeyInfo::execution_in(&work)` supplies a deferred key operation with its
original source ceiling and the current operation's funding, without opening a
reader or creating an account. Use it before direct raw-key scans; typed key
readers already preserve their source contexts.

Deferred RSA/DSA/EC identity checks preserve the key source's cumulative work
ceiling as well as current funding, including unknown-algorithm fast paths.
EC point framing also belongs to the key source when its curve is inherited
from another certificate. The inherited parameter source retains its separate
ceiling and coordinates. A source refusal remains a located resource error,
never a completed mismatch, malformed point, or successfully decoded key.

### Effective SubjectPublicKeyInfo digest input

`key::effective::EffectiveSpki::read(working_key, &work)` prepares a borrowed DER
stream containing the effective parameters, including those inherited from an
issuer. `visit(&work, visitor)` emits original OID, parameter and key payloads
with small stack-resident DER headers. It does not allocate a combined SPKI,
parse synthesized bytes or clone a resource account. Every part retains source
and current-operation ceilings; callback failures retain the part and its real
enclosing source context. Synthesized framing has no claimed physical range.

This supplies RFC5755 §7.3 digest input, not algorithm-specific key acceptance.
The selected provider must validate the original key and effective parameters
under its algorithm profile before hashing. A valid DER frame cannot repair
invalid RSA/DSA/EC parameters or establish mathematical validity or key possession.

### DSA public-key structure

`key::dsa::read(working_key, &execution)` reads the unsigned `p`, `q`, `g`
and `y` components without bigint conversion or copying. Each component
retains its original INTEGER element and sign octet; `as_bytes()` exposes
its unsigned magnitude. Domain parameters retain their original source and
record whether they were inherited. Missing parameters remain `None`; a
written NULL is refused rather than repaired through generic inheritance.

The carried `y` INTEGER must be DER even in a BER source. Parameter fields
follow the original reader's encoding. Current execution and source budgets
fund all deferred decoding and temporary reader metadata. Zero is inspectable;
group validity, component ranges, strength and signature acceptance remain
with the selected backend. The views retain no allocated storage.

### Ed25519, Ed448, X25519 and X448 key structure

`key::rfc8410::read(key_info, &execution)` returns the exact algorithm, borrowed
raw public-key octets and their source offset. It enforces absent parameters
(NULL is forbidden), whole-octet BIT STRING framing and widths of 32/57/32/56
octets respectively. Raw keys are not nested ASN.1 and are neither re-parsed nor
rewritten. Deferred checks preserve original and current execution ceilings;
the query and returned view allocate no storage.

The result establishes framing only. Edwards point validation, Montgomery
decoding and contributory checks, signature modes, provider choice and the
certificate role/keyUsage rules of RFC 9295 remain separate. Equal key widths
do not make X25519 and Ed25519 interchangeable. No inherited parameter is used
to repair a key that writes parameters.

### DSA and ECDSA signature-value structure

Certificates, CRLs and basic OCSP responses expose `signature_value()` alongside
their raw `signature()` BIT STRING. `path::Verify::verify` receives this borrowed
`signature::SignatureValue`, preserving the original payload range, source
parser, encoding and depth. Raw algorithms use `octets()` without opening a
cursor. After permission and capability checks, a selected DSA/ECDSA provider
uses `signature.reader_in(execution)` with `DssValue::read`; current operation
and original cumulative work/depth limits apply without a new parser or payload
copy. Processing/resource errors remain errors, separately from signature
mismatch and unsupported capability. XMLDSig's fixed-width `r || s` encoding
continues to belong to its XML adapter.

`signature::DssValue::read(&mut reader, "signatureValue")` reads a complete
`SEQUENCE { r INTEGER, s INTEGER }` window; `read_element` reads one embedded
value while leaving surrounding siblings to their schema. Both require DER
even under a BER parent and reuse the existing reader/INTEGER kernel, original
depth, current execution and resource ceilings. The returned integer views,
component spans and whole encoded value borrow the received bytes unchanged.
Only temporary reader/path metadata uses storage; no payload copy is made.

This is structure inspection, not signature acceptance. Zero, negative and
arbitrary-width integers stay readable; the selected provider checks the full
scalar range against its group order and performs the signature arithmetic.
XMLDSig fixed-width framing and low-S policy remain with the caller. Carried CMS
signatures can use the existing `Octets::with_nested_reader`/`SourceMap` boundary
to interpret segmented bytes without losing physical provenance.

### Scoped execution for retained inputs

Supplied-path validation accepts `ValidationContext<..., E>` with
`E: structured_asn1::memory::Work`. Implement `Verify<E>` and `Recognizer<E>`
for that same execution type and pass the current reader's `execution()`.
The default type remains `Memory`; an implementation of `Verify<Memory>` alone
does not implement verification under a reader-local ceiling. Path construction
with `Context` continues to use its documented `Memory` execution contract.

Name queries, lazy extension readers and CRL/OCSP operations also accept `Work`.
When retained certificate data is read during another operation, the shared
reader bridge preserves original source offsets, encoding and depth, checks the
original source ceilings, and charges the current root operation. Storage stays
on its original account until its allocation is freed; a new query does not
inherit credit from an earlier parse. Callback implementations must use the
provided execution before their own data-dependent work and allocations.

`ScopedReader<'source, 'operation>` separates input views from the current
decoding budget. Parsed OIDs, names, extension values and static path facts
can retain their original source lifetime after a temporary operation ends;
the reader cursor and scoped scratch cannot escape that operation. The existing
`Reader<'a>` name denotes the equal-lifetime case. `Extension::reader_scoped`
and the shared lazy decoders use this same parser kernel, without copying or
reparsing input, cloning a budget owner, or weakening source/query admission.

`ScopedResponse::evaluate_with_target` uses the same OCSP evaluation as
`evaluate`, while retaining the original target and evaluation label. Its
`TargetReading::evidence()` returns a target-bound result only when evaluation
produced evidence. `ScopedResponse::issuing_key()` retains the actual issuing
key and inherited parameters for issuer/delegate authentication; configured
responder trust returns `None` because that branch does not authenticate an
issuer key. These facts do not replace caller trust, freshness or revocation
policy. CRL absence and coverage evidence likewise expose their original target
and evaluation label.

## GeneralName identity

The source API adds `GeneralName::matches(other, &Memory)` for retained queries
and `general_name::matches(&Reader, left, right, offset, field)` for producing
parses. Both share DNS, SMTP mailbox, Directory Name and URI comparison rules.
DNS compares the whole name without ASCII case; mailbox local parts preserve
case and decode equivalent SMTP quoting, while hosts ignore ASCII case.
Directory strings use the existing Name preparation; URI comparison uses shared
syntax and recognized-scheme normalization. Original values are never rewritten.

The producing variant retains cumulative local and aggregate work limits through
Unicode preparation, sorting, deferred BER traversal and scratch allocations.
Its error preserves the supplied source location. Retained queries return an
unlocated `ErrorCode` because a borrowed GeneralName has no universal source span.
Resource refusal is never a mismatch. Decode untrusted values successfully before
comparison; duplicate reporting and malformed recovery belong to the caller.

Other, X.400 and EDI values support encoded identity only, rather than their
type-specific semantic rules. IP addresses/masks compare exactly, without subnet
containment. Exact CRL distribution-point/issuer comparisons remain exact; semantic
CRL queries reuse the GeneralName core. These additions are not in crates.io 0.1.4.

### Check an already supplied chain

The source version adds `path::validate` and `ValidationContext`; these APIs are
not available in the initial crates.io 0.1.0 release. Pass a borrowed leaf-first
chain and one explicit `Anchor`, excluding the anchor's certificate from the
chain. Validation checks exactly those certificates; `path::build` additionally
searches candidate issuers. Both entry points use the same static processing core.

`Validation::Accepted` returns the target's effective `WorkingKey`, the number
of non-self-issued intermediate CAs, and the accepted authority/user policy OIDs.
Inherited key parameters refer to the original anchor or certificate bytes.
The shared transition preserves the algorithm-specific PSS absence rule:
an id-RSASSA-PSS key with omitted parameters is unrestricted and does not
inherit its parent's PSS restrictions (RFC 4055 §3.3). This source correction
is not in registry version 0.1.2. Providers still validate the original SPKI
syntax under the selected key algorithm.
The policy container owns its allocation and retains its capacity charge after
validation returns; the contained OIDs still borrow the original input.
`into_policies()` transfers that storage without copying or reserving it again.

`Validation::Rejected` reports a completed semantic failure and its leaf-first
certificate position. Name-constraint and path-length failures also identify
the constraining certificate or anchor; path-length errors retain the original
limit. Malformed relevant extensions retain their decoder code, field and offset.
Provider `No` and `Unsupported` are separate reasons. Resource and callback
failures remain errors; local work, depth, policy-graph or deadline limits yield
`Incomplete`, without accepted facts.

Certificate-policy processing follows RFC 9618 with shared graph nodes and
multiple parent edges rather than duplicated path histories. The local policy
bound counts retained nodes, parent edges and expected OIDs; the shared memory
account separately admits actual capacity and processing work. Mapping output
preserves authority-side policy identifiers.

Accepted static facts do not settle revocation, application purpose, algorithm
permissions, key strength or trust-anchor selection. Applications supply these
decisions and account their injected providers. The API example is included in
the source documentation for `path::validate`.

## Policy qualifier validation

The source version also exposes `policy::qualifier_understood(&reader, kind,
&value)` for CPS and UserNotice DER payloads. It shares certificate-policy
validation, retaining the producing reader's current execution account, local
work/depth ceilings and document offsets, including inside BER envelopes.
`false` means unknown or malformed selected syntax; a resource refusal is an
error. Callers decide independently whether an unknown qualifier is allowed.
It does not fetch CPS URIs or select application policy. The initial crates.io
0.1.0 release does not include this API.

## Distinguished-name selectors

The source version adds `name::Selector`, `Name::rfc4514` and
`Name::rfc4514_readable`; these APIs are not in the initial crates.io 0.1.0
release. `Selector::parse(text, &memory)` accepts strict RFC 4514 syntax and
owns its accounted storage. `matches_name(&name, &execution)` compares directly
with a borrowed certificate Name; `matches(&other, &execution)` compares two
selectors using the same identity rules. RDN sequence order matters; attribute
order within an RDN does not. Escapes decode once, without implicit whitespace
trimming or a whole-Name encode/reparse bridge.
Pseudonym follows its case-exact equality rule: normalization and insignificant
space handling still apply, while `Alice` and `alice` remain different.

`rfc4514` uses registered descriptors or exact numeric OIDs and complete
original `#BER` values for reversibility. The readable formatter emits full
text for registered standard descriptors with RFC 4514
escaping and retains BER for unknown/nontext values. It never calls the bounded
display helpers. Readable output is metadata, not a canonical identity string;
the ASN.1 string tag may change when interpreting that text.
Malformed string payloads retained by Name also round-trip through `#BER`;
that preservation does not make them valid textual assertions.

Unknown numeric attribute types are preserved. A textual assertion requiring
unavailable equality semantics returns `UnsupportedNameSyntax`, separately from
malformed syntax, a completed mismatch or resource refusal. Numeric OIDs have
arbitrary-width arcs. Constructed/indefinite BER values retain their original
encoding; string segments are interpreted through the common iterative walker.
ASCII singleton comparisons need no projection allocation; Unicode preparation
and multivalued sorting use accounted execution scratch. Owned selectors and
formatted strings keep their capacity charge independently of the input/parser.

## CRL, delta CRL and OCSP evidence

The source version adds `crl` and `ocsp`; these modules are not in crates.io
0.1.2. They process caller-supplied DER without fetching, a clock, implicit trust
discovery, or a built-in cryptographic backend. The original signed ranges,
certificate identities and evidence sources remain borrowed throughout.

For CRLs, read `CertificateList`, authenticate its exact TBS with the actual
issuer certificate and effective `WorkingKey`, then call `evaluate` for the
target and caller-supplied UTC facts. Authentication alone establishes neither
applicability nor freshness. Evaluation keeps distribution-point/category/reason
scope, complete-list entry processing, unsupported critical demands, conflicts
and update-window facts separate. Indirect entries carry their certificate
issuer state. URI distribution points use scheme-aware identity rules.

`bind_delta` checks the original authenticated sources, effective signing keys,
authority identifiers, issuing-distribution-point scope and arbitrary-width
CRL numbers. A bound pair evaluates entries delta-first; `removeFromCRL` does
not fall back to the base. A current delta may update a stale base, but future,
invalid or uncertain base times cannot establish absence. An unpaired delta
never establishes standalone absence.

Only usable, conflict-free absence or delta removal can create `AbsenceEvidence`.
`Coverage` unions its reason masks while retaining exact contributing sources.
It rejects different targets, evaluation moments and execution accounts. This
growing collection belongs to one request; its owned capacity remains charged
until drop. Complete reason coverage is still not a whole-certificate trust
verdict. The caller supplies authenticated issuer paths and their trust-anchor
provenance. Cached CRLs permit the exact `nextUpdate` boundary; newly obtained
replacements require a strictly later expiry. Missing expiry remains explicit.

For OCSP, read the response envelope and move successful `ResponseBytes` into
`into_basic(&execution)`. Deferred parsing keeps the original reader's offsets,
depth and cumulative work ceiling. Unsigned error responses remain distinct
from a signed BasicResponse. `authenticate_signature` checks the actual signer,
ResponderID and exact ResponseData with an injected `algorithm::digest::AsnDigest`
provider and `path::Verify`. The CertID's written hash identifier resolves
through the shared ASN.1 digest resolver; the SHA-1 that RFC 6960 §4.2.1 imposes
for byKey identity needs no written identifier. Incorrect widths are rejected
before hashing, and an identifier with parameters its hash does not take is
reported apart from an unsupported one.

## Digest identifiers

`algorithm::digest::algorithm(&identifier, &execution)` names the standard
digest an `AlgorithmIdentifier` writes (SHA-1, SHA-2 and SHA3-224/256/384/512).
SHA-1 and SHA-2 accept absent or primitive NULL parameters, with NULL validated
under the document's encoding, so a BER long-form NULL is still NULL.
SHA3 requires absent parameters, including in BER, as specified by
[RFC 9688 §2](https://www.rfc-editor.org/rfc/rfc9688.html#section-2). Any other
parameter of a known identifier is `Malformed`; an identifier the table does not
know is `Unsupported`; a spent ceiling is an error. `resolve` then asks the
provider's `AsnDigest::identity` for its own identity, and execution runs through
the shared `structured_asn1::digest::Digest` contract. OCSP and CMS use this one
resolver. Retained identifiers keep their original parser's cumulative work
ceiling alongside the current operation ceiling and account. A new funded
account cannot reset the source limit, and a resource refusal occurs before
the provider's identity callback. Same-session resolution charges work once;
the source bridge creates no parser, cursor, allocation or parameter copy.

Bind a signed response to its issuer using `bind_issuer`, or to completed direct
delegation facts using `check_delegate` and `bind_delegate`. Direct delegation
uses the common supplied-path processor and requires explicit OCSP signing
purpose and permitted key usage. It checks current validity even with noCheck;
without noCheck the responder's revocation remains unresolved. The local issuer
anchor does not resume constraints from the caller's original root path.
`trust_for_issuer` is a separate, explicit assertion of caller-configured
responder trust, never a choice made from response content.

`ScopedResponse::evaluate` retains the selected target assertion, unique or
ambiguous identity, intended-signer binding, nonce binding, critical-extension
support and update window. `Good` is the responder's assertion, not automatic
acceptance. Unknown hashes, missing assertions, duplicate identities, unsupported
critical extensions, provider errors and resource refusals remain distinct.
Unimplemented optional noncritical extensions remain opaque.
New requester nonces require 32–128 bytes; `RequestNonce::from_sent` also represents
actual legacy 1–128 byte wire requests without treating an invalid size as absent.

Retention after expiry is read, not assumed. `SingleResponse::archive_cutoff`
(RFC 6960 §4.4.4) and `TbsCertList::expired_certs_on_crl` (X.509
`expiredCertsOnCRL`) return the stated time, so `notAfter >= cutoff` decides
whether a `good` answer or a CRL's silence still covers an expired certificate;
`Evidence::archive_cutoff` carries the assertion's value. Under the extended
revoked definition (`BasicResponse::extended_revoke`, §4.4.8), the exact §2.2
answer for a certificate that was never issued (`certificateHold` dated
1970-01-01T00:00:00Z) reads as `Status::NotIssued` through
`BasicResponse::status_of` (which names the assertion by its position in that
response) and `Evidence::status`; any other hold stays a hold. A malformed
value, a critical extended revoke or `expiredCertsOnCRL`, or an extended revoke
inside an assertion is a located fault.

Both retention accessors return `temporal::Reading`, including canonical DER
fractional seconds and any subnanosecond remainder. `start()` is a floor, not
the exact cutoff when `has_subnanosecond_remainder()` is true: an expiry equal
to that floor is then before the cutoff and is not covered. Certificate validity
dates keep their separate RFC 5280 profile without fractional seconds.

Both CRL entry and OCSP revocation dates expose UTC-qualified `time::Relation`
facts (`Before`, `At`, `After`, `Uncertain`) against a lossless `Reading`.
Applications decide historical-status policy, source age when no expiry exists,
replay/request history, delegated responder revocation and final acceptance.
They also bound the internals of injected providers. Resource errors retain
original document offsets and are never converted to absence or a positive
status. Tests exercise actual P-256 signatures and SHA-1 identities through an
independent test provider; that provider is not shipped as a runtime backend.

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

The source version also accepts lossless validation endpoints through
`Interval::at_instant` and `Interval::between_instants`, preserving leap labels
and nanoseconds. Existing integer-second constructors remain available;
`from_instant`/`to_instant` expose complete labels, while `from`/`to` are POSIX
whole-second projections.

## Deferred decoding and resource accounting

Algorithm parsing remains strict through `algorithm::read` and `read_implicit`.
For diagnostic inspection, `read_inspection` and `read_implicit_inspection`
return an `AlgorithmReading` with original OID, parameter bytes/range and a
located parameter-syntax fault. A malformed reading cannot expose a validated
identifier: require `identifier()` to return `Some` before handing it to a
cryptographic provider. Provider/profile acceptance is a further check.
Constructed NULL is malformed under X.690 §8.8; retaining it is inspection,
not acceptance of another BER spelling.

`AlgorithmReading::same_written_in` funds comparisons through the producing
reader. Malformed parameters keep opaque encoded identity; two validated
primitive NULL values can ignore BER length spelling. No algorithm defaults
are inferred. Resource/processing refusals and ambiguous schema remain errors,
never recovered document faults or successful mismatches.

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
