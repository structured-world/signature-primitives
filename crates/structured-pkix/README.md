# structured-pkix — X.509, PKIX paths and revocation evidence in Rust

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
ResponderID and exact ResponseData with injected `Digest` and `path::Verify`.
Digest providers resolve an algorithm to a handle and fixed output width, then
compare original input bytes with the expected digest. Incorrect widths are
rejected before hashing. Protocol-imposed SHA-1 for byKey identity is separate
from the CertID's original algorithm identifier.

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
