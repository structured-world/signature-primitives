# structured-xades

Provider-neutral `XAdES` mechanisms with explicit memory and work accounting.
The crate supports `no_std + alloc` and performs no implicit I/O.

An XML adapter supplies the original document, stable node identities,
authenticated reference instructions and transformed byte streams. Cryptographic
providers supply digest and signature operations: digests through the shared
`structured_asn1::digest::Digest` contract, with `certificate::DigestProvider`
adding only XML `DigestMethod` resolution and classification. Application code supplies
trust inputs and decides whether the resulting evidence meets its policy.

## Processing the original signature

1. `prepare::prepare` binds the selected signature to its complete protected
   `SignedProperties` and inventories its original properties and references.
2. `prepare::check_fields` checks declared attributes, URI/OID fields, optional
   validation-reference scalar/binary syntax and the claimed signing time before
   certificate or provider effects. Unsigned certificate references remain a
   distinct model and cannot substitute for protected signing-certificate binding.
   `validation` separately compares original whole-artifact digests, RFC 4514
   issuer/responder names and exact identifier time labels, and reads DER
   issuer/serial and OCSP byKey hints through the shared PKIX/CMS kernels.
   `validation::compare_reference_catalogues` visits every prepared reference
   and every compatible parsed XML material source, including certificates
   embedded in OCSP. It retains all comparison outcomes and original source
   ordinals while sharing finished hashes for identical artifacts and complete
   resolved algorithm identities. Responder-key matching uses the same OCSP
   identity kernel as response authentication; it does not repeat signatures.
   `compare_reference_catalogues_with_tokens` includes the separate original
   timestamp pool, including carried CRLs, whole OCSP envelopes and embedded
   certificates. Pool identities remain explicit and identical copies reuse one
   finished digest. `reference_presence` checks conditional incorporation against
   the complete original token/counter census; unavailable methods and
   identifier-only references remain unproven rather than becoming missing values.
   External parsed certificates, CRLs and whole OCSP responses can be compared
   through `compare_reference_target` without manufacturing XML copies.
   `check_root_certificate_references` covers the actual root CA/anchor path and
   excludes its signing certificate with the same digest memo. Its result does
   not assert the separate credential/TSA role rules.
   `check_certificate_reference_roles` checks ordinary references against the
   complete actual credential CA census, preserving shared TSA/signature uses
   and indeterminate older-certificate CA facts. It reuses the same lazy CA and
   digest kernels; it does not establish attribute-reference completeness.
   `check_credential_certificate_references` derives the required credential
   signer, ancestor and existing-anchor set from actual participant paths.
   Original protected and ordinary references can satisfy that set; redundant
   attribute copies remain a separate advisory finding. All sources share one
   certificate/provider memo, and absent optional properties need no catalogue.
   `check_revocation_reference_roles` applies the corresponding rule to actual
   status targets. It associates known basic OCSP bodies with their original
   whole XML/carried envelopes; missing envelopes remain unproven, with no
   payload substitution. It also retains every actual signer-path status
   contributor, including both lists of a delta source, and reports whether
   written ordinary references cover that required set. All comparisons reuse
   one exact-artifact/provider memo. Credential paths retain every non-anchor
   complete/delta or OCSP contributor too: ordinary and attribute references
   provide the A.1.4 alternatives, with redundant attribute copies reported as
   advisory. Attribute rows do not satisfy the signer's ordinary-reference set.
   Missing original whole OCSP envelopes remain unproven in either role.
   Shared status uses retain all participant
   purposes; source presence alone does not validate identifier hints or grade.
   `check_crl_reference` and `check_ocsp_reference` compose original
   issuer/responder and issue/production
   time facts; OCSP uses its authenticated signer and preflights mandatory time
   syntax before provider effects. `check_ocsp_envelope_reference` also binds
   that authenticated body to the exact whole response whose digest is checked;
   an identifier from another signed response cannot satisfy that relation.
   Its receipt retains the original property/row, whole envelope and signed
   response/signer. `identifies_response` requires both identifier fields and
   the digest when written. A legitimate identifier-only reference remains
   distinguishable through `digest()`; it does not protect the whole contents
   against substitution or establish status or trust.
   `check_crl_value_reference` likewise binds optional issuer/time fields and
   the mandatory whole-list digest to one actual parsed CRL. Its receipt retains
   the original property, row and list; independently successful facts from two
   lists cannot be combined. Missing optional identifiers remain valid when the
   digest identifies the list, while unreadable time prevents provider dispatch.
   None of these facts alone establishes a grade.
3. `certificate`, `counter`, `hashes`, `credential`, `timestamp` and `pki`
   establish their respective source-bound facts. Format-neutral path, status,
   participant, timestamp-interval and material facts live in `structured-ltv`;
   `XAdES` receipts implement its traits, and `xml::Access` is its source query. The participant census
   (`pki::participants`, derived from these receipts only) includes plain
   countersignatures and timestamps nested in countersignatures.
   The timestamp census also retains the optional Annex A signature/reference
   and reference-only timestamps; their implicit inputs preserve original
   preceding-property order rather than reusing archive coverage.
4. `baseline::basic` joins the checked fields, exact signing certificate,
   effective key, counter paths and actual hash uses. Every written protected,
   ordinary and attribute certificate-reference issuer hint uses the same DER
   reader. Located readable encoding faults prevent a positive basic predicate; original
   catalogue ordinals remain available through `HintSource`. A hint never replaces
   certificate digest binding. As specified in §5.2.2 Note 2, optional
   `IssuerSerialV2` contents are retrieval hints: their agreement is not an
   additional binding requirement. The hint reports describe DER syntax,
   rather than asserting that their issuer/serial matches a selected certificate.
5. `structured_ltv::baseline::timestamped` requires the complete token census
   and records each root signature timestamp's static time association.
6. `material::check_participants` and `material::credentials::check` examine
   the complete participant/status closure. `structured_ltv::baseline::long_term`
   joins those original reports with the preceding receipts.
7. For each archive, derive the preceding-participant closure and original
   element coverage. `structured_ltv::baseline::archive_material` joins the
   X.509 and credential material reports for that archive;
   `structured_ltv::baseline::archives` requires every root archive once, in
   original order. `renewed::check_prepared` separately processes
   every written root renewal's original Manifest instructions and digest pairs,
   retaining failed comparisons alongside successful ones.
8. `baseline::assess` takes the stage reports of exactly the level that the
   preparation requested: `Evidence::basic` for B-B, `Evidence::timestamped`
   for B-T, `Evidence::LongTerm` for B-LT, and `Evidence::Archival` (the
   `long_term` and `archives` reports) for B-LTA. It refuses a different
   level, or an archive census built from another preparation or another
   authenticated credential census than the whole signature. The result states
   whether every condition of that level holds, including the earlier levels.

Receipts keep detailed negative findings. A material-presence predicate does
not establish usable revocation status, historical trust, timestamp chronology
or algorithm longevity. The requested structural B-B/B-T/B-LT/B-LTA requirements
remain distinct from verified evidence and application acceptance. Extra
containers do not promote a result to a higher level.

## Current-operation accounting

Every query receives its current `Work`, including queries over previously
retained document data. For example, base-datatype validation delegates to the
XML owner's original scalar kernel:

```rust
use structured_asn1::memory::Work;
use structured_xades::{
    reference::LexicalSource,
    scalar::{self, Datatype, ScalarResult, ScalarXml},
    xml::Access,
};

fn check_original_uri<X: ScalarXml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
) -> ScalarResult<X> {
    scalar::check(access, node, LexicalSource::SimpleContent, Datatype::AnyUri)
}
```

Allocation capacity remains charged for its lifetime. New traversal,
normalization, copying and provider work require admission before execution;
retained facts provide no credit for later work. Scoped normalized values cannot
escape their visitor. Source/generation changes, resource failures and callback
errors remain processing failures, separate from malformed, unsupported,
missing or mismatching evidence.

## Adapter boundary

An adapter must preserve original signature selection, reference identity,
namespace interpretation, canonicalization choices and transformed bytes.
`QName` syntax, original namespace resolution and scalar normalization belong to
the XML owner. `QNameXml` retains the original lexical reading and separates an
unbound prefix from malformed text and processing refusal. The attribute kernel
accepts an explicit type equal to the actual pinned declaration, including
contextual Cert/CertifiedRole/RecomputedDigestValue declarations. Overriding
types needing other derivation/content validation remain explicitly unassessed;
a resolved name alone never certifies them. Schema hints do not trigger fetches.
The generic core
contains no second XML parser, canonicalizer, URI resolver or crypto backend.
Synthetic XML fixtures exercise the generic contracts; actual XML adapter and
interoperability qualification are separate requirements.

The repository's `scripts/qualify-xades-corpus.py` checks SHA256-pinned public
DSS fixtures (B-B, B-LT and B-LTA, negative and signature-wrapping cases, and a
document with two signatures) using test-only xmlsec1/OpenSSL and libxml2 C14N
through lxml. It compares the common signature/archive input streams
byte-for-byte with independently canonicalized/transformed inputs and their
signed token imprints, verifies XML/CMS and OCSP mathematics, including isolated
signature and data mutations, and checks each negative fixture's stated defect.
Upstream payloads and their licence notice remain outside packages in `target/`.
These external tools are test oracles; the Rust runtime gains no FFI dependency.
Historical trust, revocation acceptance and the bounded native XML adapter
remain separate checks.
