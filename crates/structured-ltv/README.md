# structured-ltv

Format-neutral long-term validation facts for `AdES` signatures, with explicit
memory and work accounting. The crate supports `no_std + alloc` and performs no
implicit I/O.

EN 319 102-1 defines path validation at a time, revocation material bound to
path members, timestamp generation intervals and archive coverage of validation
material once for every `AdES` format. This crate implements those facts over
the `structured-pkix` and `structured-cms` processors. A format layer
(`structured-xades` today) states only where material and timestamps were
written; no XML or PDF type crosses this boundary, and no fact is a trust
verdict.

## Source identity

`source::Source` is implemented by a document owner over its own stable node
identities: XML elements, CMS attributes or PDF objects. `source::Query` is one
current operation over an expected snapshot of that source; `source::Scope`
implements it for any `Source`, and a format's own access guard can implement
it so that its checks and these share one admission path. A generation change
is a processing failure, never a malformed-property finding. Every check runs
under the query that performs it; retained facts are never prepaid work.

## Facts

- `validation::validate` implements the basic and with-time indication process
  of ETSI EN 319 102-1 V1.4.1 clauses 5.3.4 and 5.5.4 over caller-established
  format, cryptographic, path, revocation, anchor-recognition and time facts.
  `Requirements` supplies the already selected cryptographic constraints,
  mandatory signature elements and timestamp delay. The named
  `ETSI_TS_119_312_V2_1_1` catalogue is optional data, never an implicit policy.
  Evaluation allocates nothing and admits its bounded traversal through caller
  `Work`. It returns the standard indication, located fact index, unmet
  constraint and independent integrity/time/revocation/trust/change axes.
  Tables 5 to 7 include retry conditions and `CUSTOM` diagnostics.
  Individual `SignatureTimestamp` results and path-specific
  `RevocationRetry` facts retain required-token failures, freshness and
  suspension bounds, and any evidence-supplied retry time. Use
  `validate_with_findings` to visit all unmet cryptographic constraints for
  the deciding material group under the caller's work budget.
  Policy selection, policy identity in reports and trusted-list processing
  belong to the caller.
  `Chain::DirectTrust` is the explicit route for an active trust anchor that
  is itself the signer. A sunset anchor can fall through to an ordinary path.
  `Signer::expiry_evidence` records the separate support needed for a finding
  of non-revocation after expiry.
- `pki::status::assess` evaluates supplied CRLs and OCSP responses for an
  original member of a checked path. It authenticates source signatures with
  caller-supplied capabilities, binds the original issuer or responder,
  validates compatible base/delta pairs, and joins the resulting statements
  across revocation reasons and the caller's signature interval. An assessment
  retains source indices, negative findings and the status's deciding basis.
  An unusable CRL with a noncritical issuing distribution point does not
  discard other sources. `Assessment::expiry_evidence` reports whether the
  deciding post-expiry assertions cover every revocation reason.
  Trust anchors, configured responders, acquisition and freshness policy
  remain explicit caller inputs.
- `validation::long_term` runs EN 319 102-1 clause 5.6 over proof-of-existence
  bounds for original objects and caller-established timestamp, Evidence
  Record, revocation and historical path facts. It keeps the with-time
  result, past certificate and signature results, timestamp decisions and
  final indication independently visible. Proofs are collected newest first
  for timestamps in the producer's established processing order, with
  explicit validity and algorithm sunset boundaries. RFC 3161 accuracy
  upper bounds are used for proofs. An optional lower bound can establish
  future generation. Historical members distinguish a policy waiver from
  missing revocation data and keep their certificate and crypto obligations.
  The report and temporary proof store use accounted, fallible memory.
  `validate_past_signature` can also operate on provisional next-token
  proofs within a format's Evidence Record validation.
- `timestamp` retains a completed CMS token check as `Verified`, with the
  original token, signature, property and `Purpose` (content, signature,
  validation data or archive). It derives complete generation intervals from
  the retained effective accuracy (signed token or explicit caller-authenticated
  TSA policy), associates a signature timestamp with the
  signer's checked path (`signature_time`) and holds the complete token
  obligations of one scope (`TimestampRequirements`, `TimestampPaths`).
- `pki` runs the common PKIX path processor for actor paths, binds CRL and
  OCSP results to actual path members, closes the validation-authority graph
  and derives the complete participant census (`participants`) from the
  format's receipts: `SignerReceipt`, `CounterReceipts` and
  `CredentialReceipts`. Later facts require those very receipts, not equal
  identities. `pki::check_direct_anchor` binds a signer to the exact certificate
  already trusted by the caller. The result exposes the original signer via
  `CheckedPath::target` and has no non-anchor revocation obligations.
- `material` indexes every incorporated certificate, CRL and OCSP value with
  the format's placement of each occurrence, attributes artifact uses to
  actors, reports incorporation, and checks each archive input's `Coverage`
  against its checked token.
- `baseline` joins a format's stage reports through `BasicStage`,
  `X509Material`, `CredentialMaterial` and `ArchiveCensus`: `timestamped`,
  `long_term`, `archive_material` and `archives`. The format layer keeps its
  own level assessment.

Reports keep detailed negative findings. Material presence does not establish
usable revocation status, historical trust, timestamp chronology or algorithm
longevity. Source, generation, resource and callback failures remain processing
errors, separate from missing or mismatching evidence.

## Implementing a format

A format layer implements `Source` (or `Query` over its access guard) and the
receipt traits on its own checked results, builds `TimestampRequirements` from
every original timestamp in source order, failed and unsupported ones included,
and builds a `material::Index` and one `Coverage` per archive input.

These receipts carry the format's issuer type, and constructing one takes a
value of it. A format defines that type with a private field, so its callers
cannot relabel checked timestamp evidence, associate it with another signer or
supply a fabricated census, index or coverage. The participant census is derived
by `pki::participants`, which takes the issuer value too, so it comes only from
the format's own signer, counter and credential receipts. Receipts of different
issuers do not combine. The
integration test `tests/cms_source.rs` drives the participant census and
archive coverage over CMS `SignerInfo` attributes identified by ordinal.

Cryptographic test adapters are development-only oracles, not qualified
production providers.
