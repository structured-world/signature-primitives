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
  identities.
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
