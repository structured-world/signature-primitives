# structured-cades

Source-bound `CAdES` baseline composition for ETSI EN 319 122-1 V1.3.1.

The format layer sits above `structured-cms` and `structured-ltv`. It uses
original CMS attributes, signer and material locations, the existing injected
cryptographic operations, and the common path/status/timestamp mechanisms.
Requested B-B, B-T, B-LT and B-LTA stages preserve their separate conformance,
mathematical, temporal and material obligations. Application trust and policy,
source acquisition and reporting remain with the consumer.

The default build supports `no_std + alloc`; `std` is optional. Operations
receive an explicit producing reader and current execution. Original signed
bytes are never serialized to bridge the layers.

Source and package verification do not establish availability of a particular
registry version or consumer adoption.

## Processing

`source::Document` binds the original `SignedData` model and selected root.
`prepare::Preparation` reads the requested level, signed and unsigned property
syntax, independent ESS sets and the complete nested counter/timestamp census.
It preserves required versus advisory findings and original malformed values.
The signed MIME description accepts a media type or complete original MIME
header fields with an explicit Content-Type, using the common MIME grammar.
Present timestamp envelopes and carried information are syntax-checked even
for a B-B request, including TSA ESS and protected CMS fields. Each `ATSv3`
also receives non-cryptographic profile/index inspection. Known digest widths
and index/imprint identities are checked without resolving a provider or
executing its hashes; unknown mechanisms remain capability questions.
Envelope models are retained once for later checks; unreadable
information keeps its original failure and independently retained source map.
An attribute OID or a successful subset cannot promote the requested level.

Use the existing CMS `verify::DocumentBatch` for the actual carried or explicit
detached payload. `basic::bind` binds its original result and effective key to
the selected certificate, signed ESS identifiers and actual checked path.
`counters::bind` checks each child over its direct parent's original signature
octets. Unreadable or failed children prevent a complete counter-path receipt;
their SID, profile, payload, signature and ESS causes remain available.

`credential::check` sends original protected non-claimed credentials to their
actual format owner. `Complete` exists only after every value authenticated
with actual authority paths, a direct anchor, or an explicit certificate-free
mechanism. Reading a credential envelope never authenticates its contents.

`material::Pool` borrows original token models and retains first-read legacy
certificate/revocation values from root, counter, parallel-root and TSA sources.
Legacy revocation-values carry bare `BasicOCSPResponse` values; RFC 5940 CMS
revocation choices carry whole `OCSPResponse` envelopes. Neither route fabricates
an envelope. Other revocation formats keep their original OID, wrapper and
source-backed values for their actual format owner. Its token visitors use
saved encoding, depth and source context, and `timestamp::Context` chooses the
actual original content, owner signature or `ATSv3` archive input. `CheckTime`
contains explicit UTC facts and an optional caller-supplied reference; there is
no clock discovery or token-derived reference. Unknown accuracy, mismatched
imprints, negative arithmetic and unverified timeliness cannot create evidence.

Bind each successful actor to its actual checked TSA path with the existing
LTV `bind_timestamp`, then bind the **complete original** timestamp requirements.
`baseline::timestamped` joins these paths and every root signature timestamp's
full static interval to the same basic report. Mathematical evidence and static
intervals do not establish historical non-revocation or trust.

`participants::participants` derives every actual signer, counter, credential
authority and TSA. Close their real per-member statuses and reached CRL/OCSP
authority paths through `close_statuses`. `material::check_participants` checks
all resulting certificates, complete/delta CRLs and whole OCSP envelopes using
the existing exact-artifact index. The credential format's material visitor
operates on its retained authentication evidence, without replaying it; empty
X.509 paths or certificate-free authentication cannot waive other dependencies.
For B-LT, the validation certificates must occur in the root certificate set;
archive augmentation can reuse actual token material under its separate rule.
`baseline::long_term` requires both material reports from the same receipts.

For each original root `ATSv3`, `ArchiveChecked::requirements` derives preceding
timestamps and counters from its **actual index coverage**, independently of
SET order or claimed dates. Check every preceding participant's X.509 and
credential material under that same coverage, then join with
`baseline::archive_material` and `baseline::archives`. The latter requires every
original archive once. The current archive's own TSA cannot substitute for an
earlier actor or repair material absent from its input.
Counter-owned `ATSv3` occurrences remain in the census with a placement finding:
the archive input selects a root `SignedData.signerInfos` item; nested counters
are protected through that root's indexed unsigned values.

Finally `baseline::assess` accepts exactly the requested stage set and the same
live preparation/credential receipts. Its predicate describes common format,
mathematical binding, static time and incorporated-material facts. Application
acceptance still needs the explicit original status results, chronology,
algorithm longevity and historical trust decisions.

## Historical and open-format obligations

`Preparation::preservation` retains older archive/long-term-validation fields
and reference timestamps from every root and counter. Older archive tokens
enter the complete original TSA census; malformed parallel sources remain
separate required findings rather than disappearing behind a valid selected root.

`timestamp::historical` implements explicit RFC 3126, TS 101 733 V1.5.1 and
RFC 5126 input contracts. An OID or claimed time does not choose an edition.
`HistoricalInput::project` takes exact preceding occurrence ordinals; excluding
another archive requires a `Later` witness from an actually checked covering
archive. Projection uses new minimal definite framing around original fields,
and honestly differs from unavailable original BER. `OriginalSnapshot` instead
binds the earlier signer fields, global content/material, parent signature and
non-archive attribute multiset before using its original unsigned wrapper/EOC.
Changed archive wrappers never acquire whole-item coverage merely because
their token values stayed unchanged.

Both RFC 5126 unsigned-field interpretations stream together through one
payload pass, without buffering the document or resolving another provider.
`Context::check_historical` uses the existing complete CMS/ESS/TSA/key/path/time
check. A matching old archive is not modern `ATSv3` conformance or a trust verdict.
`HistoricalChecked::requirements` derives its actual preceding TSA/counter
obligations, including archives owned by a counter or parallel root. Its scope
uses that actual owner and its descendant counters; wholly covered counters
also retain their nested TSA obligations.
For a counter or parallel owner's archive, `Pool::index_for_archive` builds the
same original artifact catalogue under that checked owner's signature identity;
`Pool::index` retains the selected root's scope. Foreign sources and unproven
archives refuse before an archive index can be used.
`material::credentials::Scope::before_archive` accepts either modern
or historical receipts. Each member-specific input is bound to its exact token,
including when several token values share an attribute, throughout coverage and
validation-material joins.

`timestamp::references::ReferenceInput::new` selects both Annex A.1.5 input
recipes from the actual root, counter or parallel signer. References-only
timestamps imprint the original complete-certificate-references and
complete-revocation-references Attribute contents, in that order. The
signature-and-references recipe first includes logical signature octets and
each original signature timestamp Attribute's contents. The current EN edition
requires those signature timestamps; historical external time-marks are not
invented as embedded bytes. Missing/ambiguous inputs refuse before hashing.

`Context::check_references` runs the same complete CMS/ESS/TSA/key/path/time
check and returns `ReferenceChecked`. Its purpose is `ValidationData`, distinct
from Signature and Archive. Coverage binds the exact token and original value
ranges; an omitted outer Attribute header never becomes whole-item coverage.
The timestamp proves existence of the imprinted references, not authentication
or completeness of the referenced certificates/CRLs/OCSP responses. Whole
participant assessment requires every reference TSA through the original full
census, including failed/unreadable and parallel occurrences. Original token
envelopes share the existing common cache; there is no second reference-specific
envelope decoder.

RFC 4998 long-term evidence remains an independent mechanism. An unimplemented
`PoE` mechanism blocks positive timestamped-or-higher assessment. Reference
timestamps remain advisory at B-T; their successful mathematical checks do not
waive modern baseline format rules. A valid modern archive cannot erase another
original obligation.

## Publication

This crate joins the coordinated workspace release through release-plz. Its
first publication uses only `CADES_BOOTSTRAP_TOKEN` in the isolated `CAdES` step,
after the existing packages publish through OIDC and their dependencies resolve.
The bootstrap still requires an approved release commit and successful CI on
that exact SHA; it cannot publish an ordinary feature commit. After the first
version exists, configure the crates.io Trusted Publisher for repository
`structured-world/signature-primitives`, workflow `release-plz.yml`, environment
`release`, revoke the temporary token and remove that GitHub Actions secret.
Subsequent coordinated versions use OIDC. Actual registry archives, checksums,
source revision, packaged tests, MSRV and alloc-only targets are qualified by
the existing registry job; source availability alone is not a released version.

Optional policy qualifiers and credential formats retain their original open
values for their actual owners. Policy-store linkage requires a protected,
written nonzero policy hash; an all-zero hash remains unknown. The policy's
technical specification defines its hash input and acceptance, rather than an
implicit file fetch, guessed normalization or another crypto dispatcher here.

## Execution and sources

All operations take the original producing reader/current execution. Original
signed attributes and signature fragments stay borrowed; archive input is
streamed with only the finished content digest retained across token callbacks.
Metadata, fragment fan-out, normalization, copies and retained capacity use the
same scoped work/account mechanisms as CMS/PKIX/LTV. Resource and foreign-source
refusals are terminal and never become mismatch, missing material or a
successful partial report. Information-inspection refusals retain their source
map and an explicit coordinate discriminator for the unchanged callback cause.
Callback refusal is sticky even when a format owner
attempts to return success afterward.
