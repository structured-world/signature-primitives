# structured-pkix

Borrowed X.509 certificate parsing and certification path validation. Original
signed bytes stay available as ranges rather than being re-encoded. Signature
verification is injected through `path::Verify`; this crate does not select a
cryptographic provider, fetch issuers, or decide application trust.

The default build uses `no_std + alloc`. Applications supply certificates,
trust inputs, validation time and resource limits explicitly.

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

The package is not yet published. Consumer migration and release qualification
are in progress. Licensed under Apache-2.0; third-party data notices remain
with their source data.
