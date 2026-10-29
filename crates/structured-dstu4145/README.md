# structured-dstu4145

Verification-only DSTU 4145 and Ukrainian streaming hashes in Rust.

The implementation uses fixed-width public-value arithmetic and borrowed
prepared hash tables. It performs no signing, key generation, private-key
handling, operating-system I/O or implicit random-source selection.

GOST 34.311 uses an explicitly selected DKE and zero initial vector. Kupyna
uses RustCrypto's no-std cores with declared output lengths. State and output
are inline; callers own their lifetime and storage. Backend selection, XML
algorithm URIs, deployment permissions and trust decisions belong to callers.

This package is under development. Implementation and qualification must be
completed before release; source availability is not registry delivery.
