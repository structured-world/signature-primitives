# structured-asn1

A BER/DER reader that borrows encoded values and retains their original byte
ranges. Nested readers share depth, element, length and work limits. Resource
exhaustion is distinct from malformed input.

OID identity uses its encoded bytes. `Oid::text(&Memory)` and
`Arc::text(&Memory)` materialize exact decimal text with fallible work and
capacity admission. Returned text retains its storage charge until released;
OID and arc values do not implement `Display`. Borrowed arc iteration leaves
its traversal admission to the caller.

Owned vectors, maps and strings retain allocated capacity on their original
resource account. Container construction, growth and copies operate in that
declared domain. Map lookup/removal and `try_iter(&Memory)` may instead use a
current execution account; iteration prepays control buckets, including sparse
holes. Rebuilding a collection in another domain requires an explicit fallible
copy; retained allocations are never silently rebound.

This crate reads encoding structure, not certificate trust or signature validity.
It uses `no_std + alloc` by default and has no cryptographic backend or I/O.

```rust
extern crate alloc;
use alloc::sync::Arc;
use structured_asn1::{Parser, Tag, universal};
use structured_asn1::memory::{Memory, MemoryAccount};

let bytes = [0x30, 0x03, 0x02, 0x01, 0x01];
let memory = Memory::new(Arc::new(MemoryAccount::new(1024, 1024)));
let parser = Parser::der(memory);
let mut reader = parser.read(&bytes, 0)?;
let sequence = reader.expect(Tag::constructed(universal::SEQUENCE))?;
let mut inside = reader.enter(&sequence)?;
let integer = inside.expect(Tag::primitive(universal::INTEGER))?;
assert_eq!(integer.contents(), &[1]);
# Ok::<(), structured_asn1::Error>(())
```

Licensed under Apache-2.0.
