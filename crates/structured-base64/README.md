# structured-base64

For complete values, `URL_SAFE_NO_PAD` implements the strict JWS base64url
profile and `STANDARD` implements canonical padded Base64 for JOSE `x5c`.
Both provide exact encoding lengths and caller-buffer operations.
Enable `alloc` for fallible `encode` and `decode` methods returning a
`String` and `Vec<u8>` respectively, or `encode_string(input, &mut text)`
to append after a fallible capacity reservation. Callers bound input and
output sizes before invoking the allocating helpers. Strict decode errors
return zero-based byte offsets and the original byte for invalid symbols.

```rust
use structured_base64::URL_SAFE_NO_PAD;

let mut encoded = [0; 4];
let len = URL_SAFE_NO_PAD.encode_slice(&[251, 255], &mut encoded)?;
assert_eq!(&encoded[..len], b"-_8");
let mut decoded = [0; 2];
assert_eq!(URL_SAFE_NO_PAD.decode_slice(&encoded[..len], &mut decoded)?, 2);
assert_eq!(decoded, [251, 255]);
# Ok::<(), structured_base64::Base64Error>(())
```

Resumable Base64 for caller-provided buffers. The codec uses only `core`, with
no allocator or runtime dependencies. Each successful call consumes its whole
input and returns the output length. Preserve the state fields between calls,
including `input_offset` for absolute decoder error positions. Offsets count
all original bytes, including whitespace.

```rust
use structured_base64::{Base64Codec, Base64Error};

let mut codec = Base64Codec::new(true, 4);
let mut out = [0; 16];
let first = codec.update(b"foo", &mut out)?;
let second = codec.update(b"ba", &mut out[first..])?;
let end = first + second;
let last = codec.finish(&mut out[end..])?;
assert_eq!(&out[..end + last], b"Zm9v\nYmE=");
# Ok::<(), Base64Error>(())
```

The codec uses the [RFC 4648 §4 alphabet](https://www.rfc-editor.org/rfc/rfc4648.html#section-4)
and emits padding with zero unused bits. The compatibility profile follows
[libxmlsec's streaming buffer behavior](https://github.com/lsh123/xmlsec/blob/90b3d51a25c734c667d5d37896586d3d60b862ff/src/base64.c).
Line breaks are optional and occur before the next character after a full line.
Decoding skips space, tab, CR and LF and accepts nonzero unused padding bits.
Padding must appear in the final group and data may not follow it.

A short buffer is a terminal error for that stream. The decoder needs room
only when it emits a byte. Finalization accepts an empty slice when there
is nothing to write. An encoder with a pending tail leaves one spare byte.
Capacity helpers include compatibility slack and refuse arithmetic overflow.
ABI adapters own layout, pointer checks, NUL
termination and the external error mapping.

Callers with a work budget admit the input scan and output writes before each
call. Work is linear in input and output size and the codec retains fixed
storage. Rust 1.92 or newer is required.
