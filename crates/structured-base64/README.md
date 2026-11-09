# structured-base64

Resumable Base64 for caller-provided buffers. The codec uses only `core`, with
no allocator or runtime dependencies. Each successful call consumes its whole
input and returns the output length. Store the six public state fields between
successful calls and restore them before resuming.

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
[libxmlsec 1.3.13](https://github.com/lsh123/xmlsec/blob/e4b8614fb678ee545b70ab419d4c5418f2ce4885/src/base64.c).
Line breaks are optional and occur before the next character after a full line.
Decoding skips space, tab, CR and LF and accepts nonzero unused padding bits.
Padding must appear in the final group and data may not follow it.

A short buffer is a terminal error for that stream. The decoder needs output
room before consuming a non-space byte, including padding. Finalization
requires a nonempty slice and the encoder leaves one spare byte. Capacity
helpers include this slack and refuse arithmetic overflow. The codec does
not write a NUL terminator. ABI adapters own layout, pointer checks, NUL
termination and the external error mapping.

Callers with a work budget admit the input scan and output writes before each
call. Work is linear in input and output size and the codec retains fixed
storage. Rust 1.92 or newer is required.
