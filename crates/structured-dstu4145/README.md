# structured-dstu4145

Verification-only DSTU 4145 arithmetic, streaming GOST 34.311 and Kupyna,
using fixed inline storage and safe Rust. There is no signing, key generation,
private-key API, operating-system I/O, implicit randomness or provider registry.

This is a source package. Initial registry publication and Trusted Publisher
configuration are separate release steps; a source checkout is not a published
consumer dependency.

## Domains and verification

`domain::Domain::named` prepares the ten recommended polynomial-basis and five
recommended optimal-normal-basis domains. `Domain::explicit` checks encoded
numeric components using the standard's authenticated polynomial/order facts.
Other explicit parameters use `explicit_with_evidence`: custom polynomials
require the complete prime factorization of `2^m - 1`, and unknown factors or
subgroup orders require caller-supplied cryptographic entropy for 50
Miller-Rabin rounds. Sampling is bounded and original entropy failures remain
typed. No operating-system generator is selected.

Validation includes polynomial primitivity, order bounds/primality and the
MOV check where these facts are not already authenticated, a nonzero base
point, the curve equation and `nP = O`. Public-key preparation independently
decompresses the point and checks `nQ = O`. ONB uses the original standard
coefficients and UAPKI base points, without substituting Frobenius images.

`PublicKey::verify_prehash` receives the unchanged digest octets emitted by
the selected Ukrainian PKI hash. The normative digest-to-field transformation,
zero-hash rule, low-bit extraction and signature component order live here.
It never hashes the input again. Standard worked examples print `H(T)` most
significant first; that printed representation differs from native digest
octets. Key and signature byte order do not change the digest interpretation.

The raw signature is the OCTET payload: `r_LE || s_LE` or `s_BE || r_BE`.
Components may be zero-padded up to the fixed 64-octet scalar capacity.
`accounted::Key::verify_signature_value` instead reads a certificate/CRL's
original carried OCTET STRING through the shared strict profile reader, which
requires the profile's minimum width based on `L(n)`, not the field degree.
Bad framing/key/domain inputs are typed errors. Correctly framed out-of-range
scalars, an infinite verification result and computed mismatches return false.
Arithmetic is variable-time because every operand is public.

## Streaming hashes

`gost::Dke` validates an explicit packed substitution table and prepares four
inline lookup tables once. Hash states borrow them, with no table copying,
reference counts or allocations in updates. GOST uses the zero initial vector.
The low-level API has no implicit DKE default. The source-aware parameter
adapter applies the historical profile's number-one DKE only when that actual
schema omits it.

Kupyna uses RustCrypto's `kupyna` cores with default features disabled. Output
length is explicit, from 1 through 64 octets, including 256, 384 and 512 bits.
The short/long core and right truncation follow the declared output size.
State and output are inline. `finalize_into` writes into an exact-width
caller-provided buffer. The streaming facade bounds cumulative input to
`u64::MAX` octets and refuses overflow before state mutation.

```rust
use structured_dstu4145::{gost::{Dke, DEFAULT_DKE}, hash::{Hash, State}};

let dke = Dke::new(&DEFAULT_DKE)?; // Explicit trusted caller selection.
let mut stream = State::new(Hash::Gost34311(&dke))?;
stream.update(b"first chunk")?;
stream.update(b"second chunk")?;
let mut output = [0; 32];
stream.finalize_into(&mut output)?;
# Ok::<(), structured_dstu4145::Error>(())
```

## Original and current resources

The arithmetic/hash kernel allocates nothing and owns no `Arc`. It accepts
only bounded public values; a caller funds the selected bounded operation.
`accounted` supplies that adapter for the existing ASN.1 `Work` and `Digest`
contracts. It admits the complete curve operation before arithmetic, including
decompression, subgroup checks, inverse recovery and custom-polynomial
reduction. Hash updates charge actual complete blocks and copies, and finish
admits padding, checksum and output transformations before execution.

Prepared keys and digest identities retain their original borrowed producers.
Joint admission preserves all existing current ceilings and both required
origins with one current-account bill. No account is reset, cloned or replaced
to make an operation fit. Parser limits must fund the cryptographic work as
well as initial decoding. This does not claim accounting inside arbitrary
consumer callbacks or acquisition code.

GOST identity compares the full effective DKE, not its OID, width or address.
CMS's existing `SignatureProvider::resolve_signature_digest` hook resolves
each actual effective key before creating a digest receipt. Different DKEs
share one provider and one payload fan-out pass; equal semantic identities
deduplicate. `ProviderSession` delegates the override. ESS and TSP remain
separate operation-specific resolutions, without inheriting a signer default.

XML URI mapping, canonicalization, capability/policy selection, trust and
application reporting remain with the caller. This crate does not implement
an XML `CryptoProvider` or another dispatcher.

## Build and evidence

Default builds are `no_std`. `alloc` and `std` forward the common library
features. Allocation instrumentation is opt-in through `allocation-tests`
and has no default release cost. Bare-metal and WASM compilation use the
workspace's required alloc-only checks.

Tests cover normative PB/ONB worked examples, all standard fields/recommended
domains, explicit validation evidence, independent public CA signatures,
stream boundaries, producing/current resource refusal and mixed-DKE CMS.
The allocation test includes a positive control. The `verification` benchmark
separates preparation and repeated verification, reports timing distributions
and optionally allocations, and compares selected identical domains against
`ua-cryptography-dstu4145` as a development-only performance reference.

```text
cargo nextest run -p structured-dstu4145 --features allocation-tests
cargo bench -p structured-dstu4145 --features allocation-tests --bench verification
```

Normative references: DSTU 4145-2002 sections 5–13, tables 1–2 and its worked
examples; [Kupyna's authors' description, table 1 and section 3](https://eprint.iacr.org/2015/885);
[RFC 5831 sections 5–6](https://www.rfc-editor.org/rfc/rfc5831.html#section-5)
for GOST compression. The Ukrainian certificate/OID/CMS encoding profiles
[z1398-12](https://zakon.rada.gov.ua/laws/show/z1398-12),
[z1399-12](https://zakon.rada.gov.ua/laws/show/z1399-12) and
[z1401-12](https://zakon.rada.gov.ua/laws/show/z1401-12) are historical,
repealed regulatory texts. Recognition does not assert current legal compliance.
The full copyrighted DSTU standard is not distributed. This implementation
and its tests do not constitute a cryptographic audit or certification.
