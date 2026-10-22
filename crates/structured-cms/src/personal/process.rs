//! Scoped import orchestration; no temporary plaintext or model can escape.

use super::{
    Bag, BagValue, DATA, FIELD, Integrity, Pfx, PrivateKey, Safe, ShroudedKey, encoding, end,
    equal_oid, invalid, sequence,
};
use crate::{Error, ErrorCode, Octets, Result, content_source::SourceMap, signer::required};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{Encoding, Reader, Span};
use zeroize::Zeroize;

/// Accounted plaintext which wipes initialized storage before deallocation.
/// It owns no backend and never implements Debug/Clone. Growth and copies must
/// use the supplied current Reader execution before wrapping the resulting owner.
pub struct Plaintext(OwnedVec<u8>);
impl Plaintext {
    /// Copies bytes into current accounted storage after funding the eventual
    /// wipe. Copy/refusal paths keep a wiping guard from the first stored byte.
    pub fn copy_from(bytes: &[u8], query: &Reader<'_>) -> Result<Self> {
        let execution = query.execution();
        execution
            .charge_work(bytes.len() as u64)
            .map_err(|e| Error::resource(e, FIELD, query.offset()))?;
        let mut output = Wiping(Some(execution.vector()));
        output
            .bytes()
            .try_extend_from_slice(bytes)
            .map_err(|e| Error::resource(e, FIELD, query.offset()))?;
        Ok(output.into_owned())
    }
    /// Copies exact logical octets once for in-place decryption. Metadata,
    /// capacity, copies and the eventual wipe are paid by the producing query.
    pub fn copy_octets(octets: &Octets<'_>, query: &Reader<'_>) -> Result<Self> {
        if !core::ptr::eq(octets.parser(), query.parser()) {
            return Err(Error::pkix(structured_pkix::Error::new(
                structured_pkix::ErrorCode::ForeignReader,
                FIELD,
                octets.span().start,
            )));
        }
        let execution = query.execution();
        let fail = |e| Error::resource(e, FIELD, octets.span().start);
        execution.charge_work(octets.len() as u64).map_err(fail)?;
        execution
            .charge_work(octets.pieces().len() as u64)
            .map_err(fail)?;
        let mut output = Wiping(Some(execution.vector()));
        output
            .bytes()
            .try_reserve_exact(octets.len())
            .map_err(fail)?;
        for piece in octets.pieces() {
            output
                .bytes()
                .try_extend_from_slice(piece.as_bytes())
                .map_err(fail)?;
        }
        Ok(output.into_owned())
    }
    /// Immutable plaintext; no allocating conversion is performed.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Mutable existing bytes for in-place cipher operations, without growth.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.0
    }
    /// Wipes and discards padding/trailing initialized bytes, retaining the
    /// original allocation/account. A length beyond the current length is a
    /// no-op; this cannot grow or reveal spare capacity.
    pub fn truncate(&mut self, length: usize) {
        if length < self.0.len() {
            self.0[length..].zeroize();
            while self.0.len() > length {
                self.0.pop();
            }
        }
    }
}

/// Encode a legacy PKCS#12 password as big-endian BMP characters plus a single
/// zero terminator (RFC7292 Appendix B.1). Supplementary Unicode scalars are
/// refused, never encoded as surrogate pairs. PBMAC1 (RFC9879 §6) and PBES2
/// use the original UTF-8 bytes instead; callers must not apply this conversion
/// merely because a different protection layer in the same PFX uses legacy PBE.
/// <https://www.rfc-editor.org/rfc/rfc7292#appendix-B.1>
pub fn legacy_password(password: &str, query: &Reader<'_>) -> Result<Plaintext> {
    let execution = query.execution();
    let fail = |e| Error::resource(e, FIELD, query.offset());
    // Both Unicode passes are funded before the first scan.
    execution.charge_work(password.len() as u64).map_err(fail)?;
    execution.charge_work(password.len() as u64).map_err(fail)?;
    let mut count = 1_usize;
    for ch in password.chars() {
        if u32::from(ch) > u32::from(u16::MAX) {
            return Err(Error::schema(
                ErrorCode::MalformedValue,
                FIELD,
                query.offset(),
            ));
        }
        count = count
            .checked_add(1)
            .ok_or_else(|| Error::schema(ErrorCode::LengthOverflow, FIELD, query.offset()))?;
    }
    let size = count
        .checked_mul(2)
        .ok_or_else(|| Error::schema(ErrorCode::LengthOverflow, FIELD, query.offset()))?;
    execution.charge_work(size as u64).map_err(fail)?;
    let mut output = Wiping(Some(execution.vector()));
    output.bytes().try_reserve_exact(size).map_err(fail)?;
    for ch in password.chars() {
        debug_assert!(u16::try_from(u32::from(ch)).is_ok());
        let encoded = u32::from(ch).to_be_bytes();
        output
            .bytes()
            .try_extend_from_slice(&encoded[2..])
            .map_err(fail)?;
    }
    output
        .bytes()
        .try_extend_from_slice(&[0, 0])
        .map_err(fail)?;
    Ok(output.into_owned())
}
impl Drop for Plaintext {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
struct Wiping<W: Work>(Option<OwnedVec<u8, W>>);
impl<W: Work> Wiping<W> {
    fn bytes(&mut self) -> &mut OwnedVec<u8, W> {
        self.0
            .as_mut()
            .expect("buffer exists until consuming transfer")
    }
    fn into_owned(mut self) -> Plaintext {
        Plaintext(self.0.take().expect("consuming transfer once").into_owned())
    }
}
impl<W: Work> Drop for Wiping<W> {
    fn drop(&mut self) {
        if let Some(bytes) = self.0.as_mut() {
            bytes.zeroize();
        }
    }
}

/// A provider's explicit acceptance/capability result, not an application verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Authentication succeeded (or the caller explicitly accepted no MAC).
    Accept,
    /// The original integrity protection failed or is required but absent.
    Reject,
    /// The selected provider does not implement the written mechanism.
    Unsupported,
}

/// Scoped coordinates for callback views. Joins map to their enclosing source;
/// decrypted bytes have their own coordinate space, never invented physical
/// offsets. A caller can retain/project known locations while the scope is live.
pub enum Source<'a> {
    /// Original PFX document coordinates.
    Document,
    /// Logical carried bytes with their exact original fragment mapping.
    Carried {
        /// Mapping into the parent source coordinates.
        map: &'a Fragments,
        /// The source enclosing those fragments.
        parent: &'a Source<'a>,
    },
    /// New plaintext coordinates starting at zero, without a bytewise map to
    /// ciphertext (encryption is not a source-offset-preserving transformation).
    Plaintext {
        /// Ciphertext enclosure in the parent's coordinates.
        ciphertext: Span,
        /// Original source of that encrypted container.
        parent: &'a Source<'a>,
    },
}
/// One independently retained source transformation, innermost first.
#[derive(Debug)]
pub enum Origin {
    /// Map into the next enclosing source, retained without plaintext bytes.
    Carried(Fragments),
    /// Offsets name a decrypted source; only its ciphertext enclosure is physical
    /// in the next layer. This is not a contiguous plaintext-to-ciphertext map.
    Plaintext(Span),
}

/// A carried-byte map into its immediate enclosing source. Unlike a standalone
/// document map, its parent can itself be carried or decrypted; the [`Source`]
/// / [`Failure::origins`] chain identifies that domain explicitly. No method
/// claims that a parent-relative offset is already a physical PFX coordinate.
#[derive(Debug)]
pub struct Fragments(SourceMap);
impl Fragments {
    /// Parent-relative enclosure of the complete carrying OCTET STRING TLV.
    #[must_use]
    pub fn enclosure(&self) -> Span {
        self.0.carrier()
    }
    /// Maps one current source point into the immediately enclosing source.
    /// Repeat through the retained chain until Document, or stop at a Plaintext
    /// boundary, where only the ciphertext enclosure can be mapped further.
    pub fn offset_in_parent(&self, at: u64, work: &impl Work) -> Result<u64> {
        self.0.project_offset(at, work)
    }
    /// Maps a current range into its actual parent fragments, without claiming
    /// a single contiguous physical range across headers or encryption.
    pub fn ranges_in_parent(&self, span: Span, work: &impl Work) -> Result<OwnedVec<Span>> {
        self.0.project_span(span, work)
    }
    /// Retains just this layer's metadata for a caller-owned diagnostic/result.
    pub fn try_copy_in(&self, work: &impl Work) -> Result<Self> {
        self.0.try_copy_in(work).map(Self)
    }
}
/// Terminal failure, preserving the exact cause and its coordinate chain.
/// At most two carried wrappers and two decryptions occur in this pipeline;
/// nested `SafeContents` are walked in place and add no transformation layer.
#[derive(Debug)]
pub struct Failure<E> {
    /// Processing or callback cause, without loss of its original type.
    pub cause: Cause<E>,
    /// Retained source transformations, innermost to outermost. Empty means
    /// the cause refers directly to the original PFX document.
    pub origins: [Option<Origin>; 4],
}
/// Processing failures are distinct from provider/consumer callback refusal.
#[derive(Debug)]
pub enum Cause<E> {
    /// A source/parameter/ownership/resource processing failure.
    Processing(Error),
    /// The unchanged callback error, with no conversion to invalid/mismatch.
    Callback(E),
}
impl<E> Failure<E> {
    fn processing(error: Error) -> Self {
        Self {
            cause: Cause::Processing(error),
            origins: core::array::from_fn(|_| None),
        }
    }
    fn callback(error: E) -> Self {
        Self {
            cause: Cause::Callback(error),
            origins: core::array::from_fn(|_| None),
        }
    }
    fn enclosed(mut self, origin: Origin) -> Self {
        let slot = self
            .origins
            .iter_mut()
            .find(|item| item.is_none())
            .expect("four pipeline transformations maximum");
        *slot = Some(origin);
        self
    }
}

/// A selected backend and extraction visitor. It must fund all backend work,
/// temporary/output capacity and key/password handling through the supplied
/// Reader before work. There is no default implementation or implicit engine.
pub trait Backend {
    /// Owned error type, independent of temporary decrypted input lifetimes.
    type Error;
    /// Check the entire original PFX integrity. For Password mode, MAC input is
    /// exactly `safe` logical octets. Signed mode uses the existing CMS verifier
    /// over the actual carried data. A missing MAC must be explicitly accepted
    /// or rejected here; it never gains an authentication proof from parsing.
    fn authenticate(
        &mut self,
        integrity: &Integrity<'_>,
        query: &Reader<'_>,
    ) -> core::result::Result<Decision, Self::Error>;
    /// Decrypt one complete password-protected or enveloped safe. The model
    /// retains the original algorithms/recipients; `Safe::Data` is never passed.
    /// Return a wiping buffer on this current account. A failure terminates
    /// processing; ciphertext is not interpreted as plaintext on refusal.
    fn decrypt_safe(
        &mut self,
        safe: &Safe<'_>,
        query: &Reader<'_>,
        source: &Source<'_>,
    ) -> core::result::Result<Plaintext, Self::Error>;
    /// Decrypt one original PKCS#8 shrouded key, including a key inside an
    /// already encrypted safe. Its KDF is a separate paid operation.
    fn decrypt_key(
        &mut self,
        key: &ShroudedKey<'_>,
        query: &Reader<'_>,
        source: &Source<'_>,
    ) -> core::result::Result<Plaintext, Self::Error>;
    /// Consume each original bag once in direct sibling/preorder nesting order.
    /// The parsed bag/source are scoped; owned extraction must fund its own
    /// retained storage. Unknown bags remain explicit and are not discarded.
    fn bag(
        &mut self,
        bag: &Bag<'_>,
        query: &Reader<'_>,
        source: &Source<'_>,
    ) -> core::result::Result<(), Self::Error>;
    /// Consume the clear key obtained from a shrouded bag, under its new honest
    /// plaintext coordinates. The enclosing bag is not replayed to `bag`.
    fn key(
        &mut self,
        key: &PrivateKey<'_>,
        query: &Reader<'_>,
        source: &Source<'_>,
    ) -> core::result::Result<(), Self::Error>;
}

/// Authenticate, then process every original safe and nested bag once.
///
/// Reject/Unsupported returns before any privacy or extraction callback. A
/// processing/callback error returns no successful completion; external visitor
/// effects cannot be rolled back by this library and belong in caller staging.
/// The backend's `Accept` is a trusted callback fact, not a core trust verdict.
#[expect(
    clippy::result_large_err,
    reason = "retain opaque cause and four source maps without allocating on the refusal path"
)]
pub fn process<B: Backend>(
    pfx: &Pfx<'_>,
    query: &Reader<'_>,
    backend: &mut B,
) -> core::result::Result<Decision, Failure<B::Error>> {
    let original = pfx
        .original()
        .reader_in(query)
        .map_err(Failure::processing)?;
    original
        .charge(1)
        .map_err(encoding)
        .map_err(Failure::processing)?;
    let decision = backend
        .authenticate(&pfx.integrity, &original)
        .map_err(Failure::callback)?;
    if decision != Decision::Accept {
        return Ok(decision);
    }
    nested(
        pfx.safe(),
        &original,
        &Source::Document,
        |reader, source| {
            let root = required(reader, FIELD).map_err(Failure::processing)?;
            let mut safes = sequence(reader, &root).map_err(Failure::processing)?;
            end(reader).map_err(Failure::processing)?;
            while let Some(element) = safes
                .next_element()
                .map_err(encoding)
                .map_err(Failure::processing)?
            {
                let safe = Safe::read(&safes, &element).map_err(Failure::processing)?;
                safes
                    .charge(1)
                    .map_err(encoding)
                    .map_err(Failure::processing)?;
                match &safe {
                    Safe::Data(bytes) => nested(bytes, &safes, source, |reader, source| {
                        bags(reader, source, backend)
                    })?,
                    Safe::Encrypted(encrypted) => {
                        check_data(&safes, encrypted.content.kind, element.span())
                            .map_err(Failure::processing)?;
                        let ciphertext =
                            encrypted.content.ciphertext.as_ref().ok_or_else(|| {
                                Failure::processing(invalid(ErrorCode::DetachedContent, &element))
                            })?;
                        let plain = backend
                            .decrypt_safe(&safe, &safes, source)
                            .map_err(Failure::callback)?;
                        decrypted(&plain, &safes, ciphertext, source, |reader, source| {
                            bags(reader, source, backend)
                        })?;
                    }
                    Safe::Enveloped(enveloped) => {
                        check_data(&safes, enveloped.content.kind, element.span())
                            .map_err(Failure::processing)?;
                        let ciphertext =
                            enveloped.content.ciphertext.as_ref().ok_or_else(|| {
                                Failure::processing(invalid(ErrorCode::DetachedContent, &element))
                            })?;
                        let plain = backend
                            .decrypt_safe(&safe, &safes, source)
                            .map_err(Failure::callback)?;
                        decrypted(&plain, &safes, ciphertext, source, |reader, source| {
                            bags(reader, source, backend)
                        })?;
                    }
                    Safe::Other { .. } => {
                        return Err(Failure::processing(invalid(
                            ErrorCode::UnexpectedContentType,
                            &element,
                        )));
                    }
                }
            }
            Ok(())
        },
    )?;
    Ok(decision)
}

fn check_data(parent: &Reader<'_>, kind: structured_asn1::Oid<'_>, span: Span) -> Result<()> {
    if !equal_oid(parent, kind, DATA)? {
        return Err(Error::schema(
            ErrorCode::UnexpectedContentType,
            FIELD,
            span.start,
        ));
    }
    Ok(())
}

#[expect(
    clippy::result_large_err,
    reason = "owned source maps preserve error provenance without refusal-path allocation"
)]
fn bags<B: Backend>(
    parent: &mut Reader<'_>,
    source: &Source<'_>,
    backend: &mut B,
) -> core::result::Result<(), Failure<B::Error>> {
    let root = required(parent, FIELD).map_err(Failure::processing)?;
    let reader = sequence(parent, &root).map_err(Failure::processing)?;
    end(parent).map_err(Failure::processing)?;
    let execution = parent.execution();
    let mut frames = execution.vector();
    frames
        .try_push(reader)
        .map_err(|e| Failure::processing(Error::resource(e, FIELD, root.span().start)))?;
    while let Some(frame) = frames.last_mut() {
        frame
            .charge(1)
            .map_err(encoding)
            .map_err(Failure::processing)?;
        let Some(element) = frame
            .next_element()
            .map_err(encoding)
            .map_err(Failure::processing)?
        else {
            frames.pop();
            continue;
        };
        let bag = Bag::read(frame, &element).map_err(Failure::processing)?;
        backend
            .bag(&bag, frame, source)
            .map_err(Failure::callback)?;
        if let BagValue::Contents(value) = &bag.value {
            // The original value sits inside SafeBag.[0], two levels below
            // this loop cursor. Reopen its saved context before entering it.
            let original = value.reader_in(frame).map_err(Failure::processing)?;
            let reader = sequence(&original, value.element()).map_err(Failure::processing)?;
            frames.try_push(reader).map_err(|e| {
                Failure::processing(Error::resource(e, FIELD, element.span().start))
            })?;
        } else if let BagValue::Shrouded(key) = &bag.value {
            let plain = backend
                .decrypt_key(key, frame, source)
                .map_err(Failure::callback)?;
            decrypted(&plain, frame, &key.encrypted, source, |reader, source| {
                let value = required(reader, FIELD).map_err(Failure::processing)?;
                let key = PrivateKey::read(reader, &value).map_err(Failure::processing)?;
                end(reader).map_err(Failure::processing)?;
                reader
                    .charge(1)
                    .map_err(encoding)
                    .map_err(Failure::processing)?;
                backend.key(&key, reader, source).map_err(Failure::callback)
            })?;
        }
    }
    Ok(())
}

#[expect(
    clippy::result_large_err,
    reason = "preserve independently owned source chain with the original callback cause"
)]
fn nested<R, E>(
    octets: &Octets<'_>,
    parent: &Reader<'_>,
    origin: &Source<'_>,
    callback: impl for<'scope> FnOnce(
        &mut Reader<'scope>,
        &Source<'_>,
    ) -> core::result::Result<R, Failure<E>>,
) -> core::result::Result<R, Failure<E>> {
    if !core::ptr::eq(octets.parser(), parent.parser()) {
        return Err(Failure::processing(Error::pkix(
            structured_pkix::Error::new(
                structured_pkix::ErrorCode::ForeignReader,
                FIELD,
                octets.span().start,
            ),
        )));
    }
    let map = Fragments(SourceMap::of(octets, parent, FIELD).map_err(Failure::processing)?);
    let joined;
    let (bytes, base) = if let [piece] = octets.pieces() {
        (piece.as_bytes(), piece.span().start)
    } else {
        joined = Plaintext::copy_octets(octets, parent).map_err(Failure::processing)?;
        (&*joined.0, 0)
    };
    let reader = parent.parser().read_nested_query_in(
        parent,
        bytes,
        base,
        Encoding::Ber,
        octets.outer_depth(),
    );
    let result = match reader {
        Ok(mut reader) => callback(
            &mut reader,
            &Source::Carried {
                map: &map,
                parent: origin,
            },
        ),
        Err(error) => Err(Failure::processing(encoding(error))),
    };
    result.map_err(|e| e.enclosed(Origin::Carried(map)))
}

#[expect(
    clippy::result_large_err,
    reason = "preserve source/opaque cause without another allocation on refusal"
)]
fn decrypted<R, E>(
    plain: &Plaintext,
    parent: &Reader<'_>,
    encrypted: &Octets<'_>,
    origin: &Source<'_>,
    callback: impl for<'scope> FnOnce(
        &mut Reader<'scope>,
        &Source<'_>,
    ) -> core::result::Result<R, Failure<E>>,
) -> core::result::Result<R, Failure<E>> {
    let ciphertext = encrypted.span();
    if !plain.0.memory().same_account(parent.memory()) {
        return Err(Failure::processing(Error::schema(
            ErrorCode::InvalidLocation,
            FIELD,
            ciphertext.start,
        )));
    }
    let reader = parent.parser().read_nested_query_in(
        parent,
        &plain.0,
        0,
        Encoding::Ber,
        encrypted.outer_depth(),
    );
    let result = match reader {
        Ok(mut reader) => callback(
            &mut reader,
            &Source::Plaintext {
                ciphertext,
                parent: origin,
            },
        ),
        Err(error) => Err(Failure::processing(encoding(error))),
    };
    result.map_err(|e| e.enclosed(Origin::Plaintext(ciphertext)))
}
