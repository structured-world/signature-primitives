//! RFC5755 §7.1 targeted encrypted attributes and ciphertext-stealing defense.
//!
//! The authenticated original AC contains `ContentInfo` values with independent
//! `EnvelopedData`. Its selected provider decrypts; the common core then checks
//! DER `ACClearAttrs`, issuer/serial and the original AA-control intersection.
//! Plaintext is a new logical coordinate space, never a physical ciphertext
//! offset or invertible source map. No encryption engine or key store is here.
//! <https://www.rfc-editor.org/rfc/rfc5755#section-7.1>

use super::{
    AttributeCertificate,
    validation::usage::{AttributeUse, Checked},
};
use crate::{
    Error, ErrorCode, Result,
    attribute::Attribute,
    enveloped::{EnvelopedData, oid_is},
    signer::required,
};
use structured_asn1::memory::{Execution, OwnedVec, Work};
use structured_asn1::{Element, Encoding, Integer, Oid, Reader, Span, Tag, universal};
use structured_pkix::general_name::{self, GeneralName};

/// id-aca-encAttrs, RFC5755 Appendix A.
pub const IDENTIFIER: Oid<'static> = Oid::from_bytes(&[43, 6, 1, 5, 5, 7, 10, 6]);
/// id-ct-attrCertEncAttrs, identifying the exact decrypted content syntax.
pub const CONTENT_TYPE: Oid<'static> =
    Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 1, 14]);
const FIELD: &str = "attributeCertificate.encAttrs";
const CLEAR: &str = "acClearAttrs";

/// DER plaintext inspection, not an authenticated/bound credential by itself.
#[derive(Debug)]
pub struct ClearAttrs<'a> {
    /// Original plaintext issuer name, to be bound before use.
    pub issuer: GeneralName<'a>,
    /// Full signed INTEGER, never truncated or projected through a sentinel.
    pub serial: Integer<'a>,
    /// Every decrypted attribute in original order. Duplicate types remain
    /// distinct: RFC5755 §7.1 explicitly allows clear/encrypted/multiple sets.
    pub attributes: OwnedVec<Attribute<'a>>,
    element: Element<'a>,
}
impl<'a> ClearAttrs<'a> {
    /// Read the entire required DER plaintext, including its original header.
    /// An outer BER reader does not relax RFC5755 §7.1's plaintext DER rule.
    pub fn read(parent: &mut Reader<'a>) -> Result<Self> {
        let element = parent
            .expect(Tag::constructed(universal::SEQUENCE))
            .map_err(|e| Error::encoding(e, CLEAR))?;
        let mut der = parent
            .reread(&element, Encoding::Der)
            .map_err(|e| Error::encoding(e, CLEAR))?;
        let element = der
            .expect(Tag::constructed(universal::SEQUENCE))
            .map_err(|e| Error::encoding(e, CLEAR))?;
        let mut inside = der.enter(&element).map_err(|e| Error::encoding(e, CLEAR))?;
        let value = required(&mut inside, "acClearAttrs.acIssuer")?;
        let issuer =
            general_name::read(&inside, &value, "acClearAttrs.acIssuer").map_err(Error::pkix)?;
        let serial = inside
            .read_integer()
            .map_err(|e| Error::encoding(e, "acClearAttrs.acSerial"))?;
        let sequence = inside
            .expect(Tag::constructed(universal::SEQUENCE))
            .map_err(|e| Error::encoding(e, "acClearAttrs.attrs"))?;
        let mut members = inside
            .enter(&sequence)
            .map_err(|e| Error::encoding(e, CLEAR))?;
        let work = inside.execution();
        let mut attributes = work.vector();
        while let Some(element) = members
            .next_element()
            .map_err(|e| Error::encoding(e, CLEAR))?
        {
            attributes
                .try_reserve(1)
                .map_err(|e| Error::resource(e, CLEAR, element.span().start))?;
            let value = Attribute::read(&members, &element, "acClearAttrs.attrs")?;
            attributes
                .try_push(value)
                .map_err(|e| Error::resource(e, CLEAR, element.span().start))?;
        }
        end(&inside)?;
        end(parent)?;
        Ok(Self {
            issuer,
            serial,
            attributes: attributes.into_owned(),
            element,
        })
    }
    /// Original logical plaintext range, not an offset into encrypted bytes.
    #[must_use]
    pub fn element(&self) -> &Element<'a> {
        &self.element
    }
}

/// One independent decryption result from the explicitly selected provider.
/// Capability/recipient/cryptographic rejection are completed answers, while
/// original processing/resource/backend errors use `Result::Err`.
pub enum Attempt<T> {
    /// The selected provider completed decryption and removed normative padding.
    Decrypted(T),
    /// No selected key/recipient applies to this envelope.
    NotRecipient,
    /// The selected provider cannot process its algorithms/recipient format.
    Unsupported,
    /// The selected provider completed and rejected its ciphertext/key operation.
    Rejected,
}
/// Completed negative plaintext binding. No attribute-use receipt exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// Provider completed without a valid decryption result.
    Decryption,
    /// Actual issuer name differs; ciphertext cannot be transplanted across AAs.
    Issuer,
    /// Full INTEGER differs; ciphertext cannot be transplanted across ACs.
    Serial,
}
/// One original envelope's complete result, preserving unavailable versus false.
#[derive(Debug)]
pub enum Outcome<T> {
    /// Bound plaintext was delivered once; R owns any explicitly retained output.
    Processed(T),
    /// No selected recipient applies, without trying another engine implicitly.
    NotRecipient,
    /// Unsupported is neither malformed plaintext nor an empty successful set.
    Unsupported,
    /// Complete negative answer, without a successful plaintext prefix.
    Rejected(Rejection),
}
/// Logical plaintext context retained independently of temporary decrypted bytes.
/// `envelope` is in the enclosing AC's source coordinates. Any error produced by
/// the plaintext reader uses zero-based plaintext coordinates, not that source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlaintextSource {
    /// Original independent encAttrs value ordinal.
    pub value: usize,
    /// Whole original `EnvelopedData` enclosure; no inner offset projection exists.
    pub envelope: Span,
}
/// Terminal refusal, preserving the callback cause and its honest source space.
#[derive(Debug)]
pub enum DecryptError<P, V> {
    /// Original AC/source/current-operation refusal (not plaintext coordinates).
    Processing(Error),
    /// Selected provider's unchanged cause at this original envelope.
    Provider {
        /// Original encrypted source range.
        envelope: Span,
        /// Unchanged provider/source/resource cause.
        cause: P,
    },
    /// Plaintext syntax/resource refusal in the explicitly marked logical space.
    Plaintext {
        /// Unchanged located common failure; its offset is plaintext-relative.
        cause: Error,
        /// Original encrypted enclosure and coordinate discriminator.
        source: PlaintextSource,
    },
    /// Visitor's unchanged error, never swallowed after successful decryption.
    Visitor {
        /// Caller-controlled error; reader-derived offsets use plaintext space.
        cause: V,
        /// Same original enclosure and explicit logical-source context.
        source: PlaintextSource,
    },
}
/// Temporarily bound plaintext. Its type cannot escape the callback, and a
/// readable-but-unbound `ACClearAttrs` cannot be passed in its place.
pub struct Bound<'s> {
    clear: ClearAttrs<'s>,
    attributes: OwnedVec<AttributeUse>,
    source: PlaintextSource,
}
impl Bound<'_> {
    /// Every original decrypted attribute, including duplicate types.
    #[must_use]
    pub fn clear(&self) -> &ClearAttrs<'_> {
        &self.clear
    }
    /// One original AA-control answer per decrypted attribute, in source order.
    #[must_use]
    pub fn attributes(&self) -> &[AttributeUse] {
        &self.attributes
    }
    /// Explicit encrypted enclosure/zero-based plaintext coordinate context.
    #[must_use]
    pub fn source(&self) -> PlaintextSource {
        self.source
    }
}
/// Complete catalogue of independent original targeted envelopes. Reading all
/// values precedes the first provider call, so malformed later metadata cannot
/// leave a successful decrypted prefix. It authenticates no AC on its own.
pub struct Encrypted<'r, 'a> {
    certificate: &'r AttributeCertificate<'a>,
    envelopes: OwnedVec<EnvelopedData<'a>>,
}
impl<'r, 'a> Encrypted<'r, 'a> {
    /// Read the original unique encAttrs attribute's entire value set. Returns
    /// None only when this actual AC has no such attribute. Same producing
    /// Parser is required before lookup/work, not merely the same account.
    pub fn read(
        certificate: &'r AttributeCertificate<'a>,
        parent: &Reader<'a>,
    ) -> Result<Option<Self>> {
        if !core::ptr::eq(certificate.parser, parent.parser()) {
            return Err(Error::pkix(structured_pkix::Error::new(
                structured_pkix::ErrorCode::ForeignReader,
                FIELD,
                certificate.element().span().start,
            )));
        }
        let work = parent.execution();
        let mut selected = None;
        for attribute in &certificate.information().attributes {
            work.charge_work(1)
                .map_err(|e| Error::resource(e, FIELD, attribute.span().start))?;
            if attribute.kind().as_bytes().len() != IDENTIFIER.as_bytes().len() {
                continue;
            }
            work.charge_work(IDENTIFIER.as_bytes().len() as u64)
                .map_err(|e| Error::resource(e, FIELD, attribute.span().start))?;
            if attribute.kind() == IDENTIFIER {
                selected = Some(attribute);
                break;
            }
        }
        let Some(attribute) = selected else {
            return Ok(None);
        };
        let mut envelopes = work.vector();
        envelopes
            .try_reserve_exact(attribute.values().len())
            .map_err(|e| Error::resource(e, FIELD, attribute.span().start))?;
        for ordinal in 0..attribute.values().len() {
            let mut reader = attribute
                .value_reader_in(ordinal, parent, FIELD)?
                .ok_or_else(|| {
                    Error::schema(ErrorCode::InvalidLocation, FIELD, attribute.span().start)
                })?;
            let envelope = EnvelopedData::read(&mut reader)?;
            oid_is(
                envelope.content.kind,
                CONTENT_TYPE,
                &reader,
                FIELD,
                envelope.element().span().start,
            )?;
            if envelope.content.ciphertext.is_none() {
                return Err(Error::schema(
                    ErrorCode::DetachedContent,
                    FIELD,
                    envelope.element().span().start,
                ));
            }
            envelopes
                .try_push(envelope)
                .map_err(|e| Error::resource(e, FIELD, attribute.span().start))?;
        }
        Ok(Some(Self {
            certificate,
            envelopes: envelopes.into_owned(),
        }))
    }
    /// All original envelopes. Caller inspection of borrowed metadata/bytes must
    /// account its own scans; `decrypt_all` admits all of its own traversal.
    #[must_use]
    pub fn envelopes(&self) -> &[EnvelopedData<'a>] {
        &self.envelopes
    }

    /// Process every independent value through the selected provider and a
    /// scoped visitor. Decryption receives original fragmented ciphertext and
    /// must admit its backend work/output through the supplied Execution. The
    /// returned owned plaintext must belong to that same operation account.
    ///
    /// DER parsing inherits the actual ciphertext's original depth and source
    /// and operation ceilings, without a new `Parser` or copied-buffer reset.
    /// Plaintext and parsed models are dropped after the visitor. R/V/P cannot
    /// borrow these temporary values. A late error drops all retained R/results;
    /// external provider/visitor side effects cannot be rolled back.
    ///
    /// The visitor cannot return a borrowed plaintext view. Its higher-ranked
    /// scope is the same restriction illustrated here:
    /// ```compile_fail
    /// use structured_cms::attribute_certificate::encrypted::Bound;
    /// fn scoped<R>(_: impl for<'s> Fn(&Bound<'s>) -> R) {}
    /// scoped(|bound| bound.clear().element().as_bytes());
    /// ```
    pub fn decrypt_all<'p, 'd, 'c, S, P, V, R>(
        &self,
        checked: &Checked<'_, 'p, 'd, 'c, S>,
        parent: &Reader<'_>,
        mut provider: impl FnMut(
            &EnvelopedData<'a>,
            &Execution<'_>,
        ) -> core::result::Result<Attempt<OwnedVec<u8>>, P>,
        mut visitor: impl for<'scope> FnMut(
            &Bound<'scope>,
            &Execution<'_>,
        ) -> core::result::Result<R, V>,
    ) -> core::result::Result<OwnedVec<Outcome<R>>, DecryptError<P, V>> {
        let physical = DecryptError::Processing;
        if !core::ptr::eq(self.certificate.parser, parent.parser())
            || !core::ptr::eq(self.certificate, checked.certificate())
        {
            return Err(physical(Error::schema(
                ErrorCode::InvalidLocation,
                FIELD,
                self.certificate.element().span().start,
            )));
        }
        let work = parent.execution();
        let mut results = work.vector();
        results
            .try_reserve_exact(self.envelopes.len())
            .map_err(|e| {
                physical(Error::resource(
                    e,
                    FIELD,
                    self.certificate.element().span().start,
                ))
            })?;
        for (ordinal, envelope) in self.envelopes.iter().enumerate() {
            work.charge_work(1).map_err(|e| {
                physical(Error::resource(e, FIELD, envelope.element().span().start))
            })?;
            let output = provider(envelope, &work).map_err(|cause| DecryptError::Provider {
                envelope: envelope.element().span(),
                cause,
            })?;
            let outcome = match output {
                Attempt::NotRecipient => Outcome::NotRecipient,
                Attempt::Unsupported => Outcome::Unsupported,
                Attempt::Rejected => Outcome::Rejected(Rejection::Decryption),
                Attempt::Decrypted(bytes) => {
                    if !bytes.memory().same_account(parent.memory()) {
                        return Err(physical(Error::schema(
                            ErrorCode::InvalidLocation,
                            FIELD,
                            envelope.element().span().start,
                        )));
                    }
                    self.visit(checked, parent, envelope, ordinal, &bytes, &mut visitor)?
                }
            };
            results.try_push(outcome).map_err(|e| {
                physical(Error::resource(e, FIELD, envelope.element().span().start))
            })?;
        }
        Ok(results.into_owned())
    }

    fn visit<'p, 'd, 'c, S, P, V, R>(
        &self,
        checked: &Checked<'_, 'p, 'd, 'c, S>,
        parent: &Reader<'_>,
        envelope: &EnvelopedData<'a>,
        ordinal: usize,
        bytes: &[u8],
        visitor: &mut impl for<'scope> FnMut(
            &Bound<'scope>,
            &Execution<'_>,
        ) -> core::result::Result<R, V>,
    ) -> core::result::Result<Outcome<R>, DecryptError<P, V>> {
        let source = PlaintextSource {
            value: ordinal,
            envelope: envelope.element().span(),
        };
        let logical = |cause| DecryptError::Plaintext { cause, source };
        // The ciphertext was required in the complete preflight, and no mutable
        // envelope access is exposed by Encrypted. It contributes its actual
        // nested source level, just as other carried ASN.1 payloads do.
        let ciphertext = envelope
            .content
            .ciphertext
            .as_ref()
            .expect("encAttrs requires attached ciphertext");
        let mut reader = self
            .certificate
            .parser
            .read_nested_query_in(parent, bytes, 0, Encoding::Der, ciphertext.outer_depth())
            .map_err(|e| logical(Error::encoding(e, CLEAR)))?;
        let clear = ClearAttrs::read(&mut reader).map_err(logical)?;
        let work = reader.execution();
        let ac = self.certificate;
        work.charge_work(3)
            .map_err(|e| logical(Error::resource(e, CLEAR, clear.element.span().start)))?;
        let left = clear.serial.as_bytes();
        let right = ac.information().serial.as_bytes();
        // Both are checked DER INTEGERs. Exact minimal two's-complement octets
        // therefore implement full numeric equality, including wide/negative
        // values, without a scalar projection or sentinel.
        if left.len() != right.len() {
            return Ok(Outcome::Rejected(Rejection::Serial));
        }
        work.charge_work(left.len() as u64 + right.len() as u64)
            .map_err(|e| {
                logical(Error::resource(
                    e,
                    "acClearAttrs.acSerial",
                    clear.element.span().start,
                ))
            })?;
        if left != right {
            return Ok(Outcome::Rejected(Rejection::Serial));
        }
        // A successful original RFC5755 profile has exactly one issuer DN.
        // Prepare operands separately so original-name failures keep physical
        // AC coordinates and plaintext failures stay explicitly logical.
        let Some([GeneralName::Directory(actual)]) = ac.information().issuer.names.as_deref()
        else {
            unreachable!("authenticated profile restricts issuer to one directoryName")
        };
        let GeneralName::Directory(claimed) = &clear.issuer else {
            return Ok(Outcome::Rejected(Rejection::Issuer));
        };
        let actual = actual
            .ordered(&work)
            .map_err(|e| DecryptError::Processing(Error::pkix(e)))?;
        let claimed = claimed
            .ordered_in(&reader)
            .map_err(|e| logical(Error::pkix(e)))?;
        if claimed
            .order(&actual, &work)
            .map_err(|e| logical(Error::pkix(e)))?
            != core::cmp::Ordering::Equal
        {
            return Ok(Outcome::Rejected(Rejection::Issuer));
        }
        let mut attributes = work.vector();
        attributes
            .try_reserve_exact(clear.attributes.len())
            .map_err(|e| logical(Error::resource(e, CLEAR, clear.element.span().start)))?;
        for (index, attribute) in clear.attributes.iter().enumerate() {
            work.charge_work(1)
                .map_err(|e| logical(Error::resource(e, CLEAR, attribute.span().start)))?;
            // AA-control failures originate in the original authenticated AA
            // source, not in a guessed plaintext-to-ciphertext mapping.
            let permission = checked
                .allows(attribute.kind(), &work)
                .map_err(DecryptError::Processing)?;
            attributes
                .try_push(AttributeUse { index, permission })
                .map_err(|e| logical(Error::resource(e, CLEAR, attribute.span().start)))?;
        }
        let bound = Bound {
            clear,
            attributes: attributes.into_owned(),
            source,
        };
        let output =
            visitor(&bound, &work).map_err(|cause| DecryptError::Visitor { cause, source })?;
        Ok(Outcome::Processed(output))
    }
}
fn end(parent: &Reader<'_>) -> Result<()> {
    if parent.is_empty() {
        Ok(())
    } else {
        Err(Error::schema(
            ErrorCode::TrailingData,
            CLEAR,
            parent.offset(),
        ))
    }
}
