//! One recipient schema; all algorithm/key decisions remain explicit callbacks.
use super::{EncodedValue, algorithm, end, enter, number, tag, version};
use crate::{
    Error, ErrorCode, Octets, Result,
    signer::{SignerIdentifier, required},
};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{Element, Oid, Reader, Tag, universal};
use structured_pkix::AlgorithmIdentifier;

const FIELD: &str = "envelopedData.recipientInfos";

/// Common KEK/recipient key identifier and its original optional metadata.
#[derive(Debug)]
pub struct KeyIdentifier<'a> {
    identifier: Octets<'a>,
    date: Option<Element<'a>>,
    other: Option<(Oid<'a>, Option<Element<'a>>)>,
    encoding: structured_asn1::Encoding,
}

/// All three sender-key choices of RFC5652 §6.2.2.
#[derive(Debug)]
pub enum Originator<'a> {
    /// Original issuer/serial or subject-key identifier, not a trusted signer.
    Identifier(SignerIdentifier<'a>),
    /// Uncertified sender key. Bits preserve their original primitive or BER
    /// constructed encoding; the common ASN.1 string walker validated them.
    Key {
        /// Original algorithm, including parameter provenance.
        algorithm: AlgorithmIdentifier<'a>,
        /// Original validated BIT STRING, not a fabricated SPKI.
        bits: EncodedValue<'a>,
    },
}
/// One key-agreement recipient's actual certificate identifier and encrypted key.
#[derive(Debug)]
pub struct RecipientKey<'a> {
    /// Original issuer/serial or full recipient-key identifier.
    pub identifier: AgreementIdentifier<'a>,
    /// Original encrypted content-encryption key.
    pub encrypted: Octets<'a>,
}
/// Both key-agreement recipient-identifier alternatives (§6.2.2).
#[derive(Debug)]
pub enum AgreementIdentifier<'a> {
    /// Original issuer DN and serial, using the same CMS identity kernel.
    IssuerAndSerial(SignerIdentifier<'a>),
    /// `[0] IMPLICIT RecipientKeyIdentifier`, including date/other metadata.
    KeyIdentifier(KeyIdentifier<'a>),
}
/// All five CMS `RecipientInfo` alternatives, without engine dispatch or key lookup.
#[derive(Debug)]
pub enum Recipient<'a> {
    /// Public-key transport (§6.2.1); version is 0 for issuer/serial, 2 for SKI.
    Transport {
        /// Declared version, checked against the identifier alternative.
        version: u64,
        /// Original selected recipient identity; never an implicit key hint.
        identifier: SignerIdentifier<'a>,
        /// Actual key-encryption algorithm and original parameters.
        algorithm: AlgorithmIdentifier<'a>,
        /// Original encrypted content-encryption key.
        encrypted: Octets<'a>,
    },
    /// Key agreement (§6.2.2), always version3.
    Agreement {
        /// Original sender-key alternative.
        originator: Originator<'a>,
        /// Optional explicit user-keying material; absence stays distinct.
        ukm: Option<Octets<'a>>,
        /// Original key-encryption algorithm.
        algorithm: AlgorithmIdentifier<'a>,
        /// All original recipient encrypted keys, not just the first.
        keys: OwnedVec<RecipientKey<'a>>,
    },
    /// Pre-distributed symmetric KEK (§6.2.3), always version4.
    Kek {
        /// Original KEK identifier, date and additional open value.
        identifier: KeyIdentifier<'a>,
        /// Original key-encryption algorithm.
        algorithm: AlgorithmIdentifier<'a>,
        /// Original encrypted content-encryption key.
        encrypted: Octets<'a>,
    },
    /// Password/shared-secret recipient (§6.2.4), always version0.
    Password {
        /// Optional original `[0] IMPLICIT` key derivation algorithm. Absence
        /// means externally supplied KEK, not an invented default KDF.
        derivation: Option<AlgorithmIdentifier<'a>>,
        /// Original key-encryption algorithm.
        algorithm: AlgorithmIdentifier<'a>,
        /// Original encrypted content-encryption key.
        encrypted: Octets<'a>,
    },
    /// Named open key-management format (§6.2.5), including RFC9629 KEM.
    Other {
        /// Exact format OID. Unknown is not absence or key-transport fallback.
        kind: Oid<'a>,
        /// Whole original open value, to be interpreted by its actual owner.
        value: EncodedValue<'a>,
    },
}
impl<'a> Recipient<'a> {
    pub(super) fn is_transport_zero(&self) -> bool {
        matches!(self, Self::Transport { version: 0, .. })
    }
    pub(super) fn read(parent: &Reader<'a>, element: &Element<'a>) -> Result<Self> {
        let mut inside = enter(parent, element, FIELD)?;
        let result = match element.tag() {
            t if t == Tag::constructed(universal::SEQUENCE) => {
                let (version, at) = number(&mut inside, FIELD)?;
                let value = required(&mut inside, FIELD)?;
                let identifier = SignerIdentifier::read_as(&inside, &value, FIELD)?;
                let expected = if matches!(identifier, SignerIdentifier::IssuerAndSerial { .. }) {
                    0
                } else {
                    2
                };
                if version != expected {
                    return Err(Error::schema(ErrorCode::UnsupportedVersion, FIELD, at));
                }
                let value = required(&mut inside, FIELD)?;
                let algorithm = algorithm(&inside, &value, FIELD)?;
                let encrypted = octets(&mut inside)?;
                Self::Transport {
                    version,
                    identifier,
                    algorithm,
                    encrypted,
                }
            }
            t if t == Tag::context(true, 1) => Self::agreement(parent, &mut inside)?,
            t if t == Tag::context(true, 2) => {
                version(&mut inside, 4, FIELD)?;
                let value = inside
                    .expect(Tag::constructed(universal::SEQUENCE))
                    .map_err(|e| Error::encoding(e, FIELD))?;
                let identifier = KeyIdentifier::read(&inside, &value)?;
                let value = required(&mut inside, FIELD)?;
                let algorithm = algorithm(&inside, &value, FIELD)?;
                let encrypted = octets(&mut inside)?;
                Self::Kek {
                    identifier,
                    algorithm,
                    encrypted,
                }
            }
            t if t == Tag::context(true, 3) => {
                version(&mut inside, 0, FIELD)?;
                let mut value = required(&mut inside, FIELD)?;
                let derivation = if value.tag() == Tag::context(true, 0) {
                    let derivation =
                        structured_pkix::algorithm::read_implicit(&inside, &value, 0, FIELD)
                            .map_err(Error::pkix)?;
                    value = required(&mut inside, FIELD)?;
                    Some(derivation)
                } else {
                    None
                };
                let algorithm = algorithm(&inside, &value, FIELD)?;
                let encrypted = octets(&mut inside)?;
                Self::Password {
                    derivation,
                    algorithm,
                    encrypted,
                }
            }
            t if t == Tag::context(true, 4) => {
                let kind = inside.read_oid().map_err(|e| Error::encoding(e, FIELD))?;
                let value = required(&mut inside, FIELD)?;
                structured_pkix::der::conforms(&inside, &value, FIELD).map_err(Error::pkix)?;
                Self::Other {
                    kind,
                    value: EncodedValue::new(&inside, value),
                }
            }
            _ => {
                return Err(Error::schema(
                    ErrorCode::UnknownField,
                    FIELD,
                    element.span().start,
                ));
            }
        };
        end(&inside, FIELD)?;
        Ok(result)
    }
}
impl<'a> Recipient<'a> {
    fn agreement(parent: &Reader<'a>, inside: &mut Reader<'a>) -> Result<Self> {
        version(inside, 3, FIELD)?;
        let wrapper = inside
            .expect(Tag::context(true, 0))
            .map_err(|e| Error::encoding(e, FIELD))?;
        let mut explicit = enter(inside, &wrapper, FIELD)?;
        let value = required(&mut explicit, FIELD)?;
        let originator = if value.tag() == Tag::context(true, 1) {
            let mut key = enter(&explicit, &value, FIELD)?;
            let value = required(&mut key, FIELD)?;
            let algorithm = algorithm(&key, &value, FIELD)?;
            let bits = required(&mut key, FIELD)?;
            if bits.tag() != Tag::primitive(universal::BIT_STRING)
                && bits.tag() != Tag::constructed(universal::BIT_STRING)
            {
                return Err(Error::schema(
                    ErrorCode::UnexpectedTag,
                    FIELD,
                    bits.span().start,
                ));
            }
            // The common iterative string walker retains the original BER/DER
            // contract and enforces final-fragment padding before provider work.
            structured_pkix::der::conforms(&key, &bits, FIELD).map_err(Error::pkix)?;
            end(&key, FIELD)?;
            Originator::Key {
                algorithm,
                bits: EncodedValue::new(&key, bits),
            }
        } else {
            Originator::Identifier(SignerIdentifier::read_as(&explicit, &value, FIELD)?)
        };
        end(&explicit, FIELD)?;
        let mut value = required(inside, FIELD)?;
        let ukm = if value.tag() == Tag::context(true, 1) {
            let mut explicit = enter(inside, &value, FIELD)?;
            let ukm = octets(&mut explicit)?;
            end(&explicit, FIELD)?;
            value = required(inside, FIELD)?;
            Some(ukm)
        } else {
            None
        };
        let algorithm = algorithm(inside, &value, FIELD)?;
        let set = inside
            .expect(Tag::constructed(universal::SEQUENCE))
            .map_err(|e| Error::encoding(e, FIELD))?;
        let mut members = enter(inside, &set, FIELD)?;
        let work = parent.execution();
        let mut keys = work.vector();
        while let Some(value) = members
            .next_element()
            .map_err(|e| Error::encoding(e, FIELD))?
        {
            keys.try_reserve(1)
                .map_err(|e| Error::resource(e, FIELD, value.span().start))?;
            tag(&value, Tag::constructed(universal::SEQUENCE), FIELD)?;
            let mut entry = enter(&members, &value, FIELD)?;
            let value = required(&mut entry, FIELD)?;
            let identifier = if value.tag() == Tag::context(true, 0) {
                AgreementIdentifier::KeyIdentifier(KeyIdentifier::read(&entry, &value)?)
            } else {
                tag(&value, Tag::constructed(universal::SEQUENCE), FIELD)?;
                AgreementIdentifier::IssuerAndSerial(SignerIdentifier::read_as(
                    &entry, &value, FIELD,
                )?)
            };
            let encrypted = octets(&mut entry)?;
            end(&entry, FIELD)?;
            keys.try_push(RecipientKey {
                identifier,
                encrypted,
            })
            .map_err(|e| Error::resource(e, FIELD, value.span().start))?;
        }
        // RFC5652 §6.2.2 transfers a key to one or more recipients, even though
        // RecipientEncryptedKeys' ASN.1 SEQUENCE OF has no SIZE annotation.
        // https://www.rfc-editor.org/rfc/rfc5652#section-6.2.2
        if keys.is_empty() {
            return Err(Error::schema(
                ErrorCode::MissingField,
                FIELD,
                set.span().start,
            ));
        }
        Ok(Self::Agreement {
            originator,
            ukm,
            algorithm,
            keys: keys.into_owned(),
        })
    }
}
impl<'a> KeyIdentifier<'a> {
    /// Original key identifier octets, preserving constructed BER fragments.
    /// The immutable owner also supplies the optional fields' source context.
    #[must_use]
    pub fn identifier(&self) -> &Octets<'a> {
        &self.identifier
    }
    /// Original optional `GeneralizedTime`, validated under the actual BER/DER
    /// contract. No lossy second/nanosecond projection or key-age policy.
    #[must_use]
    pub fn date(&self) -> Option<EncodedValue<'a>> {
        self.date
            .map(|element| self.encoded(element, self.identifier.outer_depth()))
    }
    /// Original additional key attribute OID and OPTIONAL open value (§10.2.7).
    /// Source metadata is stored once per key identifier, without heap indirection.
    #[must_use]
    pub fn other(&self) -> Option<(Oid<'a>, Option<EncodedValue<'a>>)> {
        self.other.map(|(kind, value)| {
            // A present value was read after a successful enter of its enclosing
            // OtherKeyAttribute; that descent already proved this addition safe.
            let depth = self.identifier.outer_depth();
            debug_assert!(depth < u32::MAX);
            (kind, value.map(|element| self.encoded(element, depth + 1)))
        })
    }
    fn encoded(&self, element: Element<'a>, depth: u32) -> EncodedValue<'a> {
        EncodedValue {
            element,
            parser: self.identifier.parser(),
            encoding: self.encoding,
            depth,
        }
    }
    fn read(parent: &Reader<'a>, element: &Element<'a>) -> Result<Self> {
        let mut inside = enter(parent, element, FIELD)?;
        let identifier = octets(&mut inside)?;
        let mut next = inside
            .next_element()
            .map_err(|e| Error::encoding(e, FIELD))?;
        let date = if let Some(value) = next.as_ref().filter(|e| {
            e.tag().number() == Some(universal::GENERALIZED_TIME)
                && e.tag().class() == structured_asn1::Class::Universal
        }) {
            structured_pkix::der::conforms(&inside, value, FIELD).map_err(Error::pkix)?;
            let time = *value;
            next = inside
                .next_element()
                .map_err(|e| Error::encoding(e, FIELD))?;
            Some(time)
        } else {
            None
        };
        let other = if let Some(value) = next {
            tag(&value, Tag::constructed(universal::SEQUENCE), FIELD)?;
            let mut fields = enter(&inside, &value, FIELD)?;
            let kind = fields.read_oid().map_err(|e| Error::encoding(e, FIELD))?;
            let other = fields
                .next_element()
                .map_err(|e| Error::encoding(e, FIELD))?;
            if let Some(value) = other.as_ref() {
                structured_pkix::der::conforms(&fields, value, FIELD).map_err(Error::pkix)?;
            }
            end(&fields, FIELD)?;
            Some((kind, other))
        } else {
            None
        };
        end(&inside, FIELD)?;
        Ok(Self {
            identifier,
            date,
            other,
            encoding: inside.encoding(),
        })
    }
}
fn octets<'a>(parent: &mut Reader<'a>) -> Result<Octets<'a>> {
    let value = required(parent, FIELD)?;
    Octets::read(parent, &value, FIELD)
}
