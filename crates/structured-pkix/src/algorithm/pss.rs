//! Borrowed RSASSA-PSS parameters, without selecting a cryptographic provider.
//!
//! RFC4055 §3.1 distinguishes absent key restrictions from absent signature
//! parameters. [`read_in`] preserves absence; its caller applies that role rule.
//! Hash/MGF support, key sanity, salt bounds and signature verification remain
//! with the selected provider. No replacement parser or encoded default is made.
//! Retained identifiers use [`read`] or [`inspect`] under current execution;
//! [`read_in`] and [`inspect_in`] additionally check a producing reader session.

use super::AlgorithmIdentifier;
use crate::error::{Error, ErrorCode, Located, Result};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{Element, Integer, Oid, ScopedReader as Reader, Tag, universal};

use crate::oid::SHA1;
pub mod profile;
const MGF1: Oid<'static> = Oid::from_bytes(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 8]);
const FIELD: &str = "algorithm.pss";

/// An explicitly written field with its original EXPLICIT wrapper.
#[derive(Debug, Clone, Copy)]
pub struct Written<'a, T> {
    element: Element<'a>,
    value: T,
}

impl<'a, T: Copy> Written<'a, T> {
    /// Original context-specific wrapper, including its source span.
    #[must_use]
    pub fn element(self) -> Element<'a> {
        self.element
    }

    /// Decoded borrowed value, without re-encoding the field.
    #[must_use]
    pub fn value(self) -> T {
        self.value
    }
}

/// A numeric field, distinguishing omission from an explicit value.
#[derive(Debug, Clone, Copy)]
pub enum Number<'a> {
    /// The schema's omitted value (salt 20 or trailer 1).
    Default(u64),
    /// An arbitrary-width original INTEGER, including its sign.
    Written(Written<'a, Integer<'a>>),
}

impl Number<'_> {
    /// Bounded numeric projection; negative/wider values remain `None`.
    #[must_use]
    pub fn as_u64(self) -> Option<u64> {
        match self {
            Self::Default(value) => Some(value),
            Self::Written(value) => value.value.as_u64(),
        }
    }
}

/// The mask function and, for the defined MGF1 schema, its original hash.
#[derive(Debug, Clone, Copy)]
pub enum Mask<'a> {
    /// Omitted maskGenAlgorithm means MGF1 with SHA-1.
    DefaultMgf1Sha1,
    /// Written MGF1 requires a hash `AlgorithmIdentifier` parameter.
    Mgf1 {
        /// Original explicit mask field and function identifier.
        function: Written<'a, AlgorithmIdentifier<'a>>,
        /// Original nested hash identifier, not a manufactured default.
        hash: AlgorithmIdentifier<'a>,
    },
    /// Another mask function, retaining opaque parameters for its provider.
    Other(Written<'a, AlgorithmIdentifier<'a>>),
}

/// Original PSS schema values, not algorithm support or signature validity.
#[derive(Debug, Clone, Copy)]
pub struct Parameters<'a> {
    parser: &'a structured_asn1::Parser,
    element: Element<'a>,
    hash: Option<Written<'a, AlgorithmIdentifier<'a>>>,
    mask: Mask<'a>,
    salt: Number<'a>,
    trailer: Number<'a>,
    defaults: u8,
}

impl<'a> Parameters<'a> {
    /// Complete original parameter SEQUENCE, without copies or normalization.
    #[must_use]
    pub fn element(self) -> Element<'a> {
        self.element
    }

    /// Written hash identifier; `None` is the schema's SHA-1 default.
    #[must_use]
    pub fn hash(self) -> Option<Written<'a, AlgorithmIdentifier<'a>>> {
        self.hash
    }

    /// Mask identity and original MGF1 hash, including omitted default.
    #[must_use]
    pub fn mask(self) -> Mask<'a> {
        self.mask
    }

    /// Original written fields equal to their ASN.1 DEFAULT values.
    /// The shared decoder decides this once, including the exact SHA-1 NULL
    /// default. A DER encoder omits these whole EXPLICIT wrappers (X.690
    /// §11.5); algorithm-support/default resolution remains independent.
    pub fn written_defaults(self) -> impl Iterator<Item = Element<'a>> {
        let hash = self.hash.map(Written::element);
        let mask = match self.mask {
            Mask::Mgf1 { function, .. } | Mask::Other(function) => Some(function.element()),
            Mask::DefaultMgf1Sha1 => None,
        };
        let salt = match self.salt {
            Number::Written(value) => Some(value.element()),
            Number::Default(_) => None,
        };
        let trailer = match self.trailer {
            Number::Written(value) => Some(value.element()),
            Number::Default(_) => None,
        };
        [hash, mask, salt, trailer]
            .into_iter()
            .enumerate()
            .filter_map(move |(number, element)| {
                if self.defaults & (1 << number) != 0 {
                    element
                } else {
                    None
                }
            })
    }

    /// Salt octet length (default 20, independently of the selected hash).
    /// Its applicability as an exact signature length or key minimum is a
    /// caller role decision (RFC4055 §3.3); no backend maximum is imposed here.
    #[must_use]
    pub fn salt(self) -> Number<'a> {
        self.salt
    }

    /// Trailer number (default 1). Other numbers are retained for inspection;
    /// RFC8017 A.2.3 defines support only for trailer 1, not other schemes.
    #[must_use]
    pub fn trailer(self) -> Number<'a> {
        self.trailer
    }
}

/// Readable fields and retained encoding diagnostics, not conforming evidence.
#[derive(Debug)]
pub struct Reading<'a> {
    parameters: Parameters<'a>,
    faults: OwnedVec<Error>,
}

impl<'a> Reading<'a> {
    /// Unmodified original fields, even when their spelling has a diagnostic.
    #[must_use]
    pub fn parameters(&self) -> Parameters<'a> {
        self.parameters
    }

    /// Located DER DEFAULT spelling diagnostics.
    /// Resource and foreign-reader failures are terminal errors, never faults.
    #[must_use]
    pub fn faults(&self) -> &[Error] {
        &self.faults
    }
}

/// Reads present PSS parameters in the producing session; preserves absence.
///
/// Callers reject absent signature parameters but may accept an unrestricted
/// PSS key (RFC4055 §3.1). This function does neither role selection nor policy.
/// Original encoding, offsets, depth and local/current work ceilings survive.
///
/// ```
/// use std::sync::Arc;
/// use structured_asn1::{Parser, memory::{Memory, MemoryAccount}};
/// use structured_pkix::algorithm::{self, pss};
/// let parser = Parser::der(Memory::new(Arc::new(MemoryAccount::new(4096, 4096))));
/// let bytes = b"\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a\x30\x00";
/// let mut reader = parser.read(bytes, 400).unwrap();
/// let element = reader.next_element().unwrap().unwrap();
/// let algorithm = algorithm::read(&reader, &element, "signatureAlgorithm")?;
/// let parameters = pss::read_in(algorithm, &reader)?.unwrap();
/// assert!(parameters.hash().is_none());
/// assert_eq!(parameters.salt().as_u64(), Some(20));
/// assert_eq!(parameters.element().span().start, 413);
/// # Ok::<(), structured_pkix::Error>(())
/// ```
pub fn read_in<'a>(
    identifier: AlgorithmIdentifier<'a>,
    parent: &Reader<'a, '_>,
) -> Result<Option<Parameters<'a>>> {
    require_session(identifier, parent)?;
    read(identifier, &parent.execution())
}

/// Inspection counterpart of [`read_in`], sharing its schema kernel.
///
/// RFC4055 §3.1 requires recognizing explicitly written defaults during
/// verification. Inspection therefore retains those values plus a DER spelling
/// fault (X.690 §11.5), rather than losing the algorithm's meaning. BER permits
/// written defaults. Neither operation verifies a signature or accepts a key.
/// <https://www.rfc-editor.org/rfc/rfc4055#section-3.1>
pub fn inspect_in<'a>(
    identifier: AlgorithmIdentifier<'a>,
    parent: &Reader<'a, '_>,
) -> Result<Option<Reading<'a>>> {
    require_session(identifier, parent)?;
    inspect(identifier, &parent.execution())
}

/// Reads a retained identifier's original PSS parameters under current work.
///
/// For verification callbacks that retain an [`AlgorithmIdentifier`] without
/// its former reader. Source parser, encoding, parameter depth and cumulative
/// ceiling come from that identifier; `execution` supplies current funding and
/// its root-operation ceiling. No reader is fabricated and no parser, resource
/// account, parameter copy or default encoding is created.
///
/// Like [`read_in`], returns `None` for absent parameters. RFC4055 §3.1 and
/// RFC5756 §2 require signature parameters, while absent PSS key parameters
/// mean unrestricted PSS usage; that role is the caller's decision. Use the
/// key's original algorithm identifier: absent PSS restrictions do not inherit
/// from another certificate (RFC4055 §3.3). No backend acceptance is implied.
/// <https://www.rfc-editor.org/rfc/rfc5756#section-2>
///
/// # Errors
/// Reports located schema/encoding errors, including written DER defaults,
/// separately from terminal source/current work, depth or storage refusal.
/// Returned scalar views borrow the original source, not current execution.
///
/// # Examples
/// ```
/// use std::sync::Arc;
/// use structured_asn1::{Parser, memory::{Memory, MemoryAccount}};
/// use structured_pkix::algorithm::{self, pss};
/// let source = Parser::der(Memory::new(Arc::new(MemoryAccount::new(4096, 4096))));
/// let bytes = b"\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a\x30\x00";
/// let identifier = {
///     let mut reader = source.read(bytes, 400).unwrap();
///     let element = reader.next_element().unwrap().unwrap();
///     algorithm::read(&reader, &element, "signatureAlgorithm")?
/// };
/// let current = Memory::new(Arc::new(MemoryAccount::new(4096, 4096)));
/// let parameters = pss::read(identifier, &current)?.unwrap();
/// assert_eq!(parameters.element().span().start, 413);
/// assert_eq!(parameters.salt().as_u64(), Some(20));
/// # Ok::<(), structured_pkix::Error>(())
/// ```
pub fn read<'a, W: Work>(
    identifier: AlgorithmIdentifier<'a>,
    execution: &W,
) -> Result<Option<Parameters<'a>>> {
    require_algorithm(identifier, execution)?;
    read_known(identifier, execution)
}

// Only a caller that has already paid for and classified the PSS OID may skip
// this check (signature classification or key-restriction interpretation).
// Parameter traversal still uses the same source/current schema kernel.
pub(super) fn read_known<'a, W: Work>(
    identifier: AlgorithmIdentifier<'a>,
    execution: &W,
) -> Result<Option<Parameters<'a>>> {
    let Some((reader, element)) = open_parameters(identifier, execution)? else {
        return Ok(None);
    };
    decode(&reader, element, Err).map(Some)
}

/// Inspects retained PSS parameters through the same kernel as [`read`].
///
/// Readable DER DEFAULT spelling faults are retained on the current storage
/// account. All diagnostic admission also obeys the original and current work
/// ceilings. The result can outlive the temporary operation; its fields still
/// borrow the original source and its diagnostic capacity stays charged until
/// dropped. Resource failures never become missing faults or successful absence.
///
/// # Examples
/// ```
/// use std::sync::Arc;
/// use structured_asn1::{Parser, memory::{Memory, MemoryAccount}};
/// use structured_pkix::{ErrorCode, algorithm::{self, pss}};
/// let source = Parser::der(Memory::new(Arc::new(MemoryAccount::new(4096, 4096))));
/// let bytes = b"\x30\x12\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a\x30\x05\xa2\x03\x02\x01\x14";
/// let mut reader = source.read(bytes, 400).unwrap();
/// let element = reader.next_element().unwrap().unwrap();
/// let identifier = algorithm::read(&reader, &element, "signatureAlgorithm")?;
/// let current = Memory::new(Arc::new(MemoryAccount::new(4096, 4096)));
/// let reading = pss::inspect(identifier, &current)?.unwrap();
/// assert_eq!(reading.parameters().salt().as_u64(), Some(20));
/// assert_eq!(reading.faults()[0].code(), ErrorCode::DefaultWritten);
/// # Ok::<(), structured_pkix::Error>(())
/// ```
pub fn inspect<'a, W: Work>(
    identifier: AlgorithmIdentifier<'a>,
    execution: &W,
) -> Result<Option<Reading<'a>>> {
    require_algorithm(identifier, execution)?;
    let Some((reader, element)) = open_parameters(identifier, execution)? else {
        return Ok(None);
    };
    let query = identifier.query_in(execution);
    let mut faults = query.vector();
    let parameters = decode(&reader, element, |fault| {
        let at = fault.offset();
        let field = fault.field();
        faults
            .try_push(fault)
            .map_err(|reason| Error::resource(reason, field, at))
    })?;
    Ok(Some(Reading {
        parameters,
        faults: faults.into_owned(),
    }))
}

fn require_algorithm<W: Work>(identifier: AlgorithmIdentifier<'_>, execution: &W) -> Result<()> {
    let query = identifier.query_in(execution);
    if !crate::key::same_oid(
        identifier.algorithm(),
        crate::oid::RSASSA_PSS,
        &query,
        FIELD,
        identifier.offset(),
    )? {
        return Err(Error::new(
            ErrorCode::UnexpectedField,
            FIELD,
            identifier.offset(),
        ));
    }
    Ok(())
}

fn open_parameters<'a: 'operation, 'operation, W: Work>(
    identifier: AlgorithmIdentifier<'a>,
    execution: &'operation W,
) -> Result<Option<(Reader<'a, 'operation>, Element<'a>)>> {
    let query = identifier.query_in(execution);
    query
        .charge_work(1)
        .map_err(|reason| Error::resource(reason, FIELD, identifier.offset()))?;
    let value = identifier
        .parameters_nested()
        .map(|parameters| parameters.open(execution, FIELD))
        .transpose()?;
    if let Some((_, element)) = &value
        && element.tag() != Tag::constructed(universal::SEQUENCE)
    {
        return Err(Error::new(
            ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag),
            FIELD,
            element.span().start,
        ));
    }
    Ok(value)
}

fn require_session(identifier: AlgorithmIdentifier<'_>, parent: &Reader<'_, '_>) -> Result<()> {
    if !identifier.same_session(parent) {
        return Err(Error::new(
            ErrorCode::ForeignReader,
            FIELD,
            identifier.offset(),
        ));
    }
    Ok(())
}

fn open_parameter<'a: 'operation, 'operation, W: Work>(
    identifier: AlgorithmIdentifier<'a>,
    parent: &Reader<'a, '_>,
    execution: &'operation W,
    field: &'static str,
) -> Result<Option<(Reader<'a, 'operation>, Element<'a>)>> {
    charge(parent, 1, identifier.offset())?;
    let Some(parameters) = identifier.parameters_nested() else {
        return Ok(None);
    };
    parameters.open(execution, field).map(Some)
}

fn decode<'a>(
    parent: &Reader<'a, '_>,
    element: Element<'a>,
    mut fault: impl FnMut(Error) -> Result<()>,
) -> Result<Parameters<'a>> {
    let mut fields = parent.enter(&element).field(FIELD)?;
    let mut parameters = Parameters {
        parser: parent.parser(),
        element,
        hash: None,
        mask: Mask::DefaultMgf1Sha1,
        salt: Number::Default(20),
        trailer: Number::Default(1),
        defaults: 0,
    };
    let mut previous = None;
    while let Some(element) = fields.next_element().field(FIELD)? {
        fields.charge(1).field(FIELD)?;
        let Some(number) = element.tag().number() else {
            return Err(Error::new(
                ErrorCode::UnexpectedField,
                FIELD,
                element.span().start,
            ));
        };
        if number > 3
            || element.tag() != Tag::context(true, number)
            || previous.is_some_and(|last| number <= last)
        {
            return Err(Error::new(
                ErrorCode::UnexpectedField,
                FIELD,
                element.span().start,
            ));
        }
        previous = Some(number);
        let mut inside = fields.enter(&element).field(FIELD)?;
        let value = inside
            .next_element()
            .field(FIELD)?
            .ok_or_else(|| Error::new(ErrorCode::MissingField, FIELD, inside.offset()))?;
        if !inside.is_empty() {
            return Err(Error::new(ErrorCode::TrailingData, FIELD, inside.offset()));
        }
        let defaulted = match number {
            0 => {
                let hash = super::read(&inside, &value, "algorithm.pss.hash")?;
                parameters.hash = Some(Written {
                    element,
                    value: hash,
                });
                default_hash(&inside, hash)?
            }
            1 => {
                let (mask, defaulted) = read_mask(&inside, element, value)?;
                parameters.mask = mask;
                defaulted
            }
            _ => {
                if value.tag() != Tag::primitive(universal::INTEGER) {
                    return Err(Error::new(
                        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag),
                        FIELD,
                        value.span().start,
                    ));
                }
                let integer = inside.integer(&value).field(FIELD)?;
                if number == 2 && integer.is_negative() {
                    return Err(Error::new(
                        ErrorCode::MalformedValue,
                        FIELD,
                        value.span().start,
                    ));
                }
                charge(&inside, 9, value.span().start)?;
                let written = Number::Written(Written {
                    element,
                    value: integer,
                });
                if number == 2 {
                    parameters.salt = written;
                    integer.as_u64() == Some(20)
                } else {
                    parameters.trailer = written;
                    integer.as_u64() == Some(1)
                }
            }
        };
        // X.690 §11.5 restricts DER spelling, independently of RFC4055's
        // requirement that verification recognize explicit default values.
        // https://www.itu.int/rec/T-REC-X.690-202102-I/en
        if defaulted {
            parameters.defaults |= 1 << number;
        }
        if defaulted && fields.encoding().is_der() {
            fault(Error::new(
                ErrorCode::DefaultWritten,
                FIELD,
                element.span().start,
            ))?;
        }
    }
    Ok(parameters)
}

fn default_hash(parent: &Reader<'_, '_>, identifier: AlgorithmIdentifier<'_>) -> Result<bool> {
    // RFC4055 §§2.1/6 defines the ASN.1 sha1Identifier DEFAULT with NULL.
    // Absent parameters have equivalent algorithm semantics but are a
    // distinct ASN.1 value; do not manufacture NULL for X.690 §11.5.
    // https://www.rfc-editor.org/rfc/rfc4055#section-2.1
    Ok(
        oid_is(parent, identifier.algorithm(), SHA1, identifier.offset())?
            && identifier.has_null_parameter(),
    )
}

fn oid_is(parent: &Reader<'_, '_>, left: Oid<'_>, right: Oid<'_>, at: u64) -> Result<bool> {
    charge(parent, 1, at)?;
    if left.as_bytes().len() != right.as_bytes().len() {
        return Ok(false);
    }
    charge(parent, left.as_bytes().len() as u64, at)?;
    Ok(left == right)
}

fn charge(parent: &Reader<'_, '_>, amount: u64, at: u64) -> Result<()> {
    parent
        .charge(amount)
        .map_err(|error| Error::new(ErrorCode::Encoding(error.code()), FIELD, at))
}

fn read_mask<'a>(
    parent: &Reader<'a, '_>,
    element: Element<'a>,
    value: Element<'a>,
) -> Result<(Mask<'a>, bool)> {
    let algorithm = super::read(parent, &value, "algorithm.pss.mask")?;
    let function = Written {
        element,
        value: algorithm,
    };
    if !oid_is(parent, algorithm.algorithm(), MGF1, algorithm.offset())? {
        return Ok((Mask::Other(function), false));
    }
    let execution = parent.execution();
    let (reader, element) =
        open_parameter(algorithm, parent, &execution, "algorithm.pss.mask.hash")?.ok_or_else(
            || {
                Error::new(
                    ErrorCode::MissingField,
                    "algorithm.pss.mask.hash",
                    algorithm.offset(),
                )
            },
        )?;
    let hash = super::read(&reader, &element, "algorithm.pss.mask.hash")?;
    Ok((Mask::Mgf1 { function, hash }, default_hash(&reader, hash)?))
}
