//! Original service authentication and access identities (RFC5755 §§4.4.1–4.4.2).
//!
//! These are untrusted assertions until the application validates the AC and
//! authenticates or authorizes its holder. No service is contacted and no
//! service-specific credentials are interpreted, copied or logged here.
//! <https://www.rfc-editor.org/rfc/rfc5755#section-4.4.1>

use super::{end, sequence, tag};
use crate::attribute::Attribute;
use crate::signer::required;
use crate::{Error, ErrorCode, Result};
use core::fmt;
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{Element, Encoding, Oid, ScopedReader, Tag, universal};
use structured_pkix::general_name::{self, GeneralName};

const FIELD: &str = "attributeCertificate.svceAuthInfo";
const SERVICE: &str = "attributeCertificate.svceAuthInfo.service";
const IDENT: &str = "attributeCertificate.svceAuthInfo.ident";
const AUTH: &str = "attributeCertificate.svceAuthInfo.authInfo";

/// `id-aca-authenticationInfo` (1.3.6.1.5.5.7.10.1), RFC5755 §4.4.1.
pub const AUTHENTICATION_INFO: Oid<'static> = Oid::from_bytes(&[43, 6, 1, 5, 5, 7, 10, 1]);
/// `id-aca-accessIdentity` (1.3.6.1.5.5.7.10.2), RFC5755 §4.4.2.
pub const ACCESS_IDENTITY: Oid<'static> = Oid::from_bytes(&[43, 6, 1, 5, 5, 7, 10, 2]);

// Wire registration, not deployment policy or an authentication decision.
#[derive(Clone, Copy)]
enum Syntax {
    Authentication,
    Access,
}

/// A complete DER `SvceAuthInfo`, borrowing original input. Name metadata
/// retains its capacity charge independently of the shorter query. `Debug`
/// prints only source ranges, never names or potential credential bytes.
pub struct SvceAuthInfo<'a> {
    element: Element<'a>,
    service_element: Element<'a>,
    service: GeneralName<'a>,
    ident_element: Element<'a>,
    ident: GeneralName<'a>,
    auth_info: Option<Element<'a>>,
}

impl fmt::Debug for SvceAuthInfo<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // §4.4.1's opaque authInfo can carry a password. Formatting metadata
        // must not implicitly traverse or disclose any original payload.
        formatter
            .debug_struct("SvceAuthInfo")
            .field("element", &self.element.span())
            .field("service", &self.service_element.span())
            .field("ident", &self.ident_element.span())
            .field("auth_info", &self.auth_info.map(Element::span))
            .finish()
    }
}

impl<'a> SvceAuthInfo<'a> {
    /// Reads exactly one standalone value. Optional authInfo is permitted by
    /// this syntax; [`Self::read_attribute`] enforces its registered placement.
    pub fn read(parent: &mut ScopedReader<'a, '_>) -> Result<Self> {
        let element = required(parent, FIELD)?;
        let reading = Self::read_element(parent, &element)?;
        end(parent, FIELD)?;
        Ok(reading)
    }

    /// Reads an original whole value as DER (RFC5755 §4.1), preserving its
    /// source offsets, depth and current execution, without a replacement Parser.
    pub fn read_element(parent: &ScopedReader<'a, '_>, element: &Element<'a>) -> Result<Self> {
        Self::read_fields(parent, element, Syntax::Authentication)
    }

    fn read_fields(
        parent: &ScopedReader<'a, '_>,
        element: &Element<'a>,
        syntax: Syntax,
    ) -> Result<Self> {
        let mut der = parent
            .reread(element, Encoding::Der)
            .map_err(|e| Error::encoding(e, FIELD))?;
        let element = required(&mut der, FIELD)?;
        tag(&element, sequence(), FIELD)?;
        end(&der, FIELD)?;
        let mut inside = der.enter(&element).map_err(|e| Error::encoding(e, FIELD))?;
        let service_element = required(&mut inside, SERVICE)?;
        let ident_element = required(&mut inside, IDENT)?;
        let auth_info = inside
            .next_element()
            .map_err(|e| Error::encoding(e, AUTH))?;
        if let Some(auth) = auth_info {
            tag(&auth, Tag::primitive(universal::OCTET_STRING), AUTH)?;
            // RFC5755 §4.4.2 forbids presence, including an empty OCTET STRING.
            // Apply the registration before Name allocations or any payload use.
            if matches!(syntax, Syntax::Access) {
                return Err(Error::schema(
                    ErrorCode::AttributeSyntax,
                    AUTH,
                    auth.span().start,
                ));
            }
        }
        end(&inside, FIELD)?;
        let service =
            general_name::read(&inside, &service_element, SERVICE).map_err(Error::pkix)?;
        let ident = general_name::read(&inside, &ident_element, IDENT).map_err(Error::pkix)?;
        Ok(Self {
            element,
            service_element,
            service,
            ident_element,
            ident,
            auth_info,
        })
    }

    /// Reads every value of a registered authenticationInfo or accessIdentity
    /// Attribute. Both permit multiple values; empty catalogues refuse. All
    /// original values are checked before success, with no partial catalogue.
    /// accessIdentity forbids authInfo; standalone syntax does not infer that
    /// registration. This establishes neither authentication nor authorization.
    pub fn read_attribute<W: Work>(attribute: &Attribute<'a>, work: &W) -> Result<OwnedVec<Self>> {
        let execution = attribute.query_in(work);
        // Two fixed-width OID comparisons and cardinality metadata. Longer
        // unknown identifiers refuse on length, without an arbitrary scan.
        execution
            .charge_work(17)
            .map_err(|e| Error::resource(e, FIELD, attribute.span().start))?;
        let syntax = if attribute.kind() == AUTHENTICATION_INFO {
            Syntax::Authentication
        } else if attribute.kind() == ACCESS_IDENTITY {
            Syntax::Access
        } else {
            return Err(Error::schema(
                ErrorCode::UnexpectedContentType,
                FIELD,
                attribute.span().start,
            ));
        };
        if attribute.values().is_empty() {
            return Err(Error::schema(
                ErrorCode::AttributeCardinality,
                FIELD,
                attribute.span().start,
            ));
        }
        let mut values = execution.vector();
        values
            .try_reserve_exact(attribute.values().len())
            .map_err(|e| Error::resource(e, FIELD, attribute.span().start))?;
        for index in 0..attribute.values().len() {
            let mut reader = attribute
                .value_reader_scoped(index, &execution, FIELD)?
                .ok_or_else(|| {
                    Error::schema(
                        ErrorCode::AttributeCardinality,
                        FIELD,
                        attribute.span().start,
                    )
                })?;
            let element = required(&mut reader, FIELD)?;
            let value = Self::read_fields(&reader, &element, syntax)?;
            end(&reader, FIELD)?;
            values
                .try_push(value)
                .map_err(|e| Error::resource(e, FIELD, element.span().start))?;
        }
        Ok(values.into_owned())
    }

    /// Original whole value. It may contain sensitive authentication data.
    #[must_use]
    pub fn element(&self) -> Element<'a> {
        self.element
    }
    /// Original decoded service name; no resolution or authentication is done.
    #[must_use]
    pub fn service(&self) -> &GeneralName<'a> {
        &self.service
    }
    /// Original service CHOICE encoding and source range.
    #[must_use]
    pub fn service_element(&self) -> Element<'a> {
        self.service_element
    }
    /// Original decoded holder identifier, not a proven identity.
    #[must_use]
    pub fn ident(&self) -> &GeneralName<'a> {
        &self.ident
    }
    /// Original holder identifier CHOICE encoding and source range.
    #[must_use]
    pub fn ident_element(&self) -> Element<'a> {
        self.ident_element
    }
    /// Original opaque authentication bytes, without interpreting or copying
    /// them. None differs from a present empty OCTET STRING.
    #[must_use]
    pub fn auth_info(&self) -> Option<&'a [u8]> {
        self.auth_info.map(Element::contents)
    }
    /// Original optional OCTET STRING, including its physical source range.
    #[must_use]
    pub fn auth_info_element(&self) -> Option<Element<'a>> {
        self.auth_info
    }
}
