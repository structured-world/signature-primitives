//! Original XML base-datatype syntax, separate from authenticated properties.

use crate::reference::LexicalSource;
use crate::xml::{Access, AccessError, Snapshot, Xml};
use structured_asn1::memory::Work;

/// Complete XML-normalized text, before schema whitespace conversion. This is
/// a lexical source view, not successful interpretation of a requested schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextValue<'view> {
    /// The requested original attribute was not written.
    Absent,
    /// Element children prevent reading simple content.
    ComplexContent,
    /// Entire original value, including significant spaces and empty text.
    Present(&'view str),
}

/// Scoped original text for a format-owned interpretation such as RFC4514.
/// Reuse the XML owner's existing scalar/simple-content reader. Do not collapse
/// spaces, flatten element children, serialize/reparse or retain callback-local
/// joined text. Current Work admits all traversal/joined storage before use.
pub trait TextXml: Xml {
    /// Visit one original simple-content or attribute source exactly once.
    /// Preserve the first visitor refusal and the owner's original processing
    /// cause. A foreign/stale source is rejected before text access.
    fn with_text<R, VE, W: Work>(
        &self,
        snapshot: Snapshot<Self::Document, Self::Generation>,
        node: Self::Id,
        source: LexicalSource<'_>,
        execution: &W,
        visitor: impl for<'view> FnOnce(TextValue<'view>) -> Result<R, VE>,
    ) -> Result<R, crate::reference::VisitError<Self::Error, VE>>;
}

/// Original `QName` value resolved by the XML owner, not by a copied prefix map.
/// Namespace strings and local names can borrow callback-local joined storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QNameValue<'view> {
    /// In-scope namespace, including the default namespace for unprefixed values.
    /// None means no binding; it does not mean a missing original value.
    pub namespace: Option<&'view str>,
    /// Complete local name, preserving case and Unicode without normalization.
    pub local_name: &'view str,
}

/// `QName` syntax/resolution outcome, independent of schema type admissibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QNameFact<'view> {
    /// Original requested attribute absent.
    Absent,
    /// Element children prevent simple content.
    ComplexContent,
    /// Original lexical value is not an XSD1.0 `QName`.
    Malformed,
    /// Valid lexical `QName` whose prefix has no original in-scope binding.
    UnboundPrefix(&'view str),
    /// Owner does not implement this datatype.
    Unsupported,
    /// Resolved original value; not proof of a declared or derived schema type.
    Value(QNameValue<'view>),
}

/// Original XML text and its separate `QName` interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QNameReading<'view> {
    /// Complete XML-normalized text before schema whitespace collapse.
    pub lexical: Option<&'view str>,
    /// Exact lexical/resolution result under the original owner's namespace scope.
    pub fact: QNameFact<'view>,
}

/// XML-owned `QName` projection for xsi:type's format-owned type interpretation.
/// The owner admits text/namespace scans, joining and resolution with current
/// Work, rejects foreign/stale source before access and preserves callback errors.
/// No declaration lookup, schema fetch or signature verification follows.
pub trait QNameXml: Xml {
    /// Visit the original reading once. Borrowed text/names cannot leave this
    /// scope; copied results must be admitted through the current execution.
    ///
    /// ```compile_fail
    /// use structured_xades::{scalar::QNameXml, reference::{LexicalSource, VisitError}, xml::{Snapshot, Xml}};
    /// use structured_asn1::memory::Work;
    /// fn escape<'a, X: QNameXml, W: Work>(xml: &'a X, snapshot: Snapshot<X::Document, X::Generation>, node: X::Id, work: &W)
    ///     -> Result<Option<&'a str>, VisitError<X::Error, ()>> {
    ///     xml.with_qname(snapshot, node, LexicalSource::SimpleContent, work, |read| Ok(read.lexical))
    /// }
    /// ```
    fn with_qname<R, VE, W: Work>(
        &self,
        snapshot: Snapshot<Self::Document, Self::Generation>,
        node: Self::Id,
        source: LexicalSource<'_>,
        execution: &W,
        visitor: impl for<'view> FnOnce(QNameReading<'view>) -> Result<R, VE>,
    ) -> Result<R, crate::reference::VisitError<Self::Error, VE>>;
}

/// Scoped complete schema-normalized anyURI, without acquisition or resolution.
/// A successful value may borrow temporary joined/collapsed storage ONLY while
/// the visitor executes. It never claims permanence or OID interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UriValue<'view> {
    /// The selected original attribute was absent.
    Absent,
    /// Element children prevent reading simple content.
    ComplexContent,
    /// The present value violates the requested base datatype.
    Malformed,
    /// The XML owner cannot establish this base datatype.
    Unsupported,
    /// Entire XSD1.0 anyURI value after schema whitespace processing.
    Valid(&'view str),
}

/// XML-owned scoped URI value for format-specific interpretation. Implementors
/// reuse the SAME anyURI kernel as [`ScalarXml`], including original identity,
/// joining/collapse capacity and current-operation admission before all work.
/// No second XML parser, string copy, resolver or signature verification follows.
pub trait UriXml: Xml {
    /// Visit the complete value once; preserve the first caller refusal without
    /// replacing it with a later source/generation/resource failure. The result
    /// cannot borrow the callback-local normalized value.
    ///
    /// ```compile_fail
    /// use structured_xades::{scalar::{UriXml, UriValue}, reference::{LexicalSource, VisitError}, xml::{Snapshot, Xml}};
    /// use structured_asn1::memory::Work;
    /// fn escape<'a, X: UriXml, W: Work>(xml: &'a X, snapshot: Snapshot<X::Document, X::Generation>, node: X::Id, work: &W)
    ///     -> Result<&'a str, VisitError<X::Error, ()>> {
    ///     xml.with_uri(snapshot, node, LexicalSource::SimpleContent, work, |value| {
    ///         match value { UriValue::Valid(text) => Ok(text), _ => Err(()) }
    ///     })
    /// }
    /// ```
    fn with_uri<R, VE, W: Work>(
        &self,
        snapshot: Snapshot<Self::Document, Self::Generation>,
        node: Self::Id,
        source: LexicalSource<'_>,
        execution: &W,
        visitor: impl for<'view> FnOnce(UriValue<'view>) -> Result<R, VE>,
    ) -> Result<R, crate::reference::VisitError<Self::Error, VE>>;
}

/// Exact base datatype requested by an `XAdES` field's normative schema.
/// This is not an application policy, URI resolver or whole-schema validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Datatype {
    /// XSD1.0 ID lexical syntax; no registration, uniqueness or authentication.
    Id,
    /// XSD1.0 anyURI, including its schema whitespace processing. No URL policy,
    /// absolute-URI requirement, escaping, dereferencing or acquisition follows.
    AnyUri,
    /// XSD1.0 integer lexical syntax without a finite machine-integer bound.
    Integer,
}

/// Outcome for one requested original base datatype, not whole-schema validity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fact {
    /// The selected original attribute was not written.
    Absent,
    /// Element children prevent reading the requested simple content.
    ComplexContent,
    /// Present lexical data do not satisfy the requested base datatype.
    Malformed,
    /// The owner has not implemented this base datatype; never invalid syntax.
    Unsupported,
    /// The complete original value satisfies only the requested base datatype.
    Valid,
}

/// Narrow XML-owned lexical projection over the original immutable source.
///
/// Implementors reuse their scalar kernel, including exact XSD1.0 whitespace,
/// Unicode and arbitrary-precision rules. Admit scans, joining/collapse and
/// temporary capacity under the supplied current Work before performing them.
/// An error keeps its original processing/resource cause; it is not a lexical
/// fact. No second parser, default value or silently narrowed integer is needed.
/// Signature authentication and compiled XML operation policy are separate;
/// this projection does not reverify a signature or confer authenticated status.
/// <https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/>
pub trait ScalarXml: Xml {
    /// Inspect exactly this original element or expanded-name attribute.
    /// Reject a foreign/stale source before access. Missing, malformed, complex
    /// and unsupported remain distinct, even when no normalized value is kept.
    fn scalar<W: Work>(
        &self,
        snapshot: Snapshot<Self::Document, Self::Generation>,
        node: Self::Id,
        source: LexicalSource<'_>,
        datatype: Datatype,
        execution: &W,
    ) -> Result<Fact, Self::Error>;
}

/// A present schema field failed its requested base-datatype check.
/// Caller/source/resource failures stay separate from these completed facts.
#[derive(Debug)]
pub enum Error<E, N> {
    /// Original current-operation, XML or generation refusal.
    Access(AccessError<E, N>),
    /// The original field did not establish the requested lexical value.
    Value {
        /// Original XML owner, not a copied-string byte coordinate.
        node: N,
        /// Requested schema base datatype.
        datatype: Datatype,
        /// Exact failed/incomplete outcome; Unsupported is not Malformed.
        fact: Fact,
    },
}

/// Lexical check result preserving this owner's original source/error types.
pub type ScalarResult<X> = Result<(), Error<<X as Xml>::Error, <X as Xml>::Id>>;

/// Require a PRESENT field's complete original lexical syntax under current
/// Work. Optional absence is decided by the owning field schema before calling
/// this function; an absent requested attribute is never fabricated as valid.
///
/// Successful return proves only this requested base datatype. It does not
/// validate other attributes, xsi:type derivation, URI/OID meaning, ID uniqueness,
/// signed coverage, permanent identifier assignment or a baseline level.
pub fn check<X: ScalarXml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
    source: LexicalSource<'_>,
    datatype: Datatype,
) -> ScalarResult<X> {
    let fact = access
        .query(node, |xml, snapshot, work| {
            xml.scalar(snapshot, node, source, datatype, work)
        })
        .map_err(Error::Access)?;
    match fact {
        Fact::Valid => Ok(()),
        fact => Err(Error::Value {
            node,
            datatype,
            fact,
        }),
    }
}
