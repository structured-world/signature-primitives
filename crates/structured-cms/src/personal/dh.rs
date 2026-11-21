//! Scoped X9.42 private-value decoding using the shared PKIX grammar.

use super::{Failure, PrivateKey, Source, process};
use crate::Error;
use structured_asn1::Reader;
use structured_pkix::key::dh;

impl PrivateKey<'_> {
    /// Visit ANSI X9.42 DH parameters and private x from this PKCS#8 container.
    /// Original/current work and depth apply throughout. Primitive DER is
    /// borrowed directly; segmented BER uses accounted, wiping temporary storage.
    /// The fixed result cannot retain temporary secret borrows. Supply the
    /// container's source, including any prior decryption boundary. Decryption
    /// remains the existing password-protection operation.
    ///
    /// # Errors
    /// Processing, resources and visitor causes remain distinct. Carried errors
    /// retain the fragment map after the temporary secret is wiped. Parameter
    /// failures name the container source; x failures name the carried source.
    /// A foreign parser fails before any parameter or secret work.
    ///
    /// ```compile_fail
    /// use structured_asn1::Reader;
    /// use structured_cms::personal::{PrivateKey, Source};
    /// fn escape<'a>(key: &PrivateKey<'a>, query: &Reader<'a>) -> &'a [u8] {
    ///     key.with_dh(query, &Source::Document, |key, _| {
    ///         Ok::<_, ()>(key.x().as_bytes())
    ///     }).unwrap()
    /// }
    /// ```
    #[expect(
        clippy::result_large_err,
        reason = "retain the original callback cause and funded source chain without allocating an error box"
    )]
    pub fn with_dh<R, E>(
        &self,
        query: &Reader<'_>,
        origin: &Source<'_>,
        visitor: impl for<'scope> FnOnce(
            dh::PrivateKey<'scope>,
            &Source<'_>,
        ) -> core::result::Result<R, E>,
    ) -> core::result::Result<R, Failure<E>> {
        const FIELD: &str = "privateKey.dh";
        if !core::ptr::eq(self.secret.parser(), query.parser()) {
            return Err(Failure::processing(Error::pkix(
                structured_pkix::Error::new(
                    structured_pkix::ErrorCode::ForeignReader,
                    FIELD,
                    self.secret.span().start,
                ),
            )));
        }
        // Parameter diagnostics name the container, not the carried x source.
        let parameters = dh::Parameters::read(self.algorithm, &query.execution())
            .map_err(|error| Failure::processing(Error::pkix(error)))?;
        process::nested(&self.secret, query, origin, |reader, source| {
            let element = crate::signer::required(reader, FIELD).map_err(Failure::processing)?;
            if !reader.is_empty() {
                return Err(Failure::processing(Error::schema(
                    crate::ErrorCode::TrailingData,
                    FIELD,
                    reader.offset(),
                )));
            }
            let key = dh::PrivateKey::read(parameters, reader, element)
                .map_err(|error| Failure::processing(Error::pkix(error)))?;
            visitor(key, source).map_err(Failure::callback)
        })
    }
}
