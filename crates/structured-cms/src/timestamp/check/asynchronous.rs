//! Asynchronous acquisition inside the same scoped timestamp check pipeline.

use super::{
    CheckContext, CheckError, CheckPurpose, CheckedTimestamp, Error, ErrorCode, Execution,
    Infallible, InfoCheckError, Information, InformationFacts, ProfileCheckError, ProfileFailure,
    ProfileInput, Reader, SignatureProvider, SourceMap, Token, TokenExtension, TokenSignature,
    common_holds, directory, ess, finish_information, preflight, profile, unrecognized,
};
use crate::timestamp::{AsyncComputedInput, AsyncInfoVisitor, AsyncRawInput, TokenInfo};

struct Inspection<'a, 'doc, 'r, 'c, P, I, R, F> {
    token: &'a Token<'doc>,
    provider: &'a P,
    parent: &'r Reader<'a>,
    context: &'c CheckContext<'a, 'c>,
    ess: &'r ess::SigningAttributes<'a>,
    identifier: &'r directory::CertificateAgreement,
    carried: Option<bool>,
    input: &'r mut I,
    recognizes: &'r mut R,
    profile: Option<F>,
    purpose: CheckPurpose,
}

impl<'a, 'doc: 'a, P, I, R, F, PE, RE, FE> AsyncInfoVisitor
    for Inspection<'a, 'doc, '_, '_, P, I, R, F>
where
    P: for<'scope> SignatureProvider<'scope, Error = PE>,
    I: AsyncComputedInput<P, PE>,
    R: FnMut(&TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
    F: for<'view, 'scope> FnOnce(
        ProfileInput<'view, 'doc, 'a, 'scope>,
    ) -> Result<(), ProfileFailure<FE>>,
{
    type Output = (TokenSignature<'a>, ess::Bindings, Information);
    type Error = profile::InformationFailure<I::Error, PE, RE, FE>;

    async fn visit<'data: 'scope, 'scope>(
        &'scope mut self,
        info: &'scope TokenInfo<'data>,
        inside: &'scope Reader<'data>,
        source: &'scope SourceMap,
    ) -> Result<Self::Output, Self::Error> {
        if info.has_faults() {
            return Err(InfoCheckError::Nonconforming { span: info.span() }.into());
        }
        self.profile.take().expect("one information visit")(ProfileInput {
            token: self.token,
            parent: self.parent,
            envelope: None,
            ess: self.ess,
            info,
            reader: inside,
            source,
        })
        .map_err(profile::InformationFailure::Profile)?;
        let bindings = self
            .ess
            .bind_certificate(self.provider, self.context.certificate, self.parent)
            .map_err(InfoCheckError::Ess)?;
        let signature: TokenSignature<'a> = self
            .token
            .check_signature(self.provider, self.context.key, self.parent)
            .map_err(InfoCheckError::Signature)?;
        let holds = common_holds(&signature, bindings, self.identifier, self.carried);
        let authority = info
            .authority(
                self.context.certificate,
                inside,
                self.context.certificate_parent,
            )
            .map_err(InfoCheckError::Authority)?;
        let fields = self
            .context
            .requested
            .as_ref()
            .map(|request| info.matches_request_fields(request.request, inside, request.parent))
            .transpose()
            .map_err(InfoCheckError::RequestField)?;
        let unknown = unrecognized(info, inside, self.recognizes)?;
        let (imprint, requested_imprint) = if let Some(request) = &self.context.requested {
            let (imprint, requested) = info
                .imprint()
                .check_requested_input_async(
                    request.request.imprint(),
                    self.provider,
                    (inside, request.parent),
                    self.input,
                )
                .await
                .map_err(|error| match error {
                    crate::timestamp::RequestedContentError::Request(source) => {
                        InfoCheckError::RequestImprint(source)
                    }
                    crate::timestamp::RequestedContentError::Content(source) => {
                        InfoCheckError::Imprint(source)
                    }
                })?;
            (imprint, Some(requested))
        } else {
            (
                info.imprint()
                    .check_input_async(self.provider, inside, self.input)
                    .await
                    .map_err(InfoCheckError::Imprint)?,
                None,
            )
        };
        let information = finish_information(
            info,
            inside,
            source,
            self.context,
            InformationFacts {
                authority,
                imprint,
                requested_imprint,
                requested_fields: fields,
                unknown,
            },
            holds,
            self.purpose,
        )?;
        Ok((signature, bindings, information))
    }
}

impl<'doc> Token<'doc> {
    /// Complete common timestamp checking over asynchronously acquired bytes.
    /// The only suspension is bounded source acquisition inside scoped `TSTInfo`;
    /// no joined reader or temporary model escapes, including on cancellation.
    #[expect(
        clippy::result_large_err,
        reason = "failure retains the original carried-source mapping rather than allocating or discarding provenance"
    )]
    pub async fn check_async<'a, P, S, PE, RE>(
        &'a self,
        provider: &'a P,
        parent: &Reader<'a>,
        context: &CheckContext<'a, '_>,
        covered: &mut S,
        recognizes: impl FnMut(&TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
    ) -> Result<CheckedTimestamp<'a>, CheckError<S::Error, PE, RE>>
    where
        'doc: 'a,
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
        S: crate::stream::AsyncSource,
    {
        self.check_async_input_with_profile(
            provider,
            parent,
            context,
            &mut AsyncRawInput::new(covered),
            recognizes,
            |_| Ok::<(), ProfileFailure<Infallible>>(()),
            CheckPurpose::Ordinary,
        )
        .await
        .map_err(ProfileCheckError::into_common)
    }

    /// Parse-once profile checking before provider/content callbacks, followed
    /// by the same complete asynchronous common pipeline.
    #[expect(
        clippy::result_large_err,
        reason = "profile failure preserves the scoped input map and original callback cause without an error allocation"
    )]
    pub async fn check_async_with_profile<'a, P, I, PE, RE, FE>(
        &'a self,
        provider: &'a P,
        parent: &Reader<'a>,
        context: &CheckContext<'a, '_>,
        covered: &mut I,
        recognizes: impl FnMut(&TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
        profile: impl for<'view, 'scope> FnOnce(
            ProfileInput<'view, 'doc, 'a, 'scope>,
        ) -> Result<(), ProfileFailure<FE>>,
    ) -> Result<CheckedTimestamp<'a>, ProfileCheckError<I::Error, PE, RE, FE>>
    where
        'doc: 'a,
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
        I: AsyncComputedInput<P, PE>,
    {
        self.check_async_input_with_profile(
            provider,
            parent,
            context,
            covered,
            recognizes,
            profile,
            CheckPurpose::Ordinary,
        )
        .await
    }

    /// Historical asynchronous pass with the same explicit prohibition on
    /// current-clock/live-request assertions as the resident archival API.
    #[expect(
        clippy::result_large_err,
        reason = "historical checking retains identical source-qualified failures to ordinary checking"
    )]
    pub async fn check_historical_async_with_profile<'a, P, I, PE, RE, FE>(
        &'a self,
        provider: &'a P,
        parent: &Reader<'a>,
        context: &CheckContext<'a, '_>,
        covered: &mut I,
        recognizes: impl FnMut(&TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
        profile: impl for<'view, 'scope> FnOnce(
            ProfileInput<'view, 'doc, 'a, 'scope>,
        ) -> Result<(), ProfileFailure<FE>>,
    ) -> Result<CheckedTimestamp<'a>, ProfileCheckError<I::Error, PE, RE, FE>>
    where
        'doc: 'a,
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
        I: AsyncComputedInput<P, PE>,
    {
        if context.requested.is_some() || context.reference.is_some() || context.window.is_some() {
            return Err(CheckError::Processing(Error::schema(
                ErrorCode::InvalidLocation,
                "tstInfo.historical",
                self.message().span().start,
            ))
            .into());
        }
        self.check_async_input_with_profile(
            provider,
            parent,
            context,
            covered,
            recognizes,
            profile,
            CheckPurpose::Historical,
        )
        .await
    }

    #[expect(
        clippy::result_large_err,
        reason = "the one shared async checking pipeline owns its error source map after temporary input is dropped"
    )]
    #[expect(
        clippy::too_many_arguments,
        reason = "the shared driver receives independent provider, source, context, recognizer, format callback and historical purpose without boxing callbacks"
    )]
    async fn check_async_input_with_profile<'a, P, I, PE, RE, FE>(
        &'a self,
        provider: &'a P,
        parent: &Reader<'a>,
        context: &CheckContext<'a, '_>,
        covered: &mut I,
        mut recognizes: impl FnMut(&TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
        profile: impl for<'view, 'scope> FnOnce(
            ProfileInput<'view, 'doc, 'a, 'scope>,
        ) -> Result<(), ProfileFailure<FE>>,
        purpose: CheckPurpose,
    ) -> Result<CheckedTimestamp<'a>, ProfileCheckError<I::Error, PE, RE, FE>>
    where
        'doc: 'a,
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
        I: AsyncComputedInput<P, PE>,
    {
        preflight(self, parent, context).map_err(CheckError::from)?;
        let identifier =
            directory::matches_certificate_in(self.signer().sid(), context.certificate, parent)
                .map_err(CheckError::Identifier)?;
        let ess =
            ess::SigningAttributes::read(self.signer(), parent).map_err(CheckError::Processing)?;
        let carried = context
            .requested
            .as_ref()
            .map(|requested| {
                self.matches_cert_req(
                    requested.request,
                    Some(context.certificate),
                    parent,
                    requested.parent,
                )
            })
            .transpose()
            .map_err(CheckError::RequestField)?;
        if !self.faults().is_empty()
            || !self.message().faults().is_empty()
            || !self.signer().faults().is_empty()
            || !ess.faults().is_empty()
            || ess.v1().is_some_and(|reading| !reading.faults().is_empty())
            || ess.v2().is_some_and(|reading| !reading.faults().is_empty())
        {
            return Err(CheckError::Nonconforming {
                span: self.message().span(),
            }
            .into());
        }
        let (signature, bindings, information) = self
            .with_info_async(
                parent,
                None,
                &mut Inspection {
                    token: self,
                    provider,
                    parent,
                    context,
                    ess: &ess,
                    identifier: &identifier,
                    carried,
                    input: covered,
                    recognizes: &mut recognizes,
                    profile: Some(profile),
                    purpose,
                },
            )
            .await
            .map_err(profile::information_error)?;
        Ok(CheckedTimestamp {
            signature,
            identifier,
            ess,
            bindings,
            authority: information.authority,
            imprint: information.imprint,
            requested_imprint: information.requested_imprint,
            requested_fields: information.requested_fields,
            carried,
            timeliness: information.timeliness,
            accuracy_error: information.accuracy_error,
            unknown_critical: information.unknown,
            evidence: information.evidence,
        })
    }
}
