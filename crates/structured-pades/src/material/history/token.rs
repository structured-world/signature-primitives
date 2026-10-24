//! One carried-token material insertion kernel for PDF DTS and VRI TS.

use super::super::{Placement, TokenChoice};
use crate::timestamp::{ISSUER, Node, Pades, sources::Revocation};
use structured_ltv::{
    material::{ArtifactRef, ArtifactSource, CarriedOrigin, Index, IndexError, Occurrence},
    source::{Location, Query},
};

pub(super) fn append<
    'q,
    'd: 'q,
    D: Copy + Eq,
    G: Copy + Eq,
    O,
    Q: Query<Id = Node, Document = D, Generation = G>,
>(
    index: &mut Index<'q, Node, D, G, Placement, O, Q::Work, Pades>,
    token: &'q structured_cms::timestamp::Token<'d>,
    revocations: &'q [Revocation<'d>],
    ordinal: usize,
    location: Location<Node, D, G>,
    placement: impl Fn(TokenChoice) -> Placement,
    query: &Q,
) -> Result<bool, IndexError<Node>> {
    for (choice, value) in token.message().certificate_choices().iter().enumerate() {
        index.admit(query)?;
        if let structured_cms::signed::CertificateChoice::X509(certificate) = value {
            index.insert(
                ISSUER,
                ArtifactRef::Certificate(&token.message().certificates()[*certificate]),
                Occurrence::new(
                    ArtifactSource::TokenCertificate {
                        token: ordinal,
                        certificate: *certificate,
                    },
                    location,
                    placement(TokenChoice::Certificate(choice)),
                ),
                query,
            )?;
        }
    }
    let mut complete = true;
    for value in revocations {
        index.admit(query)?;
        let artifact = match &value.value {
            Ok(structured_cms::signed::revocation::Reading::Crl(value)) => ArtifactRef::Crl(value),
            Ok(structured_cms::signed::revocation::Reading::Ocsp(value)) => {
                ArtifactRef::Ocsp(value)
            }
            Ok(structured_cms::signed::revocation::Reading::Open { .. }) => continue,
            Err(_) => {
                complete = false;
                continue;
            }
        };
        index.insert(
            ISSUER,
            artifact,
            Occurrence::new(
                ArtifactSource::TokenRevocation(CarriedOrigin {
                    token: ordinal,
                    choice: value.choice,
                }),
                location,
                placement(TokenChoice::Revocation(value.choice)),
            ),
            query,
        )?;
    }
    Ok(complete)
}
