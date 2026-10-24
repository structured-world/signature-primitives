//! VRI identity for the actual once-parsed CRL or basic OCSP signature.

use super::{BindingError, NameError, name_for_ranges};
use crate::{
    error::{Error, ErrorKind},
    material::{MaterialError, Parsed, Value, Vri},
    model::admit,
};
use structured_asn1::memory::Work;
use structured_pkix::{algorithm::digest::AsnDigest, signature::SignatureValue};

/// A matching normative VRI name for an actual retained status signature.
/// This does not authenticate that signature or assert certificate status.
pub struct StatusBinding<'b, 'd> {
    vri: &'b Vri,
    item: usize,
    signature: SignatureValue<'d>,
}
impl<'d> StatusBinding<'_, 'd> {
    /// The matching original VRI in this same historical owner.
    #[must_use]
    pub fn vri(&self) -> &Vri {
        self.vri
    }
    /// Original CRL/whole-OCSP item ordinal in the owning Validation.
    #[must_use]
    pub fn item(&self) -> usize {
        self.item
    }
    /// Original status signature and its producing parser context.
    #[must_use]
    pub fn signature(&self) -> SignatureValue<'d> {
        self.signature
    }
}

/// Original syntax, source, provider or absence of a status signature.
#[derive(Debug)]
pub enum StatusError<'b, E> {
    /// PDF/source/hash refusal, retaining the original cause.
    Binding(BindingError<E>),
    /// The actual retained item was unreadable on its first parse.
    Unreadable(&'b MaterialError),
    /// The known basic OCSP payload was unreadable on its first parse.
    Ocsp(&'b structured_pkix::Error),
    /// The chosen item is not a CRL or OCSP response.
    NotStatus,
    /// The original OCSP envelope has no known signed basic response.
    NotSigned,
}

impl<'v, D: Copy + Eq, G: Copy + Eq> Parsed<'v, '_, D, G> {
    /// Selects a status VRI by the SHA-1 of a primitive BER OCTET STRING
    /// containing its original signature octets (EN319142-1 §5.4.2.2(b)).
    /// The shortest definite length is also BER. No signature bytes are copied
    /// and no status envelope or signature is reparsed.
    /// <https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf>
    ///
    /// # Panics
    /// Panics if the retained original file extent is internally invalid.
    pub fn bind_status_vri<'b, 'p, P: AsnDigest<'p>>(
        &'b self,
        item: usize,
        provider: &'p P,
        operation: &impl Work,
    ) -> Result<Option<StatusBinding<'b, 'v>>, StatusError<'b, P::Error>> {
        let work = self.owner.session.query(operation);
        let location = self.owner.items.get(item).map_or_else(
            || {
                crate::source::Location::new(
                    crate::source::Source::File,
                    0,
                    self.owner.stamp.length,
                )
                .expect("original file")
            },
            crate::material::Item::location,
        );
        admit(&work, location, 1)
            .map_err(|cause| StatusError::Binding(BindingError::Pdf(cause)))?;
        let value = self.values.get(item).ok_or_else(|| {
            StatusError::Binding(BindingError::Pdf(Error {
                kind: ErrorKind::Foreign,
                location,
            }))
        })?;
        let signature = match value {
            Value::Crl(value) => value.signature_value(),
            Value::Ocsp {
                basic: Ok(Some(value)),
                ..
            } => value.signature_value(),
            Value::Ocsp {
                basic: Ok(None), ..
            } => return Err(StatusError::NotSigned),
            Value::Ocsp {
                basic: Err(cause), ..
            } => return Err(StatusError::Ocsp(cause)),
            Value::Unreadable(cause) => return Err(StatusError::Unreadable(cause)),
            _ => return Err(StatusError::NotStatus),
        };
        if self.owner.vri_names.is_empty() {
            return Ok(None);
        }
        let name = status_name(signature, provider, &work, location)
            .map_err(|cause| StatusError::Binding(BindingError::Name(cause)))?
            .ok_or(StatusError::Binding(BindingError::UnsupportedName))?;
        let matched = self.owner.vri_names.get(&name, &work).map_err(|cause| {
            StatusError::Binding(BindingError::Pdf(Error {
                kind: ErrorKind::Resource(cause),
                location,
            }))
        })?;
        Ok(matched.map(|&ordinal| StatusBinding {
            vri: &self.owner.vri[ordinal],
            item,
            signature,
        }))
    }
}

pub(super) fn status_name<'p, P: AsnDigest<'p>>(
    signature: SignatureValue<'_>,
    provider: &'p P,
    operation: &impl Work,
    location: crate::source::Location,
) -> Result<Option<super::Name>, NameError<P::Error>> {
    let work = signature.execution_in(operation);
    admit(&work, location, 1).map_err(NameError::Pdf)?;
    let bytes = signature.octets().ok_or(NameError::PaddedSignature)?;
    let mut header = [0; core::mem::size_of::<usize>() + 2];
    header[0] = 4;
    let end = if bytes.len() < 128 {
        header[1] = u8::try_from(bytes.len()).expect("short length");
        2
    } else {
        let length = bytes.len().to_be_bytes();
        let mut first = 0;
        while length[first] == 0 {
            first += 1;
        }
        let count = length.len() - first;
        header[1] = 0x80 | u8::try_from(count).expect("machine-sized length");
        header[2..2 + count].copy_from_slice(&length[first..]);
        2 + count
    };
    name_for_ranges(provider, &mut [&header[..end], bytes], &work, location)
}
