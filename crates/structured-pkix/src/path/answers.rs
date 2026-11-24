//! Operation-local reuse of definite X.509 signature verification answers.
//!
//! Use the same store in the caller's [`super::Verify`] adapter during
//! discovery and supplied-path validation. Admission, algorithm resolution,
//! key policy and source-aware decoding remain the adapter's responsibility
//! on every call. The stored answer is only the result of signature math.

use super::Verified;
use core::cell::RefCell;
use structured_asn1::memory::{Memory, MemoryError, OwnedVec, Work};

/// The exact inputs identifying one signature verification.
#[derive(Debug, Clone, Copy)]
pub struct Edge<'a> {
    /// Complete original signature `AlgorithmIdentifier`.
    pub algorithm: &'a [u8],
    /// Original signed bytes supplied for verification.
    pub signed: &'a [u8],
    /// Signature bytes supplied for verification.
    pub signature: &'a [u8],
    /// Complete effective issuer SPKI, including any inherited parameters.
    pub issuer_spki: &'a [u8],
}

impl<'a> Edge<'a> {
    fn parts(self) -> [&'a [u8]; 4] {
        [
            self.algorithm,
            self.signature,
            self.issuer_spki,
            self.signed,
        ]
    }
}

/// A store or verifier refusal, preserving the original cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error<E> {
    /// The requested execution belongs to a different operation account.
    ForeignAccount,
    /// Work to compare or retain an answer was refused.
    Work(MemoryError),
    /// The verifier refused the operation.
    Verification(E),
}

struct Entry {
    lengths: [usize; 4],
    bytes: OwnedVec<u8>,
    answer: Verified,
}

/// Definite answers from one verifier for one operation.
///
/// The store owns the verifier callback for its entire lifetime and exposes no
/// way to replace it. The callback must use a fixed provider and configuration
/// for that lifetime. Construct a fresh store when either changes.
pub struct SignatureAnswers<F> {
    verify: F,
    entries: RefCell<Option<OwnedVec<Entry>>>,
}

impl<F> SignatureAnswers<F> {
    /// Create an empty store without allocating.
    #[must_use]
    pub fn new(memory: &Memory, verify: F) -> Self {
        Self {
            verify,
            entries: RefCell::new(Some(memory.vector())),
        }
    }

    /// Return a kept answer or run the bound verifier.
    ///
    /// Pass the current execution after the caller has checked its policy,
    /// algorithm and key, including any applicable original-source ceilings.
    /// The verifier is only called on a miss, with no store borrow held.
    /// Unsupported results and verifier errors are never kept. Refused
    /// allocation only skips retention; refused work is returned.
    pub fn verify<W, E>(&self, edge: Edge<'_>, work: &W) -> Result<Verified, Error<E>>
    where
        W: Work,
        F: Fn(Edge<'_>, &W) -> Result<Verified, E>,
    {
        let parts = edge.parts();
        let lengths = parts.map(<[u8]>::len);
        if let Some(answer) = self.lookup(parts, lengths, work)? {
            return Ok(answer);
        }
        let answer = (self.verify)(edge, work).map_err(Error::Verification)?;
        if matches!(answer, Verified::Yes | Verified::No)
            && let Err(cause @ MemoryError::WorkExceeded) =
                self.remember(parts, lengths, answer, work)
        {
            return Err(Error::Work(cause));
        }
        Ok(answer)
    }

    fn lookup<W: Work, E>(
        &self,
        parts: [&[u8]; 4],
        lengths: [usize; 4],
        work: &W,
    ) -> Result<Option<Verified>, Error<E>> {
        let entries = self.entries.borrow();
        let entries = entries.as_ref().expect("the store is idle");
        if !entries.memory().same_account(work.memory()) {
            return Err(Error::ForeignAccount);
        }
        'entries: for entry in entries {
            work.charge_work(1).map_err(Error::Work)?;
            if entry.lengths != lengths {
                continue;
            }
            let mut bytes = &entry.bytes[..];
            for part in parts {
                work.charge_work(part.len() as u64).map_err(Error::Work)?;
                let (stored, rest) = bytes.split_at(part.len());
                if stored != part {
                    continue 'entries;
                }
                bytes = rest;
            }
            return Ok(Some(entry.answer));
        }
        Ok(None)
    }

    fn remember<W: Work>(
        &self,
        parts: [&[u8]; 4],
        lengths: [usize; 4],
        answer: Verified,
        work: &W,
    ) -> Result<(), MemoryError> {
        let Some(total) = lengths.into_iter().try_fold(0_usize, usize::checked_add) else {
            return Err(MemoryError::CapacityOverflow);
        };
        let mut bytes = work.vector();
        bytes.try_reserve_exact(total)?;
        for part in parts {
            bytes.try_extend_from_slice(part)?;
        }

        let mut slot = self.entries.borrow_mut();
        let entries = slot.take().expect("the store is idle");
        let Ok(mut entries) = entries.with_execution(work) else {
            unreachable!("the account was checked before verification");
        };
        let result = entries.try_push(Entry {
            lengths,
            bytes: bytes.into_owned(),
            answer,
        });
        *slot = Some(entries.into_owned());
        result
    }
}

#[cfg(test)]
mod tests;
