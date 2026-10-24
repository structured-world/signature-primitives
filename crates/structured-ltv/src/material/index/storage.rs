//! Scoped vector mutation restores the exact previous execution on unwind too.

use core::ops::{Deref, DerefMut};
use structured_asn1::memory::{MemoryError, OwnedVec, VecExecution, Work};

pub(super) struct Storage<T, W: Work>(Option<OwnedVec<T, W>>);
pub(super) enum Error {
    Foreign,
    Resource(MemoryError),
}
impl<T, W: Work> Storage<T, W> {
    pub(super) fn new(values: OwnedVec<T, W>) -> Self {
        Self(Some(values))
    }
    pub(super) fn into_inner(mut self) -> OwnedVec<T, W> {
        self.0.take().expect("restored vector")
    }
    pub(super) fn scoped<V: Work, R>(
        &mut self,
        execution: V,
        apply: impl FnOnce(&mut OwnedVec<T, V>) -> Result<R, MemoryError>,
    ) -> Result<R, Error> {
        let original = self.0.take().expect("restored vector");
        let (values, previous) = match original.rebind(execution) {
            VecExecution::Changed { values, previous } => (values, previous),
            VecExecution::Foreign { values, .. } => {
                self.0 = Some(values);
                return Err(Error::Foreign);
            }
        };
        let mut restore = Restore {
            destination: &mut self.0,
            values: Some(values),
            previous: Some(previous),
        };
        apply(restore.values.as_mut().expect("live scoped vector")).map_err(Error::Resource)
    }
}
struct Restore<'a, T, W: Work, V: Work> {
    destination: &'a mut Option<OwnedVec<T, W>>,
    values: Option<OwnedVec<T, V>>,
    previous: Option<W>,
}
impl<T, W: Work, V: Work> Drop for Restore<'_, T, W, V> {
    fn drop(&mut self) {
        let values = self.values.take().expect("live scoped vector");
        let previous = self.previous.take().expect("previous execution retained");
        *self.destination = Some(match values.rebind(previous) {
            VecExecution::Changed { values, .. } => values,
            VecExecution::Foreign { .. } => unreachable!("restore uses the exact original account"),
        });
    }
}
impl<T, W: Work> Deref for Storage<T, W> {
    type Target = OwnedVec<T, W>;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref().expect("restored vector")
    }
}
impl<T, W: Work> DerefMut for Storage<T, W> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut().expect("restored vector")
    }
}
