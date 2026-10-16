//! Accounted storage and pre-admitted hashing for the existing hashbrown engine.

use core::borrow::Borrow;
use core::fmt;
use core::hash::{BuildHasher, Hash};

use hashbrown::hash_map::RawEntryMut;
use hashbrown::{DefaultHashBuilder, HashMap, TryReserveError};

use super::allocator::AccountAllocator;
use super::{Memory, MemoryError, Work};

#[cfg(test)]
mod tests;

/// A refused in-place filter, preserving the predicate's own cause.
#[derive(Debug, PartialEq, Eq)]
pub enum RetainError<E> {
    /// The map could not admit its traversal or erase metadata.
    Resource(MemoryError),
    /// The caller's predicate refused further processing.
    Predicate(E),
}

impl From<RetainError<MemoryError>> for MemoryError {
    fn from(error: RetainError<MemoryError>) -> Self {
        match error {
            RetainError::Resource(reason) | RetainError::Predicate(reason) => reason,
        }
    }
}

/// A trusted key type's upper bound for hashing and equality work.
///
/// Implementations must cover all bytes examined by Hash and Eq. This is a
/// contract for caller-provided code, not a value an untrusted document supplies.
/// The bound must remain unchanged and successful while a key is stored, just
/// as Hash and Eq must remain stable. Accounting retains this bound for rehashes.
pub trait HashWork: Hash + Eq {
    /// Work units for one hash/equality traversal, including constant overhead.
    fn hash_work(&self) -> Result<u64, MemoryError>;
}

impl HashWork for usize {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        Ok(1)
    }
}

impl HashWork for u8 {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        Ok(1)
    }
}

impl HashWork for (usize, usize, usize) {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        Ok(3)
    }
}

impl HashWork for &[u8] {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        Ok(self.len() as u64 + 1)
    }
}

impl HashWork for str {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        (self.len() as u64)
            .checked_add(1)
            .ok_or(MemoryError::WorkExceeded)
    }
}

impl HashWork for crate::Oid<'_> {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        Ok(self.as_bytes().len() as u64 + 1)
    }
}

impl HashWork for (crate::Oid<'_>, crate::Oid<'_>) {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        self.0
            .hash_work()?
            .checked_add(self.1.hash_work()?)
            .ok_or(MemoryError::WorkExceeded)
    }
}

/// A hash map whose backing allocation and operations share one resource domain.
///
/// Hashbrown supplies bucket/probing/SIMD machinery. Reservations include its
/// control bytes and alignment, not merely the initialized entries. Hashing and
/// actual collision comparisons are admitted before examining candidate keys.
pub struct OwnedMap<K: HashWork, V, W: Work = Memory> {
    values: HashMap<K, V, DefaultHashBuilder, AccountAllocator<W>>,
    execution: W,
    key_work: u64,
    maximum_capacity: usize,
}

impl<K: HashWork + fmt::Debug, V: fmt::Debug, W: Work> fmt::Debug for OwnedMap<K, V, W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.values.fmt(f)
    }
}

impl<K: HashWork, V, W: Work> OwnedMap<K, V, W> {
    pub(super) fn new(execution: W) -> Self {
        Self {
            values: HashMap::with_hasher_in(
                DefaultHashBuilder::default(),
                AccountAllocator::new(execution.clone()),
            ),
            execution,
            key_work: 0,
            maximum_capacity: 0,
        }
    }

    /// The shared account retained until the table is deallocated.
    #[must_use]
    pub fn memory(&self) -> &Memory {
        self.execution.memory()
    }

    /// Number of initialized entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether there are no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Borrowed entries after admitting a full control-bucket traversal in
    /// the current execution domain, independently of retained storage.
    /// Sparse holes count too. Partial consumption retains the conservative
    /// prepayment; the opaque iterator exposes no cloning/restart operation.
    ///
    /// # Examples
    /// ```
    /// # extern crate alloc;
    /// # use alloc::sync::Arc;
    /// # use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
    /// # let memory = Memory::new(Arc::new(MemoryAccount::new(1024, 1024)));
    /// let mut map = memory.map();
    /// map.try_insert(1usize, 42)?;
    /// let mut entries = map.try_iter(&memory)?;
    /// assert_eq!(entries.next(), Some((&1, &42)));
    /// # Ok::<(), MemoryError>(())
    /// ```
    pub fn try_iter<'a, E: Work>(
        &'a self,
        execution: &E,
    ) -> Result<impl Iterator<Item = (&'a K, &'a V)> + 'a + use<'a, K, V, W, E>, MemoryError> {
        execution.charge_work(self.buckets()?)?;
        Ok(self.values.iter())
    }

    /// Retains entries selected by a fallible predicate, without allocating.
    ///
    /// The supplied current execution admits the entire control-bucket scan,
    /// including sparse holes, before the first predicate call. Every erase
    /// separately admits its metadata work before removal. The predicate must
    /// admit its own data-dependent work; arbitrary key/value destructors are
    /// likewise caller-owned code. No key hashing or equality is performed.
    ///
    /// Entries are visited in unspecified order. On the first refusal no more
    /// predicates or key-work metadata callbacks run; the engine finishes its
    /// already admitted scan while retaining all remaining entries. Earlier
    /// removals and predicate value edits, including an edit made by a failing
    /// predicate, remain. Refusal never reports a successful partial filter.
    ///
    /// The original allocation, capacity charge and storage account remain
    /// unchanged. Future growth still uses the map's original execution.
    /// Filtering under another execution does not rebind that allocator.
    ///
    /// # Examples
    /// ```
    /// # extern crate alloc;
    /// # use alloc::sync::Arc;
    /// use structured_asn1::memory::{Memory, MemoryAccount};
    /// let memory = Memory::new(Arc::new(MemoryAccount::new(1024, 1024)));
    /// let mut map = memory.map();
    /// map.try_insert(1usize, 10).unwrap();
    /// map.try_insert(2usize, 20).unwrap();
    /// map.try_retain(&memory, |key, value| {
    ///     *value += 1;
    ///     Ok::<_, core::convert::Infallible>(*key == 2)
    /// }).unwrap();
    /// assert_eq!(map.len(), 1);
    /// assert_eq!(map.get(&2, &memory).unwrap(), Some(&21));
    /// ```
    pub fn try_retain<E>(
        &mut self,
        execution: &impl Work,
        mut predicate: impl FnMut(&K, &mut V) -> Result<bool, E>,
    ) -> Result<(), RetainError<E>> {
        let buckets = self.buckets().map_err(RetainError::Resource)?;
        execution
            .charge_work(buckets)
            .map_err(RetainError::Resource)?;
        let mut failure = None;
        let key_work = &mut self.key_work;
        self.values.retain(|key, value| {
            if failure.is_some() {
                return true;
            }
            match predicate(key, value) {
                Ok(true) => true,
                Err(reason) => {
                    failure = Some(RetainError::Predicate(reason));
                    true
                }
                Ok(false) => {
                    // Pinned hashbrown 0.17.1 RawTableInner::erase loads the
                    // adjacent two control groups, then drops the pair in place.
                    // It neither hashes keys nor moves entries to another table.
                    if let Err(reason) = execution.charge_work(2) {
                        failure = Some(RetainError::Resource(reason));
                        return true;
                    }
                    let removed = match key.hash_work() {
                        Ok(work) => work,
                        Err(reason) => {
                            failure = Some(RetainError::Resource(reason));
                            return true;
                        }
                    };
                    // HashWork's stored bound is stable by contract. Update
                    // before hashbrown erases and invokes a possibly panicking Drop.
                    debug_assert!(*key_work >= removed);
                    *key_work -= removed;
                    false
                }
            }
        });
        match failure {
            Some(reason) => Err(reason),
            None => Ok(()),
        }
    }

    fn buckets(&self) -> Result<u64, MemoryError> {
        // Pinned hashbrown 0.17.1 raw::bucket_mask_to_capacity: tables with
        // four/eight buckets keep one empty slot; larger tables use 7/8 of
        // the buckets. Maximum capacity records each table immediately after
        // reserve, before tombstones can reduce the public capacity value.
        match self.maximum_capacity {
            0 => Ok(0),
            capacity @ 1..=7 => Ok(capacity as u64 + 1),
            capacity => (capacity as u64 / 7)
                .checked_mul(8)
                .ok_or(MemoryError::WorkExceeded),
        }
    }

    fn control_work(&self) -> Result<u64, MemoryError> {
        let buckets = self.buckets()?;
        // The pinned engine's narrowest control group is four bytes. Wider
        // scalar/SIMD groups perform the same fixed group operations. One unit
        // admits one group visit; triangular probing visits each group once.
        Ok(buckets / 4)
    }

    fn rehash_work(&self) -> Result<u64, MemoryError> {
        // reserve(1) can double the current buckets or rehash in place. Every
        // retained key is hashed once; each slot search may visit all groups.
        // In-place rehash additionally scans every bucket and swaps entries.
        let buckets = self.buckets()?;
        let groups = buckets.checked_mul(2).ok_or(MemoryError::WorkExceeded)? / 4;
        let moves = (core::mem::size_of::<(K, V)>() as u64)
            .checked_mul(2)
            .ok_or(MemoryError::WorkExceeded)?;
        groups
            .checked_add(moves)
            .and_then(|per_entry| per_entry.checked_mul(self.values.len() as u64))
            .and_then(|work| work.checked_add(self.key_work))
            .and_then(|work| {
                buckets
                    .checked_mul(2)
                    .and_then(|scan| work.checked_add(scan))
            })
            .ok_or(MemoryError::WorkExceeded)
    }

    fn hash_key<Q: HashWork + ?Sized, E: Work>(
        &self,
        key: &Q,
        execution: &E,
    ) -> Result<u64, MemoryError> {
        let work = key
            .hash_work()?
            .checked_add(self.control_work()?)
            .ok_or(MemoryError::WorkExceeded)?;
        execution.charge_work(work)?;
        Ok(self.values.hasher().hash_one(key))
    }

    /// Looks up a key after admitting its complete possible probe work.
    /// The current execution domain pays independently of stored capacity.
    ///
    /// # Examples
    /// ```
    /// # extern crate alloc;
    /// # use alloc::sync::Arc;
    /// # use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
    /// # let memory = Memory::new(Arc::new(MemoryAccount::new(1024, 1024)));
    /// # let mut map = memory.map();
    /// # map.try_insert(1usize, 42)?;
    /// assert_eq!(map.get(&1, &memory)?, Some(&42));
    /// assert_eq!(map.get(&2, &memory)?, None);
    /// # Ok::<(), MemoryError>(())
    /// ```
    pub fn get(&self, key: &K, execution: &impl Work) -> Result<Option<&V>, MemoryError> {
        self.get_key_value_borrowed(key, execution)
            .map(|entry| entry.map(|(_, value)| value))
    }

    /// Finds the canonical stored key and value using an allocation-free query.
    ///
    /// Owned and borrowed forms must have identical Hash/Eq semantics, as
    /// required by [`Borrow`]. Current work admits query hashing, table probes
    /// and every candidate comparison before executing them. The stored key's
    /// [`HashWork`] bound must also cover its `Borrow<Q>` operation, which must
    /// not allocate. A refusal returns `Err`, never successful absence or a
    /// synthetic match. No table/account is rebound and no query key is copied.
    ///
    /// Returning the canonical key lets an interner clone its existing shared
    /// owner without a second lookup or a temporary owned query allocation.
    ///
    /// ```
    /// use std::sync::Arc;
    /// use structured_asn1::memory::{Memory, MemoryAccount};
    /// let storage = Memory::new(Arc::new(MemoryAccount::new(4096, 4096)));
    /// let mut map = storage.map();
    /// map.try_insert(7usize, "retained")?;
    /// let query = Memory::new(Arc::new(MemoryAccount::new(0, 1024)));
    /// assert_eq!(map.get_key_value_borrowed(&7, &query)?, Some((&7, &"retained")));
    /// # Ok::<(), structured_asn1::memory::MemoryError>(())
    /// ```
    pub fn get_key_value_borrowed<Q: HashWork + ?Sized>(
        &self,
        key: &Q,
        execution: &impl Work,
    ) -> Result<Option<(&K, &V)>, MemoryError>
    where
        K: Borrow<Q>,
    {
        let hash = self.hash_key(key, execution)?;
        let mut failure = None;
        let entry = self.values.raw_entry().from_hash(hash, |candidate| {
            equivalent(execution, key, candidate, &mut failure)
        });
        if let Some(reason) = failure {
            return Err(reason);
        }
        Ok(entry)
    }

    /// Looks up an entry for mutation without exposing table growth.
    /// Hashing, probing and equality use the supplied execution domain.
    ///
    /// # Examples
    /// ```
    /// # extern crate alloc;
    /// # use alloc::sync::Arc;
    /// # use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
    /// # let memory = Memory::new(Arc::new(MemoryAccount::new(1024, 1024)));
    /// # let mut map = memory.map();
    /// # map.try_insert(1usize, 42)?;
    /// if let Some(value) = map.get_mut(&1, &memory)? { *value = 7; }
    /// assert_eq!(map.get(&1, &memory)?, Some(&7));
    /// # Ok::<(), MemoryError>(())
    /// ```
    pub fn get_mut(
        &mut self,
        key: &K,
        execution: &impl Work,
    ) -> Result<Option<&mut V>, MemoryError> {
        self.get_mut_borrowed(key, execution)
    }

    /// Finds a mutable value using an allocation-free borrowed query.
    ///
    /// Uses the same Hash/Eq/`Borrow` and [`HashWork`] requirements as
    /// [`Self::get_key_value_borrowed`]. Current work admits hashing, probes and
    /// each candidate comparison before exposing a mutable value. Refusal is
    /// `Err`, never absence or a synthetic match. No owned query, second lookup
    /// or table/account rebinding is performed.
    pub fn get_mut_borrowed<Q: HashWork + ?Sized>(
        &mut self,
        key: &Q,
        execution: &impl Work,
    ) -> Result<Option<&mut V>, MemoryError>
    where
        K: Borrow<Q>,
    {
        let hash = self.hash_key(key, execution)?;
        let mut failure = None;
        let entry = self.values.raw_entry_mut().from_hash(hash, |candidate| {
            equivalent(execution, key, candidate, &mut failure)
        });
        if let Some(reason) = failure {
            return Err(reason);
        }
        Ok(match entry {
            RawEntryMut::Occupied(entry) => Some(entry.into_mut()),
            RawEntryMut::Vacant(_) => None,
        })
    }

    /// Inserts a value fallibly, or replaces the value for an existing key.
    /// This storage mutation runs in the collection's original resource
    /// domain, including hashing, rehashing, allocation and copying work.
    /// To mutate under a different domain, build a new collection there from
    /// explicitly admitted borrowed entries; retained capacity is not rebound.
    pub fn try_insert(&mut self, key: K, value: V) -> Result<Option<V>, MemoryError> {
        let hash = self.hash_key(&key, &self.execution)?;
        let mut failure = None;
        let entry = self.values.raw_entry_mut().from_hash(hash, |candidate| {
            equivalent(&self.execution, &key, candidate, &mut failure)
        });
        if let Some(reason) = failure {
            return Err(reason);
        }
        if let RawEntryMut::Occupied(entry) = entry {
            let moves = (core::mem::size_of::<V>() as u64)
                .checked_mul(2)
                .ok_or(MemoryError::WorkExceeded)?;
            self.execution.charge_work(moves)?;
            return Ok(Some(core::mem::replace(entry.into_mut(), value)));
        }
        let key_work = self
            .key_work
            .checked_add(key.hash_work()?)
            .ok_or(MemoryError::WorkExceeded)?;
        if self.values.len() == self.values.capacity() {
            // Include collision-dependent slot searches, not just key hashes.
            self.execution.charge_work(self.rehash_work()?)?;
            self.values.allocator().clear_failure();
            self.values.try_reserve(1).map_err(|error| match error {
                TryReserveError::CapacityOverflow => MemoryError::CapacityOverflow,
                TryReserveError::AllocError { .. } => self.values.allocator().failure(),
            })?;
            self.maximum_capacity = self.maximum_capacity.max(self.values.capacity());
        }
        // Reuse the already computed hash after reserve. No key equality is
        // needed: the first lookup established absence and resize preserves keys.
        // raw_entry searches for a match; insert_hashed_nocheck subsequently
        // searches for an insertion slot. Admit both control traversals.
        self.execution.charge_work(
            self.control_work()?
                .checked_mul(2)
                .and_then(|work| work.checked_add(core::mem::size_of::<(K, V)>() as u64))
                .ok_or(MemoryError::WorkExceeded)?,
        )?;
        let RawEntryMut::Vacant(entry) = self.values.raw_entry_mut().from_hash(hash, |_| false)
        else {
            unreachable!("a predicate that always refuses cannot find an entry");
        };
        entry.insert_hashed_nocheck(hash, key, value);
        self.key_work = key_work;
        Ok(None)
    }

    /// Removes an entry, retaining table capacity and its storage charge.
    /// The supplied execution domain pays for lookup and removal before mutation.
    ///
    /// # Examples
    /// ```
    /// # extern crate alloc;
    /// # use alloc::sync::Arc;
    /// # use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
    /// # let memory = Memory::new(Arc::new(MemoryAccount::new(1024, 1024)));
    /// # let mut map = memory.map();
    /// # map.try_insert(1usize, 42)?;
    /// let capacity_charge = memory.used();
    /// assert_eq!(map.remove(&1, &memory)?, Some(42));
    /// assert_eq!(memory.used(), capacity_charge);
    /// # Ok::<(), MemoryError>(())
    /// ```
    pub fn remove(&mut self, key: &K, execution: &impl Work) -> Result<Option<V>, MemoryError> {
        self.remove_borrowed(key, execution)
    }

    /// Removes a value using an allocation-free borrowed query.
    ///
    /// Uses the same Hash/Eq/`Borrow` and [`HashWork`] requirements as
    /// [`Self::get_key_value_borrowed`]. Current work admits lookup and erase
    /// metadata/value movement before mutation. Refusal leaves the entry intact.
    /// The original table capacity and allocator remain retained; the removed
    /// key is dropped and the value transfers its independent ownership.
    /// Arbitrary key/value destructor work remains caller-owned.
    pub fn remove_borrowed<Q: HashWork + ?Sized>(
        &mut self,
        key: &Q,
        execution: &impl Work,
    ) -> Result<Option<V>, MemoryError>
    where
        K: Borrow<Q>,
    {
        let hash = self.hash_key(key, execution)?;
        let mut failure = None;
        let entry = self.values.raw_entry_mut().from_hash(hash, |candidate| {
            equivalent(execution, key, candidate, &mut failure)
        });
        if let Some(reason) = failure {
            return Err(reason);
        }
        let entry = match entry {
            RawEntryMut::Occupied(entry) => {
                // Erase examines the adjacent control groups; returning the
                // pair moves its storage. Admit both before changing the table.
                let work = (core::mem::size_of::<(K, V)>() as u64)
                    .checked_mul(2)
                    .and_then(|work| work.checked_add(2))
                    .ok_or(MemoryError::WorkExceeded)?;
                let removed_work = entry.key().hash_work()?;
                execution.charge_work(work)?;
                let (removed_key, value) = entry.remove_entry();
                self.key_work -= removed_work;
                // Settle metadata before caller-owned Drop can unwind.
                drop(removed_key);
                Some(value)
            }
            RawEntryMut::Vacant(_) => None,
        };
        Ok(entry)
    }
}

/// A synthetic match stops hashbrown immediately on exhaustion. The caller
/// checks failure before exposing or mutating the matched entry, so no false
/// equality escapes and no expensive comparison runs after a refusal.
fn equivalent<K: HashWork + Borrow<Q>, Q: HashWork + ?Sized, W: Work>(
    memory: &W,
    query: &Q,
    candidate: &K,
    failure: &mut Option<MemoryError>,
) -> bool {
    let cost = query.hash_work().and_then(|query| {
        candidate.hash_work().and_then(|candidate| {
            query
                .checked_add(candidate)
                .ok_or(MemoryError::WorkExceeded)
        })
    });
    let admitted = cost.and_then(|cost| memory.charge_work(cost));
    if let Err(reason) = admitted {
        *failure = Some(reason);
        return true;
    }
    query == candidate.borrow()
}
