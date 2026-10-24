//! Stable source identity, independent of a format or acquisition mechanism.

/// Original document identity and the exact immutable view generation.
/// A generation change invalidates earlier source-derived evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot<D, G> {
    /// Stable identity supplied by the source owner, not a fingerprint.
    pub document: D,
    /// Generation under which source ranges and evidence were obtained.
    pub generation: G,
}
