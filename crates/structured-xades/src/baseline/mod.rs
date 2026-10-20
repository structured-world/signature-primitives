//! Composition of source-bound baseline facts, separate from caller trust.
//!
//! Start with [`crate::prepare::check_fields`], the complete original counter
//! paths and actual-use hash census, then bind the selected original signing
//! certificate and all signed certificate digests to the checked path.
//! [`basic()`] joins those receipts, exact original header inclusion and every
//! optional issuer hint without repeating root scalar or cryptographic work.
//! [`Basic`], [`crate::material::Checks`], [`crate::material::credentials::Report`]
//! and [`crate::prepare::Preparation`] are the `XAdES` stage reports that the
//! format-neutral [`structured_ltv::baseline`] compositions join.
//!
//! [`structured_ltv::baseline::timestamped`] requires
//! [`structured_ltv::timestamp::TimestampPaths`] for the entire original
//! root/counter token census. Its static time findings cover EACH root
//! signature timestamp's full generation interval. A later source query still
//! needs its own execution allowance; retained facts are not prepaid work.
//!
//! [`structured_ltv::baseline::long_term`] links all X.509 presence/placement
//! findings and every actual credential's format-material findings to that
//! SAME participant/status input closure. Equal document/node IDs cannot
//! replace receipt identity. For each archive, use
//! [`structured_ltv::material::archived_participants`] and
//! [`crate::material::credentials::Scope::before_archive`] with the same original
//! input coverage and mathematical token evidence, then
//! [`structured_ltv::baseline::archive_material`] to join their exact scope and
//! authenticated credential input. [`structured_ltv::baseline::archives`]
//! requires every original root archive, including those with material gaps;
//! a successful subset or repeated proof cannot complete that census. Own/later
//! material cannot repair an earlier archive. [`crate::renewed::check_prepared`]
//! processes every written root renewal and retains every original pair through
//! the same [`crate::renewed::check`] kernel, independently of incorporation.
//!
//! The requested structural profile remains on the original preparation.
//! Additional containers never promote it. [`assess`] joins the stage reports
//! of exactly that level and states whether all of its conditions hold.
//! Inspect all detailed negative facts: material incorporation is not usable
//! revocation, static validity is not pre-revocation chronology, and
//! mathematical timestamps are not historical application trust or
//! algorithm-longevity policy. No report here is a trust verdict.

mod basic;
pub use basic::{Basic, BasicError, BasicInput, BasicResult, Hint, HintSource, basic};
mod level;
pub use level::{Assessment, Evidence, LevelError, assess};
