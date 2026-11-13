//! Unicode 17.0.0 default full case folding for name preparation.
//!
//! Use the same Unicode data across compiler versions. The preparation
//! pipeline applies folding before and after normalization for the
//! compatibility mappings described by RFC 4518 section 2.2.

mod data;

/// The full fold of one character.
pub(super) enum Fold {
    /// A mapping that expands to multiple characters.
    Mapped(&'static str),
    /// An unchanged character or a single-character mapping.
    One(char),
}

pub(super) fn of(c: char) -> Fold {
    if c.is_ascii() {
        return Fold::One(c.to_ascii_lowercase());
    }
    let point = u32::from(c);
    let at = data::SINGLE.partition_point(|&(_, end, _, _)| end < point);
    if let Some(&(start, _, destination, stride)) = data::SINGLE.get(at)
        && point >= start
        && (point - start).is_multiple_of(stride)
    {
        return Fold::One(
            char::from_u32(destination + point - start)
                .expect("Unicode case folding maps to a scalar"),
        );
    }
    match data::MULTI.binary_search_by_key(&c, |&(from, _)| from) {
        Ok(at) => Fold::Mapped(data::MULTI[at].1),
        Err(_) => Fold::One(c),
    }
}

#[cfg(test)]
mod tests;
