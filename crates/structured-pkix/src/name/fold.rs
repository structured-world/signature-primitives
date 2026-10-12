//! Case folding for name comparison.
//!
//! The comparison profile prepares a string by folding its case
//! (RFC 4518 2.2, required by RFC 5280 7.1), and folding is not lowercasing:
//! a few letters fold to something of a different length or a different
//! letter entirely. The sharp s folds to `ss`, so `Straße` and `STRASSE` are
//! one organization; final sigma folds to sigma, so a Greek name written
//! with the letter that ends a word is the same name; the ligatures fold to
//! the letters they are made of. Reading only the lowercase mapping leaves
//! each of those as two names and a genuine certification path unbuilt.
//!
//! Most of the map is the simple lowercase mapping, which the standard
//! library carries and keeps current, so what is written out here is only
//! where the fold and the lowercase differ: the full case folding of
//! `CaseFolding.txt` (statuses C and F) minus everything the lowercase
//! already produces. The two contiguous stretches of Cherokee are written as
//! arithmetic rather than as entries.
//!
//! The profile names the table of RFC 3454 B.2, which is this fold frozen at
//! Unicode 3.2 and carrying, in addition, the compatibility mappings folded:
//! `2102; 0063; Additional folding` takes the double-struck capital C to a
//! lowercase c in one step, where this fold leaves it alone and the
//! normalization after it produces a capital. The difference is made up by
//! running this fold on both sides of the normalization, which the pipeline
//! does; it is not made up by the normalization alone, and an earlier
//! reading here that said so was wrong.

/// What one character folds to.
pub(super) enum Fold {
    /// The characters it folds to, where the fold is not the lowercase.
    Mapped(&'static str),
    /// One character, arrived at by arithmetic rather than by a listing.
    One(char),
    /// The simple lowercase mapping is the fold.
    Lowercase,
}

/// The fold of one character.
pub(super) fn of(c: char) -> Fold {
    // Cherokee: the lowercase letters added in Unicode 8 fold back to the
    // syllabary they were added beside, in two unbroken stretches, so they
    // are a difference rather than eighty-six entries.
    let point = u32::from(c);
    let cherokee = if (0x13F8..=0x13FD).contains(&point) {
        Some(point - 8)
    } else if (0xAB70..=0xABBF).contains(&point) {
        Some(point - 0x97D0)
    } else {
        None
    };
    if let Some(folded) = cherokee {
        // Both stretches land inside the syllabary, which is assigned.
        return Fold::One(char::from_u32(folded).expect("a Cherokee syllable"));
    }
    // And the syllabary itself is where the fold and the lowercase part
    // company in the other direction: Cherokee writes its folded form in
    // capitals, so these have no fold at all while lowering them would move
    // them onto the letters above. A fold that moves a character the file
    // leaves alone makes two names equal that the profile does not.
    if (0x13A0..=0x13F5).contains(&point) {
        return Fold::One(c);
    }
    match TABLE.binary_search_by_key(&c, |&(from, _)| from) {
        Ok(at) => Fold::Mapped(TABLE[at].1),
        Err(_) => Fold::Lowercase,
    }
}

/// Where the full case fold differs from the simple lowercase mapping,
/// sorted by the character folded.
static TABLE: [(char, &str); 125] = [
    ('\u{00B5}', "\u{03BC}"),
    ('\u{00DF}', "\u{0073}\u{0073}"),
    ('\u{0149}', "\u{02BC}\u{006E}"),
    ('\u{017F}', "\u{0073}"),
    ('\u{01F0}', "\u{006A}\u{030C}"),
    ('\u{0345}', "\u{03B9}"),
    ('\u{0390}', "\u{03B9}\u{0308}\u{0301}"),
    ('\u{03B0}', "\u{03C5}\u{0308}\u{0301}"),
    ('\u{03C2}', "\u{03C3}"),
    ('\u{03D0}', "\u{03B2}"),
    ('\u{03D1}', "\u{03B8}"),
    ('\u{03D5}', "\u{03C6}"),
    ('\u{03D6}', "\u{03C0}"),
    ('\u{03F0}', "\u{03BA}"),
    ('\u{03F1}', "\u{03C1}"),
    ('\u{03F5}', "\u{03B5}"),
    ('\u{0587}', "\u{0565}\u{0582}"),
    ('\u{1C80}', "\u{0432}"),
    ('\u{1C81}', "\u{0434}"),
    ('\u{1C82}', "\u{043E}"),
    ('\u{1C83}', "\u{0441}"),
    ('\u{1C84}', "\u{0442}"),
    ('\u{1C85}', "\u{0442}"),
    ('\u{1C86}', "\u{044A}"),
    ('\u{1C87}', "\u{0463}"),
    ('\u{1C88}', "\u{A64B}"),
    ('\u{1E96}', "\u{0068}\u{0331}"),
    ('\u{1E97}', "\u{0074}\u{0308}"),
    ('\u{1E98}', "\u{0077}\u{030A}"),
    ('\u{1E99}', "\u{0079}\u{030A}"),
    ('\u{1E9A}', "\u{0061}\u{02BE}"),
    ('\u{1E9B}', "\u{1E61}"),
    ('\u{1E9E}', "\u{0073}\u{0073}"),
    ('\u{1F50}', "\u{03C5}\u{0313}"),
    ('\u{1F52}', "\u{03C5}\u{0313}\u{0300}"),
    ('\u{1F54}', "\u{03C5}\u{0313}\u{0301}"),
    ('\u{1F56}', "\u{03C5}\u{0313}\u{0342}"),
    ('\u{1F80}', "\u{1F00}\u{03B9}"),
    ('\u{1F81}', "\u{1F01}\u{03B9}"),
    ('\u{1F82}', "\u{1F02}\u{03B9}"),
    ('\u{1F83}', "\u{1F03}\u{03B9}"),
    ('\u{1F84}', "\u{1F04}\u{03B9}"),
    ('\u{1F85}', "\u{1F05}\u{03B9}"),
    ('\u{1F86}', "\u{1F06}\u{03B9}"),
    ('\u{1F87}', "\u{1F07}\u{03B9}"),
    ('\u{1F88}', "\u{1F00}\u{03B9}"),
    ('\u{1F89}', "\u{1F01}\u{03B9}"),
    ('\u{1F8A}', "\u{1F02}\u{03B9}"),
    ('\u{1F8B}', "\u{1F03}\u{03B9}"),
    ('\u{1F8C}', "\u{1F04}\u{03B9}"),
    ('\u{1F8D}', "\u{1F05}\u{03B9}"),
    ('\u{1F8E}', "\u{1F06}\u{03B9}"),
    ('\u{1F8F}', "\u{1F07}\u{03B9}"),
    ('\u{1F90}', "\u{1F20}\u{03B9}"),
    ('\u{1F91}', "\u{1F21}\u{03B9}"),
    ('\u{1F92}', "\u{1F22}\u{03B9}"),
    ('\u{1F93}', "\u{1F23}\u{03B9}"),
    ('\u{1F94}', "\u{1F24}\u{03B9}"),
    ('\u{1F95}', "\u{1F25}\u{03B9}"),
    ('\u{1F96}', "\u{1F26}\u{03B9}"),
    ('\u{1F97}', "\u{1F27}\u{03B9}"),
    ('\u{1F98}', "\u{1F20}\u{03B9}"),
    ('\u{1F99}', "\u{1F21}\u{03B9}"),
    ('\u{1F9A}', "\u{1F22}\u{03B9}"),
    ('\u{1F9B}', "\u{1F23}\u{03B9}"),
    ('\u{1F9C}', "\u{1F24}\u{03B9}"),
    ('\u{1F9D}', "\u{1F25}\u{03B9}"),
    ('\u{1F9E}', "\u{1F26}\u{03B9}"),
    ('\u{1F9F}', "\u{1F27}\u{03B9}"),
    ('\u{1FA0}', "\u{1F60}\u{03B9}"),
    ('\u{1FA1}', "\u{1F61}\u{03B9}"),
    ('\u{1FA2}', "\u{1F62}\u{03B9}"),
    ('\u{1FA3}', "\u{1F63}\u{03B9}"),
    ('\u{1FA4}', "\u{1F64}\u{03B9}"),
    ('\u{1FA5}', "\u{1F65}\u{03B9}"),
    ('\u{1FA6}', "\u{1F66}\u{03B9}"),
    ('\u{1FA7}', "\u{1F67}\u{03B9}"),
    ('\u{1FA8}', "\u{1F60}\u{03B9}"),
    ('\u{1FA9}', "\u{1F61}\u{03B9}"),
    ('\u{1FAA}', "\u{1F62}\u{03B9}"),
    ('\u{1FAB}', "\u{1F63}\u{03B9}"),
    ('\u{1FAC}', "\u{1F64}\u{03B9}"),
    ('\u{1FAD}', "\u{1F65}\u{03B9}"),
    ('\u{1FAE}', "\u{1F66}\u{03B9}"),
    ('\u{1FAF}', "\u{1F67}\u{03B9}"),
    ('\u{1FB2}', "\u{1F70}\u{03B9}"),
    ('\u{1FB3}', "\u{03B1}\u{03B9}"),
    ('\u{1FB4}', "\u{03AC}\u{03B9}"),
    ('\u{1FB6}', "\u{03B1}\u{0342}"),
    ('\u{1FB7}', "\u{03B1}\u{0342}\u{03B9}"),
    ('\u{1FBC}', "\u{03B1}\u{03B9}"),
    ('\u{1FBE}', "\u{03B9}"),
    ('\u{1FC2}', "\u{1F74}\u{03B9}"),
    ('\u{1FC3}', "\u{03B7}\u{03B9}"),
    ('\u{1FC4}', "\u{03AE}\u{03B9}"),
    ('\u{1FC6}', "\u{03B7}\u{0342}"),
    ('\u{1FC7}', "\u{03B7}\u{0342}\u{03B9}"),
    ('\u{1FCC}', "\u{03B7}\u{03B9}"),
    ('\u{1FD2}', "\u{03B9}\u{0308}\u{0300}"),
    ('\u{1FD3}', "\u{03B9}\u{0308}\u{0301}"),
    ('\u{1FD6}', "\u{03B9}\u{0342}"),
    ('\u{1FD7}', "\u{03B9}\u{0308}\u{0342}"),
    ('\u{1FE2}', "\u{03C5}\u{0308}\u{0300}"),
    ('\u{1FE3}', "\u{03C5}\u{0308}\u{0301}"),
    ('\u{1FE4}', "\u{03C1}\u{0313}"),
    ('\u{1FE6}', "\u{03C5}\u{0342}"),
    ('\u{1FE7}', "\u{03C5}\u{0308}\u{0342}"),
    ('\u{1FF2}', "\u{1F7C}\u{03B9}"),
    ('\u{1FF3}', "\u{03C9}\u{03B9}"),
    ('\u{1FF4}', "\u{03CE}\u{03B9}"),
    ('\u{1FF6}', "\u{03C9}\u{0342}"),
    ('\u{1FF7}', "\u{03C9}\u{0342}\u{03B9}"),
    ('\u{1FFC}', "\u{03C9}\u{03B9}"),
    ('\u{FB00}', "\u{0066}\u{0066}"),
    ('\u{FB01}', "\u{0066}\u{0069}"),
    ('\u{FB02}', "\u{0066}\u{006C}"),
    ('\u{FB03}', "\u{0066}\u{0066}\u{0069}"),
    ('\u{FB04}', "\u{0066}\u{0066}\u{006C}"),
    ('\u{FB05}', "\u{0073}\u{0074}"),
    ('\u{FB06}', "\u{0073}\u{0074}"),
    ('\u{FB13}', "\u{0574}\u{0576}"),
    ('\u{FB14}', "\u{0574}\u{0565}"),
    ('\u{FB15}', "\u{0574}\u{056B}"),
    ('\u{FB16}', "\u{057E}\u{0576}"),
    ('\u{FB17}', "\u{0574}\u{056D}"),
];

#[cfg(test)]
mod tests;
