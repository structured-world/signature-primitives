use super::{Form, NO_WELL_DEFINED_EXPIRY, Time, read};
use crate::error::ErrorCode;
use crate::fixtures::{generalized_time, printable, utc_time};
use alloc::format;
use structured_asn1::Parser;

/// Reads the one element in `der` as a time.
fn time_of(der: &[u8]) -> crate::error::Result<Time> {
    let parser = Parser::der(crate::fixtures::memory());
    let mut reader = parser.read(der, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    read(&element, "test")
}

#[test]
fn both_forms_name_the_same_moment() {
    let two_digit = time_of(&utc_time("240701091500Z")).unwrap();
    let four_digit = time_of(&generalized_time("20240701091500Z")).unwrap();

    assert_eq!(two_digit, four_digit);
    assert_eq!(two_digit.seconds(), 1_719_825_300);
    assert_eq!(format!("{two_digit}"), "2024-07-01T09:15:00Z");
    // Equal as moments, and still distinguishable as encodings, because a
    // report has to explain what the certificate said.
    assert_eq!(two_digit.form(), Form::Utc);
    assert_eq!(four_digit.form(), Form::Generalized);
}

#[test]
fn a_two_digit_year_lands_in_the_window_the_profile_fixes() {
    // 50 and above is the twentieth century, below it the twenty-first, so a
    // certificate issued in 1998 does not become one issued in 2098.
    let older = time_of(&utc_time("980115000000Z")).unwrap();
    assert_eq!(format!("{older}"), "1998-01-15T00:00:00Z");

    let newer = time_of(&utc_time("490115000000Z")).unwrap();
    assert_eq!(format!("{newer}"), "2049-01-15T00:00:00Z");

    let pivot = time_of(&utc_time("500101000000Z")).unwrap();
    assert_eq!(format!("{pivot}"), "1950-01-01T00:00:00Z");
}

#[test]
fn moments_before_the_epoch_are_read_and_rendered() {
    // Certificates from the nineties are still in trusted lists as historical
    // roots, and a negative count is the answer rather than a refusal.
    let old = time_of(&utc_time("960201123000Z")).unwrap();
    assert_eq!(old.seconds(), 823_177_800);

    let older = time_of(&generalized_time("19510302000000Z")).unwrap();
    assert!(older.seconds() < 0);
    assert_eq!(format!("{older}"), "1951-03-02T00:00:00Z");
}

#[test]
fn the_leap_day_exists_only_in_a_leap_year() {
    assert!(time_of(&generalized_time("20240229120000Z")).is_ok());
    assert!(time_of(&generalized_time("20000229120000Z")).is_ok());

    for absent in ["20230229120000Z", "19000229120000Z"] {
        let error = time_of(&generalized_time(absent)).unwrap_err();
        assert_eq!(error.code(), ErrorCode::TimeOutOfRange, "{absent}");
    }
}

#[test]
fn a_moment_that_does_not_exist_is_refused() {
    for absent in [
        "20240001000000Z", // month zero
        "20241301000000Z", // thirteenth month
        "20240100000000Z", // day zero
        "20240631000000Z", // a thirty-first of June
        "20240101240000Z", // an hour past the day
        "20240101006000Z", // a minute past the hour
        "20161231235860Z", // insertion label outside the UTC day's last minute
        "20161231235961Z", // past an inserted second
    ] {
        let error = time_of(&generalized_time(absent)).unwrap_err();
        assert_eq!(error.code(), ErrorCode::TimeOutOfRange, "{absent}");
    }
}

#[test]
fn generalized_leap_label_is_distinct_and_der_conforming() {
    // DER spelling must accept a GeneralizedTime leap label without aliasing
    // either neighbour. Occurrence is a separate caller-supplied UTC fact.
    let before = time_of(&generalized_time("20161231235959Z")).unwrap();
    let leap = time_of(&generalized_time("20161231235960Z")).unwrap();
    let after = time_of(&generalized_time("20170101000000Z")).unwrap();
    assert!(before < leap && leap < after);
    assert_eq!(format!("{leap}"), "2016-12-31T23:59:60Z");
    for text in ["20161231235960Z", "20161231235960.1234567891Z"] {
        let bytes = generalized_time(text);
        let parser = Parser::der(crate::fixtures::memory());
        let mut reader = parser.read(&bytes, 37).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        crate::der::conforms(&reader, &element, "test").unwrap();
        assert!(
            crate::temporal::read_generalized(&reader, &element, "test")
                .unwrap()
                .start()
                .is_leap_second()
        );
    }
}

#[test]
fn utc_time_does_not_inherit_generalized_leap_grammar() {
    // X.680 §47.3 explicitly bounds UTCTime seconds to 00..59.
    let error = time_of(&utc_time("161231235960Z")).unwrap_err();
    assert_eq!(error.code(), ErrorCode::TimeOutOfRange);
}

#[test]
fn only_the_fixed_width_form_with_seconds_and_zulu_is_read() {
    // Every one of these is a second way to write a moment already written
    // once, and a certificate is only ever the bytes it arrived as.
    for other in [
        "2024070109150Z",      // a digit short
        "202407010915000Z",    // a digit long
        "20240701091500",      // no zone
        "20240701091500+0200", // an offset from local time
        "20240701091500.5Z",   // a fraction of a second
        "202407010915Z",       // minutes without seconds
        "2024070109150aZ",     // not digits
    ] {
        let error = time_of(&generalized_time(other)).unwrap_err();
        assert_eq!(error.code(), ErrorCode::MalformedTime, "{other}");
    }

    for other in ["2407010915Z", "240701091500+0200", "2407010915000Z"] {
        let error = time_of(&utc_time(other)).unwrap_err();
        assert_eq!(error.code(), ErrorCode::MalformedTime, "{other}");
    }
}

#[test]
fn an_element_that_is_not_a_time_is_refused() {
    let error = time_of(&printable("20240701091500Z")).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
    );
}

#[test]
fn the_moment_the_profile_uses_for_no_expiry_is_reported_as_itself() {
    let forever = time_of(&generalized_time("99991231235959Z")).unwrap();

    assert_eq!(forever.seconds(), NO_WELL_DEFINED_EXPIRY);
    assert!(forever.is_no_well_defined_expiry());
    assert_eq!(format!("{forever}"), "9999-12-31T23:59:59Z");

    // A moment one second earlier is an ordinary expiry, and calling it the
    // convention would turn a certificate that expires into one that does not.
    let ordinary = time_of(&generalized_time("99991231235958Z")).unwrap();
    assert!(!ordinary.is_no_well_defined_expiry());
}

#[test]
fn a_year_is_written_in_fifty_two_weeks_or_fifty_three() {
    // The long year is the one beginning on a Thursday, and the leap year
    // beginning on a Wednesday (ISO 8601 4.1.4). These are the years either
    // side of the rule, checked against the calendar rather than against the
    // formula that produces them.
    for year in [2004, 2009, 2015, 2020, 2026, 2032] {
        assert_eq!(super::weeks_in_year(year), 53, "{year}");
    }
    for year in [2019, 2021, 2022, 2023, 2024, 2025] {
        assert_eq!(super::weeks_in_year(year), 52, "{year}");
    }
}
