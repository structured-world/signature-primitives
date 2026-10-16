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
fn calendar_projection_reuses_gregorian_core_and_preserves_leap_labels() {
    // XAdES identifier times may use offsets and end-of-day notation. The
    // shared projection must cross date/year boundaries without reparsing text
    // or discarding an inserted-second label.
    let work = crate::fixtures::memory();
    for (encoded, offset, expected) in [
        ("20260101000000Z", -1440, (2025, 12, 31, 0, 0, 0)),
        ("99991231235959Z", 1, (10000, 1, 1, 0, 0, 59)),
        ("00000101000000Z", -1, (-1, 12, 31, 23, 59, 0)),
        ("20161231235960Z", 150, (2017, 1, 1, 2, 29, 60)),
    ] {
        let time = time_of(&generalized_time(encoded)).unwrap();
        let projected = time.calendar_at_minutes(offset, &work).unwrap();
        assert_eq!(
            (
                projected.year,
                projected.month,
                projected.day,
                projected.hour,
                projected.minute,
                projected.second
            ),
            expected
        );
        assert_eq!(projected.nanos, 0);
    }
    let fractional = Time {
        instant: crate::temporal::Instant::new(1_767_225_600, 123_456_789).unwrap(),
        form: Form::Generalized,
    };
    assert_eq!(
        fractional.calendar_at_minutes(0, &work).unwrap().nanos,
        123_456_789
    );
}

#[test]
fn calendar_projection_admits_fixed_work_before_conversion() {
    // Metadata conversion still requires the CURRENT operation's CPU budget;
    // no output allocation or source-account credit is necessary.
    use alloc::sync::Arc;
    use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
    let time = time_of(&generalized_time("20260101000000Z")).unwrap();
    let denied = Memory::new(Arc::new(MemoryAccount::new(0, 63)));
    assert_eq!(
        time.calendar_at_minutes(0, &denied),
        Err(MemoryError::WorkExceeded)
    );
    assert_eq!(denied.work_used(), 0);
    let exact = Memory::new(Arc::new(MemoryAccount::new(0, 64)));
    assert_eq!(time.calendar_at_minutes(0, &exact).unwrap().year, 2026);
    assert_eq!(exact.work_used(), 64);
    assert_eq!(exact.used(), 0);
}

#[test]
fn xsd10_normalization_has_its_own_calendar_value_contract() {
    // XSD1.0 Appendix E uses signed-year leap arithmetic, no year zero and
    // overflow normalization for second60; UTC identity remains unchanged.
    use super::Xsd10Label;
    let work = crate::fixtures::memory();
    let label = Xsd10Label {
        year: -1,
        month: 3,
        day: 1,
        hour: 0,
        minute: 30,
        second: 0,
        nanos: 0,
    };
    let utc = label.at_utc(60, &work).unwrap().unwrap();
    assert_eq!(
        (utc.year, utc.month, utc.day, utc.hour, utc.minute),
        (-1, 2, 28, 23, 30)
    );
    let leap = time_of(&generalized_time("20161231235960Z")).unwrap();
    let utc = leap
        .xsd10_label(&work)
        .unwrap()
        .at_utc(0, &work)
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            utc.year, utc.month, utc.day, utc.hour, utc.minute, utc.second
        ),
        (2017, 1, 1, 0, 0, 0)
    );
    assert!(leap.is_leap_second());
    for (year, month, day, expected) in [(-1, 2, 29, false), (-4, 2, 29, true), (0, 1, 1, false)] {
        assert_eq!(
            Xsd10Label {
                year,
                month,
                day,
                ..label
            }
            .at_utc(0, &work)
            .unwrap()
            .is_some(),
            expected
        );
    }
    let end = Xsd10Label {
        year: -1,
        month: 12,
        day: 31,
        hour: 24,
        minute: 0,
        ..label
    };
    assert_eq!(end.at_utc(0, &work).unwrap().unwrap().year, 1);
}

#[test]
fn xsd10_normalization_refusal_precedes_any_conversion() {
    // A previously decoded label is not CPU credit for the current query.
    use alloc::sync::Arc;
    use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
    let label = super::Xsd10Label {
        year: 2026,
        month: 1,
        day: 1,
        hour: 0,
        minute: 0,
        second: 0,
        nanos: 0,
    };
    let denied = Memory::new(Arc::new(MemoryAccount::new(0, 127)));
    assert_eq!(label.at_utc(0, &denied), Err(MemoryError::WorkExceeded));
    assert_eq!(denied.work_used(), 0);
    let exact = Memory::new(Arc::new(MemoryAccount::new(0, 128)));
    assert_eq!(label.at_utc(0, &exact).unwrap(), Some(label));
    assert_eq!(exact.work_used(), 128);
    assert_eq!(exact.used(), 0);
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
