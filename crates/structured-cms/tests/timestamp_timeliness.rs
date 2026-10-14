//! Freshness facts cannot turn absent accuracy into zero or hide failed checks.

use structured_cms::timestamp::{
    Accuracy, BoundUncertainty, RequestWindow, Timeliness, timeliness,
};
use structured_pkix::temporal::{Instant, LeapTable, Reading};

fn at(seconds: i64) -> Instant {
    Instant::new(seconds, 0).unwrap()
}

#[test]
fn nonce_does_not_override_performed_future_or_window_failure() {
    // Independently matching nonce never erases a completed negative temporal
    // comparison, including when only one accuracy endpoint crosses the window.
    let utc = LeapTable::new(0, 100, &[]).unwrap();
    let window = RequestWindow::for_unique_imprint(at(45), at(55)).unwrap();
    let reading = Reading::from(at(50));
    assert_eq!(
        timeliness(
            reading,
            Some(Accuracy::new(1, 0, 0)),
            &utc,
            Some(at(48)),
            true,
            Some(true),
            Some(window)
        ),
        Timeliness::Future
    );
    assert_eq!(
        timeliness(
            reading,
            Some(Accuracy::new(6, 0, 0)),
            &utc,
            Some(at(90)),
            true,
            Some(true),
            Some(window)
        ),
        Timeliness::OutsideWindow
    );
    assert_eq!(
        timeliness(
            reading,
            Some(Accuracy::new(5, 0, 0)),
            &utc,
            Some(at(90)),
            true,
            Some(true),
            Some(window)
        ),
        Timeliness::LocalWindow
    );
}

#[test]
fn unstated_accuracy_nonce_fallback_and_archived_evidence_stay_distinct() {
    // Missing accuracy never yields a zero interval. Nonce can independently
    // establish live-response freshness, but archived facts claim no live request.
    let utc = LeapTable::new(0, 100, &[]).unwrap();
    let reading = Reading::from(at(50));
    let window = RequestWindow::for_unique_imprint(at(45), at(55)).unwrap();
    assert_eq!(
        timeliness(
            reading,
            None,
            &utc,
            Some(at(90)),
            true,
            Some(true),
            Some(window)
        ),
        Timeliness::RequestNonce
    );
    assert_eq!(
        timeliness(
            reading,
            None,
            &utc,
            Some(at(90)),
            true,
            Some(false),
            Some(window)
        ),
        Timeliness::Uncertain(BoundUncertainty::AccuracyUnstated)
    );
    assert_eq!(
        timeliness(
            reading,
            Some(Accuracy::new(0, 0, 0)),
            &utc,
            Some(at(90)),
            false,
            None,
            None
        ),
        Timeliness::NotRequested
    );
    assert_eq!(
        timeliness(reading, None, &utc, None, true, Some(false), None),
        Timeliness::Unverified
    );
    assert!(RequestWindow::for_unique_imprint(at(55), at(45)).is_none());
}
