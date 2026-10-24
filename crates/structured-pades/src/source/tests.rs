use super::{Location, Source};
use structured_asn1::Span;

#[test]
fn compact_coordinates_preserve_every_original_domain_and_checked_boundary() {
    // Packing revision presence must not conflate physical and decoded EOF
    // points, truncate a stage, or claim a decoded span is a physical range.
    for source in [
        Source::File,
        Source::Decoded {
            stream: Span {
                start: 1000,
                length: 90,
            },
            revision: 0,
            stage: usize::MAX,
        },
        Source::Decoded {
            stream: Span {
                start: 20,
                length: 0,
            },
            revision: usize::MAX - 1,
            stage: 0,
        },
    ] {
        let location = Location::new(source, 7, 0).unwrap();
        assert_eq!(location.source(), source);
        assert_eq!(
            location.span(),
            Span {
                start: 7,
                length: 0
            }
        );
        assert_eq!(location.end(), 7);
        assert!(!location.contains(7));
        match source {
            Source::File => assert_eq!(location.enclosing(), location.span()),
            Source::Decoded { stream, .. } => assert_eq!(location.enclosing(), stream),
        }
    }
    assert!(Location::new(Source::File, u64::MAX, 1).is_none());
    assert!(
        Location::new(
            Source::Decoded {
                stream: Span {
                    start: u64::MAX,
                    length: 1
                },
                revision: 0,
                stage: 0,
            },
            0,
            0
        )
        .is_none()
    );
    assert!(
        Location::new(
            Source::Decoded {
                stream: Span {
                    start: 0,
                    length: 0
                },
                revision: usize::MAX,
                stage: 0,
            },
            0,
            0
        )
        .is_none()
    );
    assert!(core::mem::size_of::<Location>() <= core::mem::size_of::<(Source, Span)>());
}
