use super::*;
use crate::timestamp::Role;

#[test]
fn another_timestamp_token_cannot_supply_self_carried_validation_data() {
    // Siblings and two tokens inside the SAME property are distinct. No
    // URI hint, global timestamp-purpose bit or encoding hash reassigns it.
    for (property, token, expected, cost) in [(4, 8, true, 2), (4, 9, false, 2), (5, 8, false, 1)] {
        let mut calls = 0;
        let placement = Placement::TimestampToken {
            property,
            token,
            role: Role::Signature,
        };
        assert_eq!(
            allowed(placement, 4, 8, &mut |left, right| {
                calls += 1;
                Ok::<_, ()>(left == right)
            }),
            Ok(expected)
        );
        assert_eq!(calls, cost);
    }
    for placement in [Placement::General(1), Placement::Timestamp(2)] {
        assert_eq!(
            allowed(placement, 4, 8, &mut |_, _| -> Result<bool, ()> {
                panic!("no fabricated token association")
            }),
            Ok(true)
        );
    }
    for placement in [
        Placement::KeyInfo(1),
        Placement::Signature(2),
        Placement::Attribute(3),
    ] {
        assert_eq!(
            allowed(placement, 4, 8, &mut |_, _| -> Result<bool, ()> {
                panic!("placement is already excluded")
            }),
            Ok(false)
        );
    }
}

#[test]
fn token_identity_refusal_does_not_become_missing_or_allowed_material() {
    // Both original IDs are paid before comparison; preserve the first
    // failure instead of treating a budget error as a nonmatching copy.
    let placement = Placement::TimestampToken {
        property: 4,
        token: 8,
        role: Role::Signature,
    };
    assert_eq!(
        allowed(placement, 4, 8, &mut |_, _| Err::<bool, _>(
            MemoryError::WorkExceeded
        )),
        Err(MemoryError::WorkExceeded)
    );
}
