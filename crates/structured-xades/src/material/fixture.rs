//! Trusted metadata-only DER fixtures; no signature/path authentication claim.

use alloc::vec::Vec;
use structured_pkix::Version;

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    assert!(value.len() < 128, "fixture only writes short DER lengths");
    let mut result = alloc::vec![tag, u8::try_from(value.len()).unwrap()];
    result.extend_from_slice(value);
    result
}

fn algorithm() -> Vec<u8> {
    tlv(0x30, &tlv(6, &[42, 3]))
}
fn bits() -> Vec<u8> {
    tlv(3, &[0, 1])
}
fn name() -> Vec<u8> {
    tlv(
        0x30,
        &tlv(
            0x31,
            &tlv(0x30, &[tlv(6, &[0x55, 4, 3]), tlv(12, b"a")].concat()),
        ),
    )
}

pub(super) fn certificate(serial: u8, version: Version, authority: Option<bool>) -> Vec<u8> {
    let mut body = Vec::new();
    match version {
        Version::V1 => {}
        Version::V2 => body.extend(tlv(0xa0, &tlv(2, &[1]))),
        Version::V3 => body.extend(tlv(0xa0, &tlv(2, &[2]))),
    }
    body.extend(tlv(2, &[serial]));
    body.extend(algorithm());
    body.extend(name());
    body.extend(tlv(
        0x30,
        &[tlv(0x17, b"250101000000Z"), tlv(0x17, b"300101000000Z")].concat(),
    ));
    body.extend(name());
    body.extend(tlv(0x30, &[algorithm(), bits()].concat()));
    if let Some(authority) = authority {
        assert_eq!(version, Version::V3, "extensions require V3");
        let constraints = if authority {
            tlv(0x30, &tlv(1, &[0xff]))
        } else {
            tlv(0x30, &[])
        };
        let extension = tlv(
            0x30,
            &[
                tlv(6, &[0x55, 0x1d, 0x13]),
                tlv(1, &[0xff]),
                tlv(4, &constraints),
            ]
            .concat(),
        );
        body.extend(tlv(0xa3, &tlv(0x30, &extension)));
    }
    tlv(0x30, &[tlv(0x30, &body), algorithm(), bits()].concat())
}

pub(super) fn crl() -> Vec<u8> {
    let body = tlv(
        0x30,
        &[
            tlv(2, &[1]),
            algorithm(),
            name(),
            tlv(0x17, b"250101000000Z"),
        ]
        .concat(),
    );
    tlv(0x30, &[body, algorithm(), bits()].concat())
}
