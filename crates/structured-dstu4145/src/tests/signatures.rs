use super::{bytes, compressed, encoded, normal, polynomial};
use crate::{
    Basis, ByteOrder,
    curve::Point,
    domain::{Domain, Explicit},
    domains,
    field::Arithmetic,
    words::Words,
};
use structured_pkix::algorithm::dstu4145::Reduction;

struct SignatureExample<'a> {
    digest: &'a str,
    r: &'a str,
    s: &'a str,
}

fn example<F: Arithmetic>(
    curve: &crate::curve::Curve<F>,
    base: Point,
    public: Point,
    spec: &domains::Spec,
    reduction: Reduction,
    signature: &SignatureExample<'_>,
    width: usize,
) {
    let SignatureExample { digest, r, s } = *signature;
    let m = spec.m.div_ceil(8);
    let b = encoded(curve.field.export(curve.b), m, ByteOrder::BigEndian);
    let base_bytes = encoded(compressed(curve, base), m, ByteOrder::BigEndian);
    let order = encoded(
        spec.order,
        spec.order.bits().div_ceil(8),
        ByteOrder::BigEndian,
    );
    let public_bytes = encoded(compressed(curve, public), m, ByteOrder::BigEndian);
    let input = Explicit {
        degree: u32::try_from(spec.m).unwrap(),
        reduction,
        a: curve.a,
        b: &b,
        order: &order,
        base_point: &base_bytes,
        byte_order: ByteOrder::BigEndian,
    };
    let key = Domain::explicit(input)
        .unwrap()
        .public_key(&public_bytes, ByteOrder::BigEndian)
        .unwrap();
    let mut hash = bytes(digest);
    hash.reverse();
    for endian in [ByteOrder::BigEndian, ByteOrder::LittleEndian] {
        let (first, last) = if endian == ByteOrder::BigEndian {
            (s, r)
        } else {
            (r, s)
        };
        let mut signature = encoded(Words::hex(first), width, endian);
        signature.extend(encoded(Words::hex(last), width, endian));
        assert!(key.verify_prehash(&hash, &signature, endian).unwrap());
        hash[0] ^= 1;
        assert!(!key.verify_prehash(&hash, &signature, endian).unwrap());
        hash[0] ^= 1;
        signature.fill(0);
        assert!(!key.verify_prehash(&hash, &signature, endian).unwrap());
    }
}

/// DSTU4145-2002 AnnexB.1 independently fixes the PB163 point/scalar math.
/// Its deliberately wider32-octet components must not be confused with m.
#[test]
fn normative_polynomial_verification_example() {
    let spec = &domains::PB[0];
    let base = Point {
        x: Words::hex("72D867F93A93AC27DF9FF01AFFE74885C8C540420"),
        y: Words::hex("0224A9C3947852B97C5599D5F4AB81122ADC3FD9B"),
    };
    let public = Point {
        x: Words::hex("057DE7FDE023FF929CB6AC785CE4B79CF64ABDC2DA"),
        y: Words::hex("3E85444324BCF06AD85ABF6AD7B5F34770532B9AA"),
    };
    example(
        &polynomial(spec),
        base,
        public,
        spec,
        Reduction::Pentanomial { k: 3, j: 6, l: 7 },
        &SignatureExample {
            digest: "09C9C44277910C9AAEE486883A2EB95B7180166DDF73532EEB76EDAEF52247FF",
            r: "274EA2C0CAA014A0D80A424F59ADE7A93068D08A7",
            s: "2100D86957331832B8E8C230F5BD6A332B3615ACA",
        },
        32,
    );
}

/// AnnexB.2 independently fixes normal-basis bit numbering and digest mapping.
#[test]
fn normative_normal_verification_example() {
    let spec = &domains::ONB[0];
    let curve = normal(spec);
    let base = Point {
        x: curve
            .field
            .import(Words::hex("1D26E5282C2647E1B0327CB4F6087932A0A1F006A89F")),
        y: curve
            .field
            .import(Words::hex("0322218E4551CF8F6E3345644A10B2408F5DF19EC2C7")),
    };
    let public = Point {
        x: curve
            .field
            .import(Words::hex("16C1FF796B32D6D2FC83CA9530B368B322F7874B2D01")),
        y: curve
            .field
            .import(Words::hex("1F253334197826B6ADAE44EDEAA7EA281D1C5E597A37")),
    };
    example(
        &curve,
        base,
        public,
        spec,
        Reduction::OptimalNormal,
        &SignatureExample {
            digest: "2A681ECE118389B27A108137187EA862117EF1484289470ECAC802C5A651FDA8",
            r: "477ECC260F390FB6D0AE4AE3B7A78120F8EC458EF9A",
            s: "472EA56AE478F95F1EC9F628FF43857E168B50FB819",
        },
        22,
    );
}

/// Named setup never requires randomness, and malformed signature lengths fail
/// before scalar arithmetic rather than being silently padded or truncated.
#[test]
fn signature_framing_is_bounded() {
    let spec = &domains::PB[0];
    let curve = polynomial(spec);
    let point = Point {
        x: spec.x,
        y: spec.y,
    };
    let public = encoded(compressed(&curve, point), 21, ByteOrder::BigEndian);
    let key = Domain::named(Basis::Polynomial, 163)
        .unwrap()
        .public_key(&public, ByteOrder::BigEndian)
        .unwrap();
    for length in [0, 1, 40, 41, 43, 129, 130] {
        assert!(
            key.verify_prehash(&[0; 32], &std::vec![0;length], ByteOrder::BigEndian)
                .is_err()
        );
    }
    assert!(
        !key.verify_prehash(&[0; 32], &[0; 42], ByteOrder::BigEndian)
            .unwrap()
    );
    assert!(
        key.verify_prehash(&[], &[0; 42], ByteOrder::BigEndian)
            .is_err()
    );
}
