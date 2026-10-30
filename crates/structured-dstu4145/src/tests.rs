//! Deterministic arithmetic, normative vectors and streaming boundary coverage.

mod accounting;
mod cms;
mod fields;
mod hashes;
mod real;
#[cfg(feature = "rustcrypto")]
mod rustcrypto;
mod signatures;
mod validation;

use crate::{
    ByteOrder,
    curve::{Curve, Point},
    field::Arithmetic,
    words::Words,
};
use std::vec::Vec;

fn bytes(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

fn encoded(value: Words, width: usize, order: ByteOrder) -> Vec<u8> {
    let mut result = Vec::with_capacity(width);
    for at in 0..width {
        let i = match order {
            ByteOrder::LittleEndian => at,
            ByteOrder::BigEndian => width - 1 - at,
        };
        result.push(value.0[i / 8].to_le_bytes()[i % 8]);
    }
    result
}

fn compressed<F: Arithmetic>(curve: &Curve<F>, point: Point) -> Words {
    let mut value = curve.field.export(point.x);
    if !point.x.is_zero() {
        let sign = curve
            .field
            .trace(curve.field.multiply(point.y, curve.field.inverse(point.x)));
        value.0[0] = (value.0[0] & !1) | u64::from(sign);
    }
    value
}

fn polynomial(spec: &crate::domains::Spec) -> Curve<crate::field::Polynomial> {
    let row = crate::domains::POLYNOMIALS
        .iter()
        .find(|row| row[0] == spec.m)
        .unwrap();
    let count = if row[2] == 0 { 1 } else { 3 };
    Curve::new(
        crate::field::Polynomial::new(spec.m, &row[1..=count], crate::multiplication::Portable)
            .unwrap(),
        spec.a,
        spec.b,
    )
    .unwrap()
}

fn normal(spec: &crate::domains::Spec) -> Curve<crate::field::Normal> {
    let field = crate::field::Normal::new(spec.m, crate::multiplication::Portable).unwrap();
    let b = field.import(spec.b);
    Curve::new(field, spec.a, b).unwrap()
}
