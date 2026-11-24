//! Binary short-Weierstrass point operations over one borrowed field context.

use crate::Error;
use crate::field::Arithmetic;
use crate::words::Words;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Point {
    pub(crate) x: Words,
    pub(crate) y: Words,
}

#[derive(Debug, Clone)]
pub(crate) struct Curve<F> {
    pub(crate) field: F,
    pub(crate) a: bool,
    pub(crate) b: Words,
    pub(crate) sqrt_b: Words,
}

#[derive(Clone, Copy)]
struct Projective {
    x: Words,
    z: Words,
}

enum Multiple {
    Known(Option<Point>),
    Recover(Recovery),
}

struct Recovery {
    point: Point,
    x: Words,
    y: Words,
    denominator: Words,
}

impl Recovery {
    fn finish(self, field: &impl Arithmetic, inverse: Words) -> Point {
        let x = field.multiply(self.x, inverse);
        let y = field
            .multiply(x.add(self.point.x), field.multiply(self.y, inverse))
            .add(self.point.y);
        Point { x, y }
    }
}

impl Multiple {
    fn finish(self, field: &impl Arithmetic) -> Option<Point> {
        match self {
            Self::Known(point) => point,
            Self::Recover(recovery) => {
                let inverse = field.inverse(recovery.denominator);
                Some(recovery.finish(field, inverse))
            }
        }
    }
}

impl<F: Arithmetic> Curve<F> {
    pub(crate) fn new(field: F, a: bool, b: Words) -> Result<Self, Error> {
        if b.is_zero() {
            return Err(Error::InvalidDomain);
        }
        let sqrt_b = field.sqrt(b);
        Ok(Self {
            field,
            a,
            b,
            sqrt_b,
        })
    }

    pub(crate) fn contains(&self, point: Point) -> bool {
        let field = &self.field;
        let x_squared = field.square(point.x);
        let mut right = field.multiply(x_squared, point.x).add(self.b);
        if self.a {
            right = right.add(x_squared);
        }
        field.square(point.y).add(field.multiply(point.x, point.y)) == right
    }

    pub(crate) fn decompress(&self, mut compressed: Words) -> Result<Point, Error> {
        // DSTU4145 section6.10: the low bit holds Tr(y/x), while Tr(x)=a
        // restores x's overwritten low bit. Do not use SEC1's parity bit.
        if compressed.is_zero() {
            return Ok(Point {
                x: Words::ZERO,
                y: self.sqrt_b,
            });
        }
        let sign = compressed.bit(0);
        compressed.0[0] &= !1;
        if self.field.trace(self.field.import(compressed)) != self.a {
            compressed.flip(0);
        }
        let compressed = self.field.import(compressed);
        if compressed.is_zero() {
            return Err(Error::InvalidKey);
        }
        let field = &self.field;
        let inverse = field.inverse(compressed);
        let mut equation = compressed.add(field.multiply(self.b, field.square(inverse)));
        if self.a {
            equation = equation.add(field.one());
        }
        if field.trace(equation) {
            return Err(Error::InvalidKey);
        }
        let mut root = field.half_trace(equation);
        if field.trace(root) != sign {
            root = root.add(field.one());
        }
        let point = Point {
            x: compressed,
            y: field.multiply(root, compressed),
        };
        if !self.contains(point) {
            return Err(Error::InvalidKey);
        }
        Ok(point)
    }

    #[cfg(test)]
    pub(crate) fn add(&self, left: Option<Point>, right: Option<Point>) -> Option<Point> {
        let (Some(left), Some(right)) = (left, right) else {
            return left.or(right);
        };
        let field = &self.field;
        if left.x == right.x {
            if left.y != right.y || left.x.is_zero() {
                return None;
            }
            let slope = left.x.add(field.multiply(left.y, field.inverse(left.x)));
            let mut x = field.square(slope).add(slope);
            if self.a {
                x = x.add(field.one());
            }
            return Some(Point {
                x,
                y: field
                    .square(left.x)
                    .add(field.multiply(slope.add(field.one()), x)),
            });
        }
        let slope = field.multiply(left.y.add(right.y), field.inverse(left.x.add(right.x)));
        let mut x = field.square(slope).add(slope).add(left.x).add(right.x);
        if self.a {
            x = x.add(field.one());
        }
        Some(Point {
            x,
            y: field.multiply(slope, left.x.add(x)).add(x).add(left.y),
        })
    }

    pub(crate) fn multiply(&self, point: Point, scalar: Words) -> Option<Point> {
        self.ladder(point, scalar).finish(&self.field)
    }

    pub(crate) fn multiply_sum_x(
        &self,
        left: Point,
        s: Words,
        right: Point,
        r: Words,
    ) -> Option<Words> {
        let field = &self.field;
        let (left, right) = (self.ladder(left, s), self.ladder(right, r));
        match (left, right) {
            (Multiple::Recover(left), Multiple::Recover(right)) => self.recover_sum_x(left, right),
            (left, right) => self.add_x(left.finish(field), right.finish(field)),
        }
    }

    fn recover_sum_x(&self, left: Recovery, right: Recovery) -> Option<Words> {
        let field = &self.field;
        let left_x = field.multiply(left.x, right.denominator);
        let right_x = field.multiply(right.x, left.denominator);
        let difference = left_x.add(right_x);
        let denominator = field.multiply(left.denominator, right.denominator);
        if difference.is_zero() {
            // Equal affine x still needs the doubling/inverse-point cases.
            let inverse = field.inverse(denominator);
            let a = field.multiply(inverse, right.denominator);
            let b = field.multiply(inverse, left.denominator);
            return self.add_x(Some(left.finish(field, a)), Some(right.finish(field, b)));
        }
        // Over the common denominator D, x_i = X_i/D and
        // y_i = ((X_i + p_i.x*D) * Y_i + p_i.y*D²) / D².
        // The distinct-point slope has denominator D*(X_1 + X_2).
        // Its inverse also recovers x_1 + x_2 from (X_1 + X_2)².
        let left_y = field.multiply(
            left_x.add(field.multiply(left.point.x, denominator)),
            field.multiply(left.y, right.denominator),
        );
        let right_y = field.multiply(
            right_x.add(field.multiply(right.point.x, denominator)),
            field.multiply(right.y, left.denominator),
        );
        let y_sum = left_y
            .add(right_y)
            .add(field.multiply(left.point.y.add(right.point.y), field.square(denominator)));
        let inverse = field.inverse(field.multiply(denominator, difference));
        let slope = field.multiply(y_sum, inverse);
        let x_sum = field.multiply(field.square(difference), inverse);
        Some(self.x_from_slope(slope, x_sum))
    }

    fn add_x(&self, left: Option<Point>, right: Option<Point>) -> Option<Words> {
        let (Some(left), Some(right)) = (left, right) else {
            return left.or(right).map(|point| point.x);
        };
        let field = &self.field;
        if left.x == right.x {
            if left.y != right.y || left.x.is_zero() {
                return None;
            }
            let slope = left.x.add(field.multiply(left.y, field.inverse(left.x)));
            return Some(self.x_from_slope(slope, Words::ZERO));
        }
        let x_sum = left.x.add(right.x);
        let slope = field.multiply(left.y.add(right.y), field.inverse(x_sum));
        Some(self.x_from_slope(slope, x_sum))
    }

    fn x_from_slope(&self, slope: Words, x_sum: Words) -> Words {
        let mut x = self.field.square(slope).add(slope).add(x_sum);
        if self.a {
            x = x.add(self.field.one());
        }
        x
    }

    fn ladder(&self, point: Point, scalar: Words) -> Multiple {
        let bits = scalar.bits();
        if bits == 0 {
            return Multiple::Known(None);
        }
        if point.x.is_zero() {
            return Multiple::Known(scalar.bit(0).then_some(point));
        }
        let field = &self.field;
        let mut lower = Projective {
            x: point.x,
            z: field.one(),
        };
        let x_squared = field.square(point.x);
        let mut upper = Projective {
            x: field.square(x_squared).add(self.b),
            z: x_squared,
        };
        let mut previous = false;
        // Lopez-Dahab, CHES1999 section4.2 and appendix: x-only differential
        // addition/doubling, one final inversion, no affine inversion per bit.
        // https://doi.org/10.1007/3-540-48059-5_27
        for bit in (0..bits - 1).rev() {
            let selected = scalar.bit(bit);
            swap(
                &mut lower,
                &mut upper,
                previous ^ selected,
                field.degree().div_ceil(64),
            );
            previous = selected;
            let crossed_left = field.multiply(upper.x, lower.z);
            let crossed_right = field.multiply(lower.x, upper.z);
            let sum_z = field.square(crossed_left.add(crossed_right));
            upper = Projective {
                x: field
                    .multiply(point.x, sum_z)
                    .add(field.multiply(crossed_left, crossed_right)),
                z: sum_z,
            };
            let x_squared = field.square(lower.x);
            let z_squared = field.square(lower.z);
            lower = Projective {
                x: field.square(x_squared.add(field.multiply(self.sqrt_b, z_squared))),
                z: field.multiply(x_squared, z_squared),
            };
        }
        swap(
            &mut lower,
            &mut upper,
            previous,
            field.degree().div_ceil(64),
        );
        if lower.z.is_zero() {
            return Multiple::Known(None);
        }
        if upper.z.is_zero() {
            return Multiple::Known(Some(Point {
                x: point.x,
                y: point.x.add(point.y),
            }));
        }
        // Recover both affine coordinates with the common denominator x Z1 Z2.
        let z_product = field.multiply(lower.z, upper.z);
        let first = field.multiply(lower.z, point.x).add(lower.x);
        let x_z2 = field.multiply(upper.z, point.x);
        let joined = field.multiply(first, x_z2.add(upper.x));
        let numerator = field
            .multiply(field.square(point.x).add(point.y), z_product)
            .add(joined);
        Multiple::Recover(Recovery {
            point,
            x: field.multiply(x_z2, lower.x),
            y: numerator,
            denominator: field.multiply(point.x, z_product),
        })
    }
}

fn swap(left: &mut Projective, right: &mut Projective, selected: bool, count: usize) {
    let mask = 0_u64.wrapping_sub(u64::from(selected));
    for i in 0..count {
        let x = (left.x.0[i] ^ right.x.0[i]) & mask;
        let z = (left.z.0[i] ^ right.z.0[i]) & mask;
        left.x.0[i] ^= x;
        right.x.0[i] ^= x;
        left.z.0[i] ^= z;
        right.z.0[i] ^= z;
    }
}
