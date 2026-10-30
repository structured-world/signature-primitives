//! Register-only multiplication. The private witness proves CPU support.

#![deny(unsafe_op_in_unsafe_fn)]

use super::Kernel;
use crate::words::{LIMBS, Product, Words};

#[derive(Debug, Clone, Copy)]
pub(crate) struct Hardware(Instructions);

#[derive(Debug, Clone, Copy)]
enum Instructions {
    #[cfg(target_arch = "x86_64")]
    Pclmul,
    #[cfg(target_arch = "aarch64")]
    Pmull,
}

impl Hardware {
    pub(crate) fn detect() -> Option<Self> {
        #[cfg(target_arch = "x86_64")]
        {
            if cfg!(target_feature = "pclmulqdq") {
                return Some(Self(Instructions::Pclmul));
            }
            // CPUID is baseline on x86-64. Leaf1 ECX bit1 reports PCLMULQDQ;
            // SSE2/XMM state is required by the ABI. SGX cannot execute CPUID.
            #[cfg(not(target_env = "sgx"))]
            {
                #[allow(unused_unsafe, reason = "CPUID requires unsafe on Rust 1.92")]
                // SAFETY: x86-64 guarantees CPUID outside SGX.
                let features = unsafe { core::arch::x86_64::__cpuid(1) };
                if features.ecx & 2 != 0 {
                    return Some(Self(Instructions::Pclmul));
                }
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            if cfg!(all(target_feature = "aes", target_feature = "neon")) {
                return Some(Self(Instructions::Pmull));
            }
            #[cfg(feature = "std")]
            if std::arch::is_aarch64_feature_detected!("aes")
                && std::arch::is_aarch64_feature_detected!("neon")
            {
                return Some(Self(Instructions::Pmull));
            }
        }
        None
    }

    #[inline]
    fn compute<const N: usize>(
        self,
        left: &Words,
        right: [&Words; N],
        count: usize,
    ) -> [Product; N] {
        debug_assert!(count <= LIMBS);
        match (self.0, left, right, count) {
            #[cfg(target_arch = "x86_64")]
            // SAFETY: only detect constructs this witness after checking
            // PCLMUL; operands and result use safe fixed-array indexing.
            (Instructions::Pclmul, left, right, count) => unsafe { x86(left, right, count) },
            #[cfg(target_arch = "aarch64")]
            // SAFETY: Rust's aes feature includes PMULL. The witness also
            // proves NEON; neither kernel performs pointer memory access.
            (Instructions::Pmull, left, right, count) => unsafe { arm(left, right, count) },
        }
    }
}

impl Kernel for Hardware {
    #[inline]
    fn product(self, left: &Words, right: &Words, count: usize) -> Product {
        let [product] = self.compute(left, [right], count);
        product
    }

    #[inline]
    fn products(self, left: &Words, right: [&Words; 2], count: usize) -> [Product; 2] {
        self.compute(left, right, count)
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "pclmulqdq,sse2")]
fn x86<const N: usize>(left: &Words, right: [&Words; N], count: usize) -> [Product; N] {
    use core::arch::x86_64::{
        _mm_clmulepi64_si128, _mm_cvtsi64_si128, _mm_cvtsi128_si64, _mm_setzero_si128,
        _mm_unpackhi_epi64, _mm_xor_si128,
    };
    let mut result = [[0; 2 * LIMBS]; N];
    if count == 0 {
        return result;
    }
    let mut carried = [0_u64; N];
    for k in 0..2 * count - 1 {
        let first = if k < count { 0 } else { k + 1 - count };
        let last = k.min(count - 1);
        let mut sums = [_mm_setzero_si128(); N];
        for i in first..=last {
            let a = _mm_cvtsi64_si128(i64::from_ne_bytes(left.0[i].to_ne_bytes()));
            for (sum, operand) in sums.iter_mut().zip(&right) {
                let b = _mm_cvtsi64_si128(i64::from_ne_bytes(operand.0[k - i].to_ne_bytes()));
                *sum = _mm_xor_si128(*sum, _mm_clmulepi64_si128::<0>(a, b));
            }
        }
        for ((product, carry), sum) in result.iter_mut().zip(&mut carried).zip(sums) {
            product[k] = u64::from_ne_bytes(_mm_cvtsi128_si64(sum).to_ne_bytes()) ^ *carry;
            *carry =
                u64::from_ne_bytes(_mm_cvtsi128_si64(_mm_unpackhi_epi64(sum, sum)).to_ne_bytes());
        }
    }
    for (product, carry) in result.iter_mut().zip(carried) {
        product[2 * count - 1] = carry;
    }
    result
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "aes,neon")]
fn arm<const N: usize>(left: &Words, right: [&Words; N], count: usize) -> [Product; N] {
    use core::arch::aarch64::vmull_p64;
    let mut result = [[0; 2 * LIMBS]; N];
    if count == 0 {
        return result;
    }
    let mut carried = [0_u64; N];
    for k in 0..2 * count - 1 {
        let first = if k < count { 0 } else { k + 1 - count };
        let last = k.min(count - 1);
        let mut sums = [0_u128; N];
        for i in first..=last {
            for (sum, operand) in sums.iter_mut().zip(&right) {
                *sum ^= vmull_p64(left.0[i], operand.0[k - i]);
            }
        }
        for ((product, carry), sum) in result.iter_mut().zip(&mut carried).zip(sums) {
            let halves = sum.to_le_bytes();
            product[k] = u64::from_le_bytes(halves[..8].try_into().expect("eight bytes")) ^ *carry;
            *carry = u64::from_le_bytes(halves[8..].try_into().expect("eight bytes"));
        }
    }
    for (product, carry) in result.iter_mut().zip(carried) {
        product[2 * count - 1] = carry;
    }
    result
}
