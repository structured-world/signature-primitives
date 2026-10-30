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
}

impl Kernel for Hardware {
    #[inline]
    fn product(self, left: &Words, right: &Words, count: usize) -> Product {
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

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "pclmulqdq,sse2")]
fn x86(left: &Words, right: &Words, count: usize) -> Product {
    use core::arch::x86_64::{
        _mm_clmulepi64_si128, _mm_cvtsi64_si128, _mm_cvtsi128_si64, _mm_setzero_si128,
        _mm_unpackhi_epi64, _mm_xor_si128,
    };
    let mut result = [0; 2 * LIMBS];
    if count == 0 {
        return result;
    }
    let mut carried = 0_u64;
    for (k, slot) in result[..2 * count - 1].iter_mut().enumerate() {
        let first = if k < count { 0 } else { k + 1 - count };
        let last = k.min(count - 1);
        let mut sum = _mm_setzero_si128();
        for i in first..=last {
            let a = _mm_cvtsi64_si128(i64::from_ne_bytes(left.0[i].to_ne_bytes()));
            let b = _mm_cvtsi64_si128(i64::from_ne_bytes(right.0[k - i].to_ne_bytes()));
            sum = _mm_xor_si128(sum, _mm_clmulepi64_si128::<0>(a, b));
        }
        *slot = u64::from_ne_bytes(_mm_cvtsi128_si64(sum).to_ne_bytes()) ^ carried;
        carried = u64::from_ne_bytes(_mm_cvtsi128_si64(_mm_unpackhi_epi64(sum, sum)).to_ne_bytes());
    }
    result[2 * count - 1] = carried;
    result
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "aes,neon")]
fn arm(left: &Words, right: &Words, count: usize) -> Product {
    use core::arch::aarch64::vmull_p64;
    let mut result = [0; 2 * LIMBS];
    if count == 0 {
        return result;
    }
    let mut carried = 0_u64;
    for (k, slot) in result[..2 * count - 1].iter_mut().enumerate() {
        let first = if k < count { 0 } else { k + 1 - count };
        let last = k.min(count - 1);
        let mut sum = 0_u128;
        for i in first..=last {
            sum ^= vmull_p64(left.0[i], right.0[k - i]);
        }
        let halves = sum.to_le_bytes();
        *slot = u64::from_le_bytes(halves[..8].try_into().expect("eight bytes")) ^ carried;
        carried = u64::from_le_bytes(halves[8..].try_into().expect("eight bytes"));
    }
    result[2 * count - 1] = carried;
    result
}
