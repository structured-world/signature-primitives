use ::cbc::cipher::{BlockModeDecrypt, KeyIvInit, inout::InOutBuf};
use zeroize::Zeroize;

#[derive(Clone, Copy)]
pub(crate) enum Cipher {
    Aes128,
    Aes192,
    Aes256,
    #[cfg(feature = "openssl")]
    Des,
    DesEde,
    DesEde3,
}

impl Cipher {
    pub(crate) fn key_len(self) -> usize {
        match self {
            Self::Aes128 | Self::DesEde => 16,
            Self::Aes192 | Self::DesEde3 => 24,
            Self::Aes256 => 32,
            #[cfg(feature = "openssl")]
            Self::Des => 8,
        }
    }

    pub(crate) fn block_len(self) -> usize {
        match self {
            Self::Aes128 | Self::Aes192 | Self::Aes256 => 16,
            #[cfg(feature = "openssl")]
            Self::Des => 8,
            Self::DesEde | Self::DesEde3 => 8,
        }
    }

    pub(crate) fn decrypt(self, key: &[u8], iv: &[u8], buffer: &mut [u8]) -> Option<usize> {
        let width = self.block_len();
        if buffer.is_empty() || !buffer.len().is_multiple_of(width) {
            return None;
        }
        macro_rules! decrypt {
            ($cipher:ty) => {{
                let mut mode = ::cbc::Decryptor::<$cipher>::new_from_slices(key, iv).ok()?;
                let (blocks, tail) = InOutBuf::from(&mut *buffer).into_chunks();
                debug_assert!(tail.is_empty());
                mode.decrypt_blocks_inout(blocks);
            }};
        }
        match self {
            Self::Aes128 => decrypt!(aes::Aes128Dec),
            Self::Aes192 => decrypt!(aes::Aes192Dec),
            Self::Aes256 => decrypt!(aes::Aes256Dec),
            #[cfg(feature = "openssl")]
            Self::Des => decrypt!(des::Des),
            Self::DesEde => decrypt!(des::TdesEde2),
            Self::DesEde3 => decrypt!(des::TdesEde3),
        }
        let padding_byte = buffer[buffer.len() - 1];
        let padding = usize::from(padding_byte);
        // Scan the entire final block regardless of the decrypted padding length.
        let mut invalid = u8::from(padding == 0 || padding > width);
        for (index, byte) in buffer.iter().rev().take(width).enumerate() {
            let mask = 0_u8.wrapping_sub(u8::from(index < padding));
            invalid |= (*byte ^ padding_byte) & mask;
        }
        if invalid != 0 {
            buffer.zeroize();
            return None;
        }
        let length = buffer.len() - padding;
        buffer[length..].zeroize();
        Some(length)
    }
}
