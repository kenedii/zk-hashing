//! EksBlowfish/bcrypt specialized for the Miden Rust memory model.
//!
//! The current Rust-to-Miden lowering can pack adjacent scalar `u32` array
//! cells into one field element. Each Blowfish word is therefore stored as an
//! entire `Felt`, while every operation converts it to a range-checked `u32`.
//! This gives each state word its own VM memory element and keeps all XOR,
//! addition, indexing, and byte extraction exact. The output remains
//! byte-for-byte bcrypt.

use alloc::vec::Vec;
use miden::Felt;

#[cfg(test)]
mod consts;

#[derive(Clone, Copy, Default)]
pub(crate) struct Word32(Felt);

impl Word32 {
    pub(crate) const ZERO: Self = Self(Felt::ZERO);

    #[inline(never)]
    pub(crate) fn from_u32(value: u32) -> Self {
        Self(Felt::from_u32(value))
    }

    #[inline(never)]
    pub(crate) fn to_u32(self) -> u32 {
        self.0.as_canonical_u64() as u32
    }

    fn xor(self, rhs: Self) -> Self {
        Self::from_u32(self.to_u32() ^ rhs.to_u32())
    }

    fn add(self, rhs: Self) -> Self {
        Self::from_u32(self.to_u32().wrapping_add(rhs.to_u32()))
    }
}

struct Blowfish {
    s: Vec<Felt>,
    p: Vec<Felt>,
}

#[inline(never)]
fn next_word_wrap(buf: &[Felt], offset: &mut usize) -> Word32 {
    let mut value = 0u32;
    for _ in 0..4 {
        if *offset >= buf.len() {
            *offset = 0;
        }
        value = value
            .wrapping_mul(256)
            .wrapping_add(Word32(buf[*offset]).to_u32());
        *offset += 1;
    }
    Word32::from_u32(value)
}

impl Blowfish {
    fn init_state(p: Vec<Felt>, s: Vec<Felt>) -> Self {
        Self { p, s }
    }

    fn p_word(&self, index: usize) -> Word32 {
        Word32(self.p[index])
    }

    fn set_p_word(&mut self, index: usize, value: Word32) {
        self.p[index] = value.0;
    }

    fn s_word(&self, index: usize) -> Word32 {
        Word32(self.s[index])
    }

    fn set_s_word(&mut self, index: usize, value: Word32) {
        self.s[index] = value.0;
    }

    #[inline(never)]
    fn round_function(&self, x: Word32) -> Word32 {
        let x = x.to_u32();
        let a = self.s_word((x >> 24) as usize);
        let b = self.s_word(256 + ((x >> 16) & 0xff) as usize);
        let c = self.s_word(512 + ((x >> 8) & 0xff) as usize);
        let d = self.s_word(768 + (x & 0xff) as usize);
        a.add(b).xor(c).add(d)
    }

    #[inline(never)]
    fn encrypt(&self, left: &mut Word32, right: &mut Word32) {
        let mut left_value = *left;
        let mut right_value = *right;
        for i in 0..8 {
            left_value = left_value.xor(self.p_word(2 * i));
            right_value = right_value.xor(self.round_function(left_value));
            right_value = right_value.xor(self.p_word(2 * i + 1));
            left_value = left_value.xor(self.round_function(right_value));
        }
        left_value = left_value.xor(self.p_word(16));
        right_value = right_value.xor(self.p_word(17));
        *left = right_value;
        *right = left_value;
    }

    #[inline(always)]
    fn expand_key(&mut self, key: &[Felt]) {
        let mut key_pos = 0;
        for i in 0..18 {
            self.set_p_word(i, self.p_word(i).xor(next_word_wrap(key, &mut key_pos)));
        }
        let mut left = Word32::ZERO;
        let mut right = Word32::ZERO;
        for i in 0..9 {
            self.encrypt(&mut left, &mut right);
            self.set_p_word(2 * i, left);
            self.set_p_word(2 * i + 1, right);
        }
        for pair in 0..512 {
            self.encrypt(&mut left, &mut right);
            let index = 2 * pair;
            self.set_s_word(index, left);
            self.set_s_word(index + 1, right);
        }
    }

    #[inline(always)]
    fn salted_expand_key(&mut self, salt: &[Felt], key: &[Felt]) {
        let mut key_pos = 0;
        for i in 0..18 {
            self.set_p_word(i, self.p_word(i).xor(next_word_wrap(key, &mut key_pos)));
        }
        let mut left = Word32::ZERO;
        let mut right = Word32::ZERO;
        let mut salt_pos = 0;
        for i in 0..9 {
            left = left.xor(next_word_wrap(salt, &mut salt_pos));
            right = right.xor(next_word_wrap(salt, &mut salt_pos));
            self.encrypt(&mut left, &mut right);
            self.set_p_word(2 * i, left);
            self.set_p_word(2 * i + 1, right);
        }
        for quartet in 0..256 {
            left = left.xor(next_word_wrap(salt, &mut salt_pos));
            right = right.xor(next_word_wrap(salt, &mut salt_pos));
            self.encrypt(&mut left, &mut right);
            let index = 4 * quartet;
            self.set_s_word(index, left);
            self.set_s_word(index + 1, right);

            left = left.xor(next_word_wrap(salt, &mut salt_pos));
            right = right.xor(next_word_wrap(salt, &mut salt_pos));
            self.encrypt(&mut left, &mut right);
            self.set_s_word(index + 2, left);
            self.set_s_word(index + 3, right);
        }
    }
}

pub(crate) fn bcrypt_words(
    cost: u32,
    salt: &[Felt],
    password: &[Felt],
    p: Vec<Felt>,
    s: Vec<Felt>,
) -> [Word32; 6] {
    let mut state = Blowfish::init_state(p, s);
    state.salted_expand_key(salt, password);
    for _ in 0..1u32 << cost {
        state.expand_key(password);
        state.expand_key(salt);
    }

    let mut text = [
        Word32::from_u32(0x4f727068),
        Word32::from_u32(0x65616e42),
        Word32::from_u32(0x65686f6c),
        Word32::from_u32(0x64657253),
        Word32::from_u32(0x63727944),
        Word32::from_u32(0x6f756274),
    ];
    for pair in 0..3 {
        let index = pair * 2;
        for _ in 0..64 {
            let mut left = text[index];
            let mut right = text[index + 1];
            state.encrypt(&mut left, &mut right);
            text[index] = left;
            text[index + 1] = right;
        }
    }
    text
}

/// Native/test wrapper retaining the conventional byte-for-byte bcrypt API. It is excluded from
/// Miden builds so the circuit itself never emits packed byte stores.
#[cfg(not(miden))]
pub fn bcrypt(
    cost: u32,
    salt: [u8; 16],
    password: &[u8],
    p: [Word32; 18],
    s: [Word32; 1024],
) -> [u8; 24] {
    let salt_words = salt.map(|byte| Felt::from_u32(byte as u32));
    let password_words = password
        .iter()
        .map(|byte| Felt::from_u32(*byte as u32))
        .collect::<Vec<_>>();
    let p_words = p.into_iter().map(|word| word.0).collect();
    let s_words = s.into_iter().map(|word| word.0).collect();
    let words = bcrypt_words(cost, &salt_words, &password_words, p_words, s_words);
    let mut output = [0u8; 24];
    for (index, word) in words.into_iter().enumerate() {
        let value = word.to_u32();
        let out = index * 4;
        output[out] = (value >> 24) as u8;
        output[out + 1] = (value >> 16) as u8;
        output[out + 2] = (value >> 8) as u8;
        output[out + 3] = value as u8;
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn differential_vectors_match_rustcrypto() {
        for (password, salt, cost) in [
            (&b"hunter2"[..], *b"0123456789abcdef", 4),
            (&b"correct horse battery staple"[..], [0xa5; 16], 5),
            (&b"embedded\0nul"[..], [0x5a; 16], 4),
            (&[0xff, 0x80, 1, 2, 3][..], [0x11; 16], 4),
        ] {
            let mut key = Vec::from(password);
            key.push(0);
            let mut p = [Word32::ZERO; 18];
            let mut s = [Word32::ZERO; 1024];
            for i in 0..18 {
                p[i] = Word32::from_u32(consts::P[i] as u32);
            }
            for i in 0..1024 {
                s[i] = Word32::from_u32(consts::S[i] as u32);
            }
            assert_eq!(
                bcrypt(cost, salt, &key, p, s),
                ::bcrypt::bcrypt(cost, salt, &key),
                "cost={cost}, password={password:?}",
            );
        }
    }
}
