#![cfg_attr(miden, no_std)]
#![cfg_attr(miden, feature(alloc_error_handler))]
#![allow(unexpected_cfgs)]

extern crate alloc;

use alloc::vec::Vec;
use miden::{Felt, Word};

mod bcrypt_miden;

const PASSWORD_CAPACITY: usize = 64;
const SALT_LENGTH: usize = 16;
const BCRYPT_TAG_LENGTH: usize = 23;
const ADVICE_ELEMENTS: usize = 1_128;
const ADVICE_WORDS: u64 = (ADVICE_ELEMENTS / 4) as u64;
const TABLE_OFFSET: usize = 84;
const P_WORDS: usize = 18;
const S_WORDS: usize = 1_024;
const TABLE_DOMAIN: u64 = 0x4243_5259_5441_424c;
const TABLE_COMMITMENT: [u64; 4] = [
    11_934_322_110_593_991_474,
    5_005_372_264_145_646_159,
    4_383_011_660_075_928_681,
    1_918_514_189_970_762_585,
];
const STATEMENT_DOMAIN: u64 = 0x4243_5259_5054_3242;
const ADVICE_KEY: [u64; 4] = [
    0x4243_5259_5054_3242,
    0x5a4b_5354_4152_4b01,
    0x454b_5342_4c4f_5746,
    0x4252_4f57_5345_5201,
];

#[cfg(miden)]
#[global_allocator]
static ALLOCATOR: miden::BumpAlloc = miden::BumpAlloc::new();

#[cfg(miden)]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[cfg(miden)]
#[alloc_error_handler]
fn alloc_error(_info: core::alloc::Layout) -> ! {
    loop {}
}

/// Proves the complete bcrypt 2b/EksBlowfish computation for the selected
/// cost. The circuit applies bcrypt's required NUL terminator and commits to
/// the standard 23 output bytes, salt, and cost.
#[unsafe(no_mangle)]
pub fn entrypoint(
    credential_0_lo: u32,
    credential_0_hi: u32,
    credential_1_lo: u32,
    credential_1_hi: u32,
    credential_2_lo: u32,
    credential_2_hi: u32,
    credential_3_lo: u32,
    credential_3_hi: u32,
    _challenge_0: u32,
    _challenge_1: u32,
    _challenge_2: u32,
    _challenge_3: u32,
) -> u32 {
    if !valid_felt_limbs(credential_0_lo, credential_0_hi)
        || !valid_felt_limbs(credential_1_lo, credential_1_hi)
        || !valid_felt_limbs(credential_2_lo, credential_2_hi)
        || !valid_felt_limbs(credential_3_lo, credential_3_hi)
    {
        return 0;
    }
    let credential = [
        felt_from_u32_limbs(credential_0_lo, credential_0_hi),
        felt_from_u32_limbs(credential_1_lo, credential_1_hi),
        felt_from_u32_limbs(credential_2_lo, credential_2_hi),
        felt_from_u32_limbs(credential_3_lo, credential_3_hi),
    ];

    let key = Word::new([
        felt(ADVICE_KEY[0]),
        felt(ADVICE_KEY[1]),
        felt(ADVICE_KEY[2]),
        felt(ADVICE_KEY[3]),
    ]);
    let advice_len = miden::intrinsics::advice::adv_push_mapvaln(key);
    miden::assert_eq(advice_len, felt(ADVICE_ELEMENTS as u64));
    let (_advice_hash, witness) = miden::pipe_words_to_memory(felt(ADVICE_WORDS));

    let password_len = witness[0].as_canonical_u64() as usize;
    if password_len == 0 || password_len > PASSWORD_CAPACITY {
        return 0;
    }
    // Keep byte-valued witness data in full field cells. The Miden Rust memory lowering uses
    // read/modify/write u32 operations for packed u8 stores; mixing those stores with Felt locals
    // can make a reused cell fail a u32 assertion. Range checks below retain exact byte semantics.
    let mut nul_terminated_password = Vec::with_capacity(PASSWORD_CAPACITY + 1);
    for i in 0..PASSWORD_CAPACITY {
        let value = witness[1 + i].as_canonical_u64();
        if value > u8::MAX as u64 || (i >= password_len && value != 0) {
            return 0;
        }
        nul_terminated_password.push(Felt::from_u32(value as u32));
    }
    nul_terminated_password.push(Felt::ZERO);

    let mut salt = Vec::with_capacity(SALT_LENGTH);
    for i in 0..SALT_LENGTH {
        let value = witness[1 + PASSWORD_CAPACITY + i].as_canonical_u64();
        if value > u8::MAX as u64 {
            return 0;
        }
        salt.push(Felt::from_u32(value as u32));
    }
    let cost_u64 = witness[81].as_canonical_u64();
    if cost_u64 > u32::MAX as u64 || witness[82] != Felt::ZERO || witness[83] != Felt::ZERO {
        return 0;
    }
    let cost = cost_u64 as u32;
    // bcrypt defines 4..=31. This implementation caps at 16 so an untrusted
    // witness cannot force a practically unbounded proving job.
    if !(4..=16).contains(&cost) {
        return 0;
    }

    let mut table_statement = Vec::with_capacity(2 + P_WORDS + S_WORDS);
    table_statement.push(felt(TABLE_DOMAIN));
    table_statement.push(felt((P_WORDS + S_WORDS) as u64));
    table_statement.extend_from_slice(&witness[TABLE_OFFSET..TABLE_OFFSET + P_WORDS + S_WORDS]);
    let table_digest: [Felt; 4] = miden::hash_elements(table_statement).into();
    for i in 0..4 {
        miden::assert_eq(table_digest[i], felt(TABLE_COMMITMENT[i]));
    }

    let mut p = Vec::with_capacity(P_WORDS);
    let mut s = Vec::with_capacity(S_WORDS);
    for i in 0..P_WORDS {
        let value = witness[TABLE_OFFSET + i].as_canonical_u64();
        if value > u32::MAX as u64 {
            return 0;
        }
        p.push(Felt::from_u32(value as u32));
    }
    for i in 0..S_WORDS {
        let value = witness[TABLE_OFFSET + P_WORDS + i].as_canonical_u64();
        if value > u32::MAX as u64 {
            return 0;
        }
        s.push(Felt::from_u32(value as u32));
    }
    if witness[1_126] != Felt::ZERO || witness[1_127] != Felt::ZERO {
        return 0;
    }

    let raw_words = bcrypt_miden::bcrypt_words(
        cost,
        &salt,
        &nul_terminated_password[..password_len + 1],
        p,
        s,
    );
    let mut statement = Vec::with_capacity(2 + BCRYPT_TAG_LENGTH + SALT_LENGTH + 2);
    statement.push(felt(STATEMENT_DOMAIN));
    statement.push(felt((BCRYPT_TAG_LENGTH + SALT_LENGTH + 2) as u64));
    for byte_index in 0..BCRYPT_TAG_LENGTH {
        let word = raw_words[byte_index / 4].to_u32();
        let shift = 24 - 8 * (byte_index % 4);
        statement.push(felt(((word >> shift) & 0xff) as u64));
    }
    for byte in salt {
        statement.push(byte);
    }
    statement.push(felt(cost as u64));
    statement.push(felt(BCRYPT_TAG_LENGTH as u64));
    let digest: [Felt; 4] = miden::hash_elements(statement).into();
    for i in 0..4 {
        miden::assert_eq(digest[i], credential[i]);
    }
    1
}

#[inline(always)]
fn valid_felt_limbs(lo: u32, hi: u32) -> bool {
    // Goldilocks modulus = 0xffff_ffff_0000_0001. Since `hi` itself is a u32, the only invalid
    // encodings have hi == u32::MAX and lo != 0.
    hi != u32::MAX || lo == 0
}

#[inline(always)]
fn felt_from_u32_limbs(lo: u32, hi: u32) -> Felt {
    Felt::new_unchecked((lo as u64) | ((hi as u64) << 32))
}

#[inline(always)]
fn felt(value: u64) -> Felt {
    Felt::new_unchecked(value)
}
