#![no_std]
#![feature(alloc_error_handler)]

extern crate alloc;

use alloc::vec::Vec;
use miden::{Felt, Word};

mod argon2id;

const PASSWORD_CAPACITY: usize = 64;
const SALT_LENGTH: usize = 16;
const TAG_LENGTH: usize = 32;
const ADVICE_ELEMENTS: usize = 84;
const ADVICE_WORDS: u64 = (ADVICE_ELEMENTS / 4) as u64;
const ADVICE_KEY: [u64; 4] = [
    0x4152_474f_4e32_4944,
    0x5a4b_5354_4152_4b01,
    0x5246_4339_3130_3601,
    0x4252_4f57_5345_5201,
];

#[global_allocator]
static ALLOCATOR: miden::BumpAlloc = miden::BumpAlloc::new();

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[cfg(not(test))]
#[alloc_error_handler]
fn alloc_error(_info: core::alloc::Layout) -> ! {
    loop {}
}

/// Proves the exact RFC 9106 Argon2id v=19 computation whose private witness is
/// supplied via the Miden advice map. The twelve public stack inputs are eight
/// 32-bit limbs for the four-element credential digest and four 32-bit limbs
/// for a one-time 128-bit server challenge.
/// The challenge is intentionally not mixed into Argon2: the VM execution proof
/// is already bound to the complete public input stack by the STARK statement.
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
    let credential = match (
        felt_from_u32_limbs(credential_0_lo, credential_0_hi),
        felt_from_u32_limbs(credential_1_lo, credential_1_hi),
        felt_from_u32_limbs(credential_2_lo, credential_2_hi),
        felt_from_u32_limbs(credential_3_lo, credential_3_hi),
    ) {
        (Some(a), Some(b), Some(c), Some(d)) => [a, b, c, d],
        _ => return 0,
    };
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

    let mut password = [0u8; PASSWORD_CAPACITY];
    for i in 0..PASSWORD_CAPACITY {
        let value = witness[1 + i].as_canonical_u64();
        if value > u8::MAX as u64 {
            return 0;
        }
        password[i] = value as u8;
    }

    let mut salt = [0u8; SALT_LENGTH];
    for i in 0..SALT_LENGTH {
        let value = witness[1 + PASSWORD_CAPACITY + i].as_canonical_u64();
        if value > u8::MAX as u64 {
            return 0;
        }
        salt[i] = value as u8;
    }

    let memory_kib = witness[81].as_canonical_u64() as u32;
    let time_cost = witness[82].as_canonical_u64() as u32;
    let lanes = witness[83].as_canonical_u64() as u32;

    // RFC 9106 validity conditions. A stricter deployment floor is enforced by
    // the browser and verifier wrappers without changing Argon2 semantics.
    if memory_kib < 8 * lanes || time_cost == 0 || lanes == 0 || lanes > 4 {
        return 0;
    }

    let tag = match argon2id::hash(
        &password[..password_len],
        &salt,
        memory_kib,
        time_cost,
        lanes,
    ) {
        Some(tag) => tag,
        None => return 0,
    };

    // Commit to every byte of the computed tag, the complete public salt, and
    // all Argon2 parameters. One byte is one field element, eliminating packing
    // ambiguity. Domain and length tags prevent cross-protocol/length reuse.
    let mut statement = Vec::with_capacity(2 + TAG_LENGTH + SALT_LENGTH + 4);
    statement.push(felt(0x4152_474f_4e32_4944));
    statement.push(felt((TAG_LENGTH + SALT_LENGTH + 4) as u64));
    for byte in tag {
        statement.push(felt(byte as u64));
    }
    for byte in salt {
        statement.push(felt(byte as u64));
    }
    statement.push(felt(memory_kib as u64));
    statement.push(felt(time_cost as u64));
    statement.push(felt(lanes as u64));
    statement.push(felt(TAG_LENGTH as u64));

    let digest: [Felt; 4] = miden::hash_elements(statement).into();
    miden::assert_eq(digest[0], credential[0]);
    miden::assert_eq(digest[1], credential[1]);
    miden::assert_eq(digest[2], credential[2]);
    miden::assert_eq(digest[3], credential[3]);

    1
}

#[inline(always)]
fn felt_from_u32_limbs(lo: u32, hi: u32) -> Option<Felt> {
    Felt::new((lo as u64) | ((hi as u64) << 32)).ok()
}

#[inline(always)]
fn felt(value: u64) -> Felt {
    Felt::new(value).unwrap()
}
