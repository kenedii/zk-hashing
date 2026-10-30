#![no_std]
#![feature(alloc_error_handler)]

extern crate alloc;

use alloc::vec::Vec;
use miden::{Felt, Word};

const PASSWORD_CAPACITY: usize = 64;
const SALT_LENGTH: usize = 16;
const ADVICE_ELEMENTS: usize = 84;
const ADVICE_WORDS: u64 = (ADVICE_ELEMENTS / 4) as u64;
const MIMC_ROUNDS: usize = 220;
// Legacy nothing-up-my-sleeve decimal seeds reduced into Miden's Goldilocks field.
const RC_A: u64 = 1_724_911_711_848_099_566;
const RC_B: u64 = 8_205_926_492_195_879_531;
const MIMC_DOMAIN: u64 = 0x4d49_4d43_3750_5701;
const STATEMENT_DOMAIN: u64 = 0x4d49_4d43_4352_4544;
const ADVICE_KEY: [u64; 4] = [
    0x4d49_4d43_3750_5701,
    0x5a4b_5354_4152_4b01,
    0x5041_5353_574f_5244,
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

/// Proves a complete MiMC-7 password-hash computation. Password and salt are
/// private advice; the credential digest and one-time challenge are public.
/// A domain-separated Poseidon2 absorption binds every password byte, its
/// length, and the salt to one field element; all 220 MiMC-7 rounds are then
/// applied to that element. Both stages execute inside the proven program.
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
        if value > u8::MAX as u64 || (i >= password_len && value != 0) {
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
    if witness[81] != Felt::ZERO || witness[82] != Felt::ZERO || witness[83] != Felt::ZERO {
        return 0;
    }

    let output = mimc7_password_hash(&password, password_len, &salt);
    let mut statement = Vec::with_capacity(2 + SALT_LENGTH + 3);
    statement.push(felt(STATEMENT_DOMAIN));
    statement.push(felt((SALT_LENGTH + 3) as u64));
    statement.push(output);
    for byte in salt {
        statement.push(felt(byte as u64));
    }
    statement.push(felt(password_len as u64));
    statement.push(felt(MIMC_ROUNDS as u64));
    let digest: [Felt; 4] = miden::hash_elements(statement).into();
    for i in 0..4 {
        miden::assert_eq(digest[i], credential[i]);
    }
    1
}

fn mimc7_password_hash(
    password: &[u8; PASSWORD_CAPACITY],
    password_len: usize,
    salt: &[u8; SALT_LENGTH],
) -> Felt {
    let mut preimage = Vec::with_capacity(3 + PASSWORD_CAPACITY + SALT_LENGTH);
    preimage.push(felt(MIMC_DOMAIN));
    preimage.push(felt((PASSWORD_CAPACITY + SALT_LENGTH + 1) as u64));
    preimage.push(felt(password_len as u64));
    for byte in password {
        preimage.push(felt(*byte as u64));
    }
    for byte in salt {
        preimage.push(felt(*byte as u64));
    }
    let absorbed: [Felt; 4] = miden::hash_elements(preimage).into();
    compress(felt(MIMC_DOMAIN), absorbed[0])
}

fn compress(key: Felt, message: Felt) -> Felt {
    let mut value = message;
    let mut rc = felt(RC_A);
    for i in 0..MIMC_ROUNDS {
        rc = rc * felt(RC_B) + felt(i as u64) * felt(RC_A) + Felt::ONE;
        if rc == Felt::ZERO {
            rc = Felt::ONE;
        }
        let t = value + key + rc;
        let t2 = t * t;
        let t4 = t2 * t2;
        value = t4 * t2 * t;
    }
    let encrypted = value + key;
    encrypted + key + message
}

#[inline(always)]
fn felt_from_u32_limbs(lo: u32, hi: u32) -> Option<Felt> {
    Felt::new((lo as u64) | ((hi as u64) << 32)).ok()
}

#[inline(always)]
fn felt(value: u64) -> Felt {
    Felt::new(value).unwrap()
}
