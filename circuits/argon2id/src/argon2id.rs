use alloc::vec;

const BLOCK_WORDS: usize = 128;
const BLOCK_BYTES: usize = 1024;
const SYNC_POINTS: usize = 4;
const ARGON2ID: u32 = 2;
const VERSION_13: u32 = 0x13;

#[derive(Clone, Copy, Default, Eq, PartialEq)]
struct Word64 {
    lo: u32,
    hi: u32,
}

impl Word64 {
    const ZERO: Self = Self { lo: 0, hi: 0 };

    const fn from_u64(value: u64) -> Self {
        Self {
            lo: value as u32,
            hi: (value >> 32) as u32,
        }
    }

    fn xor(self, rhs: Self) -> Self {
        Self {
            lo: self.lo ^ rhs.lo,
            hi: self.hi ^ rhs.hi,
        }
    }

    fn add(self, rhs: Self) -> Self {
        let (lo, carry) = self.lo.overflowing_add(rhs.lo);
        Self {
            lo,
            hi: self.hi.wrapping_add(rhs.hi).wrapping_add(carry as u32),
        }
    }

    /// a + b + 2 * low32(a) * low32(b), modulo 2^64.
    fn blamka(self, rhs: Self) -> Self {
        let product = (self.lo as u64) * (rhs.lo as u64);
        let product_lo = (product as u32) << 1;
        let product_hi = (product >> 31) as u32;
        let (lo0, carry0) = self.lo.overflowing_add(rhs.lo);
        let (lo, carry1) = lo0.overflowing_add(product_lo);
        Self {
            lo,
            hi: self
                .hi
                .wrapping_add(rhs.hi)
                .wrapping_add(product_hi)
                .wrapping_add(carry0 as u32)
                .wrapping_add(carry1 as u32),
        }
    }

    fn rotr(self, amount: u32) -> Self {
        match amount {
            16 => Self {
                lo: (self.lo >> 16) | (self.hi << 16),
                hi: (self.hi >> 16) | (self.lo << 16),
            },
            24 => Self {
                lo: (self.lo >> 24) | (self.hi << 8),
                hi: (self.hi >> 24) | (self.lo << 8),
            },
            32 => Self {
                lo: self.hi,
                hi: self.lo,
            },
            63 => Self {
                lo: (self.lo << 1) | (self.hi >> 31),
                hi: (self.hi << 1) | (self.lo >> 31),
            },
            _ => unreachable!(),
        }
    }
}

type Block = [Word64; BLOCK_WORDS];

pub(crate) fn hash(
    password: &[u8],
    salt: &[u8; 16],
    memory_kib: u32,
    time_cost: u32,
    lanes: u32,
) -> Option<[u8; 32]> {
    if password.is_empty()
        || password.len() > 64
        || lanes == 0
        || lanes > 4
        || time_cost == 0
        || memory_kib < 8 * lanes
    {
        return None;
    }

    let lanes = lanes as usize;
    let mut block_count = memory_kib as usize;
    block_count -= block_count % (SYNC_POINTS * lanes);
    if block_count < 2 * SYNC_POINTS * lanes {
        return None;
    }
    let lane_length = block_count / lanes;
    let segment_length = lane_length / SYNC_POINTS;

    let h0 = initial_hash(password, salt, memory_kib, time_cost, lanes as u32);
    let mut memory = vec![[Word64::ZERO; BLOCK_WORDS]; block_count];

    initialize_blocks(&mut memory, &h0, lanes, lane_length);
    fill_memory(
        &mut memory,
        block_count,
        time_cost as usize,
        lanes,
        lane_length,
        segment_length,
    );
    Some(finalize(&memory, lanes, lane_length))
}

fn initialize_blocks(memory: &mut [Block], h0: &[u8; 64], lanes: usize, lane_length: usize) {
    for lane in 0..lanes {
        for block in 0..2usize {
            let mut seed = [0u8; 72];
            seed[..64].copy_from_slice(h0);
            seed[64..68].copy_from_slice(&(block as u32).to_le_bytes());
            seed[68..72].copy_from_slice(&(lane as u32).to_le_bytes());
            let mut bytes = [0u8; BLOCK_BYTES];
            blake2b_long(&seed, &mut bytes);
            memory[lane * lane_length + block] = block_from_bytes(&bytes);
        }
    }
}

fn fill_memory(
    memory: &mut [Block],
    block_count: usize,
    time_cost: usize,
    lanes: usize,
    lane_length: usize,
    segment_length: usize,
) {
    for pass in 0..time_cost {
        for slice in 0..SYNC_POINTS {
            for lane in 0..lanes {
                fill_segment(
                    memory,
                    block_count,
                    time_cost,
                    lanes,
                    lane_length,
                    segment_length,
                    pass,
                    slice,
                    lane,
                );
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn fill_segment(
    memory: &mut [Block],
    block_count: usize,
    time_cost: usize,
    lanes: usize,
    lane_length: usize,
    segment_length: usize,
    pass: usize,
    slice: usize,
    lane: usize,
) {
    let zero = [Word64::ZERO; BLOCK_WORDS];
    let independent = pass == 0 && slice < SYNC_POINTS / 2;
    let mut address = zero;
    let mut input = zero;
    if independent {
        input[0] = Word64::from_u64(pass as u64);
        input[1] = Word64::from_u64(lane as u64);
        input[2] = Word64::from_u64(slice as u64);
        input[3] = Word64::from_u64(block_count as u64);
        input[4] = Word64::from_u64(time_cost as u64);
        input[5] = Word64::from_u64(ARGON2ID as u64);
    }

    let first_block = if pass == 0 && slice == 0 {
        if independent {
            update_address(&mut address, &mut input, &zero);
        }
        2
    } else {
        0
    };
    let mut current = lane * lane_length + slice * segment_length + first_block;
    let mut previous = if slice == 0 && first_block == 0 {
        current + lane_length - 1
    } else {
        current - 1
    };

    for block in first_block..segment_length {
        let random = if independent {
            let address_index = block % BLOCK_WORDS;
            if address_index == 0 {
                update_address(&mut address, &mut input, &zero);
            }
            address[address_index]
        } else {
            memory[previous][0]
        };
        let reference_lane = reference_lane(random, pass, slice, lane, lanes);
        let reference_area = reference_area_size(
            pass,
            slice,
            block,
            lane,
            reference_lane,
            lane_length,
            segment_length,
        );
        let reference = reference_index(
            random,
            pass,
            slice,
            reference_lane,
            reference_area,
            lane_length,
            segment_length,
        );
        let result = compress(&memory[previous], &memory[reference]);
        if pass == 0 {
            memory[current] = result;
        } else {
            xor_block_in_place(&mut memory[current], &result);
        }
        previous = current;
        current += 1;
    }
}

fn reference_lane(random: Word64, pass: usize, slice: usize, lane: usize, lanes: usize) -> usize {
    if pass == 0 && slice == 0 {
        lane
    } else {
        (random.hi as usize) % lanes
    }
}

#[allow(clippy::too_many_arguments)]
fn reference_area_size(
    pass: usize,
    slice: usize,
    block: usize,
    lane: usize,
    reference_lane: usize,
    lane_length: usize,
    segment_length: usize,
) -> usize {
    if pass == 0 {
        if slice == 0 {
            block - 1
        } else if reference_lane == lane {
            slice * segment_length + block - 1
        } else {
            slice * segment_length - usize::from(block == 0)
        }
    } else if reference_lane == lane {
        lane_length - segment_length + block - 1
    } else {
        lane_length - segment_length - usize::from(block == 0)
    }
}

#[allow(clippy::too_many_arguments)]
fn reference_index(
    random: Word64,
    pass: usize,
    slice: usize,
    reference_lane: usize,
    reference_area: usize,
    lane_length: usize,
    segment_length: usize,
) -> usize {
    let square = (random.lo as u64) * (random.lo as u64);
    let mapped = (square >> 32) as u32;
    let scaled = ((reference_area as u64) * (mapped as u64)) >> 32;
    let relative = reference_area - 1 - scaled as usize;
    let start = if pass != 0 && slice != SYNC_POINTS - 1 {
        (slice + 1) * segment_length
    } else {
        0
    };
    reference_lane * lane_length + (start + relative) % lane_length
}

fn finalize(memory: &[Block], lanes: usize, lane_length: usize) -> [u8; 32] {
    let mut final_block = memory[lane_length - 1];
    for lane in 1..lanes {
        xor_block_in_place(
            &mut final_block,
            &memory[lane * lane_length + lane_length - 1],
        );
    }
    let final_bytes = block_to_bytes(&final_block);
    let mut tag = [0u8; 32];
    blake2b_long(&final_bytes, &mut tag);
    tag
}

fn initial_hash(
    password: &[u8],
    salt: &[u8; 16],
    memory_kib: u32,
    time_cost: u32,
    lanes: u32,
) -> [u8; 64] {
    let mut input = [0u8; 128];
    let mut cursor = 0usize;
    for value in [lanes, 32, memory_kib, time_cost, VERSION_13, ARGON2ID] {
        input[cursor..cursor + 4].copy_from_slice(&value.to_le_bytes());
        cursor += 4;
    }
    input[cursor..cursor + 4].copy_from_slice(&(password.len() as u32).to_le_bytes());
    cursor += 4;
    input[cursor..cursor + password.len()].copy_from_slice(password);
    cursor += password.len();
    input[cursor..cursor + 4].copy_from_slice(&16u32.to_le_bytes());
    cursor += 4;
    input[cursor..cursor + 16].copy_from_slice(salt);
    cursor += 16;
    input[cursor..cursor + 4].copy_from_slice(&0u32.to_le_bytes());
    cursor += 4;
    input[cursor..cursor + 4].copy_from_slice(&0u32.to_le_bytes());
    cursor += 4;

    let mut output = [0u8; 64];
    blake2b(&input[..cursor], 64, &mut output);
    output
}

fn update_address(address: &mut Block, input: &mut Block, zero: &Block) {
    input[6] = input[6].add(Word64::from_u64(1));
    *address = compress(zero, input);
    *address = compress(zero, address);
}

fn compress(rhs: &Block, lhs: &Block) -> Block {
    let mut r = [Word64::ZERO; BLOCK_WORDS];
    let mut q = [Word64::ZERO; BLOCK_WORDS];
    for i in 0..BLOCK_WORDS {
        r[i] = rhs[i].xor(lhs[i]);
        q[i] = r[i];
    }
    for row in 0..8 {
        permute_at(&mut q, row_indices(row));
    }
    for column in 0..8 {
        permute_at(&mut q, column_indices(column));
    }
    for i in 0..BLOCK_WORDS {
        q[i] = q[i].xor(r[i]);
    }
    q
}

fn row_indices(row: usize) -> [usize; 16] {
    let base = row * 16;
    [
        base,
        base + 1,
        base + 2,
        base + 3,
        base + 4,
        base + 5,
        base + 6,
        base + 7,
        base + 8,
        base + 9,
        base + 10,
        base + 11,
        base + 12,
        base + 13,
        base + 14,
        base + 15,
    ]
}

fn column_indices(column: usize) -> [usize; 16] {
    let base = column * 2;
    [
        base,
        base + 1,
        base + 16,
        base + 17,
        base + 32,
        base + 33,
        base + 48,
        base + 49,
        base + 64,
        base + 65,
        base + 80,
        base + 81,
        base + 96,
        base + 97,
        base + 112,
        base + 113,
    ]
}

fn permute_at(block: &mut Block, indices: [usize; 16]) {
    let mut words = [Word64::ZERO; 16];
    for i in 0..16 {
        words[i] = block[indices[i]];
    }
    round16(&mut words);
    for i in 0..16 {
        block[indices[i]] = words[i];
    }
}

fn round16(v: &mut [Word64; 16]) {
    g(v, 0, 4, 8, 12);
    g(v, 1, 5, 9, 13);
    g(v, 2, 6, 10, 14);
    g(v, 3, 7, 11, 15);
    g(v, 0, 5, 10, 15);
    g(v, 1, 6, 11, 12);
    g(v, 2, 7, 8, 13);
    g(v, 3, 4, 9, 14);
}

fn g(v: &mut [Word64; 16], a: usize, b: usize, c: usize, d: usize) {
    v[a] = v[a].blamka(v[b]);
    v[d] = v[d].xor(v[a]).rotr(32);
    v[c] = v[c].blamka(v[d]);
    v[b] = v[b].xor(v[c]).rotr(24);
    v[a] = v[a].blamka(v[b]);
    v[d] = v[d].xor(v[a]).rotr(16);
    v[c] = v[c].blamka(v[d]);
    v[b] = v[b].xor(v[c]).rotr(63);
}

fn xor_block_in_place(dst: &mut Block, rhs: &Block) {
    for i in 0..BLOCK_WORDS {
        dst[i] = dst[i].xor(rhs[i]);
    }
}

fn block_from_bytes(bytes: &[u8; BLOCK_BYTES]) -> Block {
    let mut block = [Word64::ZERO; BLOCK_WORDS];
    for (i, chunk) in bytes.chunks_exact(8).enumerate() {
        block[i] = Word64 {
            lo: u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
            hi: u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
        };
    }
    block
}

fn block_to_bytes(block: &Block) -> [u8; BLOCK_BYTES] {
    let mut bytes = [0u8; BLOCK_BYTES];
    for (i, word) in block.iter().enumerate() {
        bytes[i * 8..i * 8 + 4].copy_from_slice(&word.lo.to_le_bytes());
        bytes[i * 8 + 4..i * 8 + 8].copy_from_slice(&word.hi.to_le_bytes());
    }
    bytes
}

fn blake2b_long(input: &[u8], output: &mut [u8]) {
    let output_len = output.len();
    let mut prefixed = [0u8; BLOCK_BYTES + 4];
    prefixed[..4].copy_from_slice(&(output_len as u32).to_le_bytes());
    prefixed[4..4 + input.len()].copy_from_slice(input);
    if output_len <= 64 {
        let mut digest = [0u8; 64];
        blake2b(&prefixed[..4 + input.len()], output_len, &mut digest);
        output.copy_from_slice(&digest[..output_len]);
        return;
    }

    let rounds = (output_len + 31) / 32 - 2;
    let mut current = [0u8; 64];
    blake2b(&prefixed[..4 + input.len()], 64, &mut current);
    for round in 0..rounds {
        output[round * 32..round * 32 + 32].copy_from_slice(&current[..32]);
        if round + 1 < rounds {
            let previous = current;
            blake2b(&previous, 64, &mut current);
        }
    }
    let final_len = output_len - rounds * 32;
    let previous = current;
    blake2b(&previous, final_len, &mut current);
    output[rounds * 32..].copy_from_slice(&current[..final_len]);
}

const BLAKE2_IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

fn blake2b(input: &[u8], output_len: usize, output: &mut [u8; 64]) {
    let mut h = [Word64::ZERO; 8];
    for i in 0..8 {
        h[i] = Word64::from_u64(BLAKE2_IV[i]);
    }
    h[0] = h[0].xor(Word64::from_u64(0x0101_0000 ^ output_len as u64));

    let mut offset = 0usize;
    let mut total = 0u64;
    while input.len() - offset > 128 {
        let mut block = [0u8; 128];
        block.copy_from_slice(&input[offset..offset + 128]);
        total += 128;
        blake2_compress(&mut h, &block, total, false);
        offset += 128;
    }
    let remaining = input.len() - offset;
    let mut block = [0u8; 128];
    block[..remaining].copy_from_slice(&input[offset..]);
    total += remaining as u64;
    blake2_compress(&mut h, &block, total, true);

    for (i, word) in h.iter().enumerate() {
        output[i * 8..i * 8 + 4].copy_from_slice(&word.lo.to_le_bytes());
        output[i * 8 + 4..i * 8 + 8].copy_from_slice(&word.hi.to_le_bytes());
    }
}

fn blake2_compress(h: &mut [Word64; 8], block: &[u8; 128], total: u64, last: bool) {
    let mut message = [Word64::ZERO; 16];
    for (i, chunk) in block.chunks_exact(8).enumerate() {
        message[i] = Word64 {
            lo: u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
            hi: u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
        };
    }
    let mut v = [Word64::ZERO; 16];
    v[..8].copy_from_slice(h);
    for i in 0..8 {
        v[8 + i] = Word64::from_u64(BLAKE2_IV[i]);
    }
    v[12] = v[12].xor(Word64::from_u64(total));
    if last {
        v[14] = v[14].xor(Word64::from_u64(u64::MAX));
    }
    for sigma in SIGMA {
        blake_g(&mut v, 0, 4, 8, 12, message[sigma[0]], message[sigma[1]]);
        blake_g(&mut v, 1, 5, 9, 13, message[sigma[2]], message[sigma[3]]);
        blake_g(&mut v, 2, 6, 10, 14, message[sigma[4]], message[sigma[5]]);
        blake_g(&mut v, 3, 7, 11, 15, message[sigma[6]], message[sigma[7]]);
        blake_g(&mut v, 0, 5, 10, 15, message[sigma[8]], message[sigma[9]]);
        blake_g(&mut v, 1, 6, 11, 12, message[sigma[10]], message[sigma[11]]);
        blake_g(&mut v, 2, 7, 8, 13, message[sigma[12]], message[sigma[13]]);
        blake_g(&mut v, 3, 4, 9, 14, message[sigma[14]], message[sigma[15]]);
    }
    for i in 0..8 {
        h[i] = h[i].xor(v[i]).xor(v[i + 8]);
    }
}

fn blake_g(v: &mut [Word64; 16], a: usize, b: usize, c: usize, d: usize, x: Word64, y: Word64) {
    v[a] = v[a].add(v[b]).add(x);
    v[d] = v[d].xor(v[a]).rotr(32);
    v[c] = v[c].add(v[d]);
    v[b] = v[b].xor(v[c]).rotr(24);
    v[a] = v[a].add(v[b]).add(y);
    v[d] = v[d].xor(v[a]).rotr(16);
    v[c] = v[c].add(v[d]);
    v[b] = v[b].xor(v[c]).rotr(63);
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::{Algorithm, Argon2, Params, Version};

    fn oracle(password: &[u8], salt: &[u8; 16], m: u32, t: u32, p: u32) -> [u8; 32] {
        let params = Params::new(m, t, p, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut output = [0u8; 32];
        argon2
            .hash_password_into(password, salt, &mut output)
            .unwrap();
        output
    }

    #[test]
    fn word_operations_match_u64() {
        let samples = [
            0,
            1,
            u32::MAX as u64,
            u32::MAX as u64 + 1,
            0x0123_4567_89ab_cdef,
            u64::MAX,
        ];
        for a in samples {
            for b in samples {
                let x = Word64::from_u64(a);
                let y = Word64::from_u64(b);
                let sum = x.add(y);
                assert_eq!(((sum.hi as u64) << 32) | sum.lo as u64, a.wrapping_add(b));
                let z = x.blamka(y);
                let expected = a
                    .wrapping_add(b)
                    .wrapping_add(2u64.wrapping_mul((a as u32 as u64) * (b as u32 as u64)));
                assert_eq!(((z.hi as u64) << 32) | z.lo as u64, expected);
                for rotation in [16, 24, 32, 63] {
                    let z = x.rotr(rotation);
                    assert_eq!(
                        ((z.hi as u64) << 32) | z.lo as u64,
                        a.rotate_right(rotation)
                    );
                }
            }
        }
    }

    #[test]
    fn differential_vectors() {
        let salt = *b"0123456789abcdef";
        for (password, m, t, p) in [
            (&b"password"[..], 8, 1, 1),
            (&b"correct horse battery staple"[..], 32, 2, 1),
            (&b"parallel"[..], 16, 1, 2),
            (&b"three-pass"[..], 24, 3, 1),
            (&b"four-lanes"[..], 32, 1, 4),
        ] {
            assert_eq!(
                hash(password, &salt, m, t, p).unwrap(),
                oracle(password, &salt, m, t, p)
            );
        }
    }

    #[test]
    fn deterministic_differential_matrix() {
        // Exercises memory rounding, all supported lane counts, all three pass
        // behaviors, embedded NUL bytes, and every password length boundary.
        let mut state = 0xd1b5_4a32_d192_ed03u64;
        for case in 0..64u32 {
            let lanes = 1 + case % 4;
            let memory = 8 * lanes + (case / 4) % (4 * lanes);
            let passes = 1 + (case / 7) % 3;
            let password_len = 1 + case as usize;
            let mut password = [0u8; 64];
            let mut salt = [0u8; 16];
            for byte in password.iter_mut().chain(salt.iter_mut()) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            assert_eq!(
                hash(&password[..password_len], &salt, memory, passes, lanes).unwrap(),
                oracle(&password[..password_len], &salt, memory, passes, lanes),
                "case={case}, m={memory}, t={passes}, p={lanes}",
            );
        }
    }

    #[test]
    fn randomized_word_arithmetic_matches_u64() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..4096 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let a = state;
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let b = state;
            let x = Word64::from_u64(a);
            let y = Word64::from_u64(b);
            let sum = x.add(y);
            assert_eq!(((sum.hi as u64) << 32) | sum.lo as u64, a.wrapping_add(b));
            let z = x.blamka(y);
            let expected = a
                .wrapping_add(b)
                .wrapping_add(2u64.wrapping_mul((a as u32 as u64) * (b as u32 as u64)));
            assert_eq!(((z.hi as u64) << 32) | z.lo as u64, expected);
            for rotation in [16, 24, 32, 63] {
                let z = x.rotr(rotation);
                assert_eq!(
                    ((z.hi as u64) << 32) | z.lo as u64,
                    a.rotate_right(rotation)
                );
            }
        }
    }
}
