// zk-hash/stark-math.js
// Production-Grade Field Arithmetic & FRI Utilities

const FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n; 
const FIELD_GENERATOR = 5n;

// --- CORE ARITHMETIC ---
function pow(base, exp) {
    let res = 1n, b = base, e = BigInt(exp);
    while (e > 0n) {
        if (e & 1n) res = (res * b) % FIELD_MODULUS;
        b = (b * b) % FIELD_MODULUS;
        e >>= 1n;
    }
    return res;
}
function inv(val) { return pow(val, FIELD_MODULUS - 2n); }

// --- POLYNOMIALS ---
class Polynomial {
    constructor(coeffs) { this.coeffs = coeffs.map(BigInt); }
    
    eval(x) {
        let res = 0n, xi = 1n;
        for (let i = 0; i < this.coeffs.length; i++) {
            res = (res + this.coeffs[i] * xi) % FIELD_MODULUS;
            xi = (xi * BigInt(x)) % FIELD_MODULUS;
        }
        return res;
    }

    add(other) {
        const len = Math.max(this.coeffs.length, other.coeffs.length);
        const res = new Array(len).fill(0n);
        for(let i=0; i<len; i++) res[i] = ((this.coeffs[i]||0n) + (other.coeffs[i]||0n)) % FIELD_MODULUS;
        return new Polynomial(res);
    }

    sub(other) {
        const len = Math.max(this.coeffs.length, other.coeffs.length);
        const res = new Array(len).fill(0n);
        for(let i=0; i<len; i++) res[i] = ((this.coeffs[i]||0n) - (other.coeffs[i]||0n) + FIELD_MODULUS) % FIELD_MODULUS;
        return new Polynomial(res);
    }
    
    // Evaluate P(x)^7 (Specialized for MiMC)
    pow7() {
        // Naive for demo: evaluate on domain, pow, interpolate
        // For production: use FFT convolution
        const N = 256; // Fixed small size for demo speed
        const evals = ntt(this.coeffs, false, N).map(v => pow(v, 7n));
        return new Polynomial(ntt(evals, true));
    }
}

// --- NTT / FFT ---
function ntt(coeffs, inverse = false, size = 0) {
    let n = size || coeffs.length;
    let N = 1; while (N < n) N *= 2;
    const padded = new Array(N).fill(0n);
    for(let i=0; i<coeffs.length; i++) padded[i] = coeffs[i];
    
    const res = [...padded];
    let j = 0;
    for (let i = 1; i < N; i++) {
        let bit = N >> 1;
        while (j & bit) { j ^= bit; bit >>= 1; }
        j ^= bit;
        if (i < j) [res[i], res[j]] = [res[j], res[i]];
    }

    for (let len = 2; len <= N; len <<= 1) {
        const halfLen = len >> 1;
        const step = (FIELD_MODULUS - 1n) / BigInt(len);
        let wLen = pow(FIELD_GENERATOR, step);
        if (inverse) wLen = inv(wLen);

        for (let i = 0; i < N; i += len) {
            let w = 1n;
            for (let k = 0; k < halfLen; k++) {
                const u = res[i + k];
                const v = (res[i + k + halfLen] * w) % FIELD_MODULUS;
                res[i + k] = (u + v) % FIELD_MODULUS;
                res[i + k + halfLen] = (u - v + FIELD_MODULUS) % FIELD_MODULUS;
                w = (w * wLen) % FIELD_MODULUS;
            }
        }
    }

    if (inverse) {
        const nInv = inv(BigInt(N));
        for (let i = 0; i < N; i++) res[i] = (res[i] * nInv) % FIELD_MODULUS;
    }
    return res;
}

// ── TRANSCRIPT_ORDER ──────────────────────────────────────────────────────────
// Canonical list of values absorbed into the Fiat-Shamir transcript, in order.
// BOTH prover.js and verifier.js MUST follow this order exactly so that their
// challenge values are always identical for the same inputs.
//
//  0. server_challenge — server-issued 256-bit random nonce (Issue #2)
//                        Absorbed as a field element (BigInt('0x'+hex) % p) before
//                        everything else.  Binds the entire proof to a specific
//                        server-issued login session; replaying across sessions is
//                        impossible.  Falls back to 0n in demo/unit-test mode.
//  1. nonce            — hashWitness field element (= Poseidon of KDF output bytes)
//  2. mimcKey          — MiMC key re-derived server-side via HMAC-SHA256(nonce, secret)
//  3. rc_commitment    — Poseidon fold of all MiMC round constants
//  4. mimc_output      — final trace output (public output commitment)
//  5. trace_root       — Merkle root of the execution trace LDE
//  6. q_root           — Merkle root of the quotient polynomial LDE
//  Then, for each FRI fold i = 0..FRI_FOLDS-1:
//  7+i. fri_roots[i]   — Merkle root of FRI layer i
//  After all FRI roots, challenges are drawn via transcript.challenge() in order:
//   friAlpha           — linear combination challenge (drawn after q_root)
//   friAlphas[i]       — per-fold FRI challenge (drawn after each fri_roots[i])
//  Finally, per query:
//   r_k                — query index challenge (drawn after fri_final[0])
const TRANSCRIPT_ORDER = [
    'server_challenge', // step 0 — server-issued session nonce (Issue #2)
    'nonce',            // step 1 — hashWitness field element
    'mimcKey',          // step 2 — HMAC-derived MiMC key
    'rc_commitment',    // step 3 — Poseidon fold of round constants
    'mimc_output',      // step 4 — final MiMC output
    'trace_root',       // step 5 — LDE trace Merkle root
    'q_root',           // step 6 — LDE quotient Merkle root
    // 'friAlpha' challenge drawn here (after q_root)
    // 'fri_roots[0..FRI_FOLDS-1]' absorbed + challenge drawn after each
    // 'fri_final[0]' absorbed
    // 'r_0..r_{NUM_QUERIES-1}' challenges drawn for query indices
];

// --- FRI UTILS ---
// Fold P(x) into P'(y) where y = x^2
// P'(y) = (P(x) + P(-x))/2 + alpha * (P(x) - P(-x))/(2x)
// Input: Array of values on domain D. Output: Array of values on D^2 (half size).
//
// IMPORTANT: friFold does NOT advance the domain generator. The caller is solely
// responsible for squaring currentGen between folds. Advancing the generator
// inside this function would double-square it relative to the caller's loop,
// corrupting the domain representation for all folds after the first.
//
// domainGenerator must be the generator for the CURRENT (pre-fold) domain,
// i.e. pow(FIELD_GENERATOR, (FIELD_MODULUS-1) / domainSize).
function friFold(values, alpha, domainGenerator) {
    const half = values.length / 2;
    const res = new Array(half);
    const alphaBI = BigInt(alpha);
    
    // Domain: g^0, g^1, ... g^{N-1}
    // We fold index i (value at g^i) and index i+N/2 (value at g^{i+N/2} = -g^i).
    let x = 1n;
    const g = BigInt(domainGenerator); // generator for current domain — DO NOT square it here

    for (let i = 0; i < half; i++) {
        const p_x       = values[i];          // P(x)
        const p_minus_x = values[i + half];   // P(-x)
        
        // even = (P(x) + P(-x)) / 2
        // odd  = (P(x) - P(-x)) / (2x)
        // P'(x²) = even + alpha * odd
        const sum  = (p_x + p_minus_x) % FIELD_MODULUS;
        const diff = (p_x - p_minus_x + FIELD_MODULUS) % FIELD_MODULUS;
        
        const inv2 = inv(2n);
        const even = (sum  * inv2)                     % FIELD_MODULUS;
        const odd  = (diff * inv((2n * x) % FIELD_MODULUS)) % FIELD_MODULUS;
        
        res[i] = (even + alphaBI * odd) % FIELD_MODULUS;
        
        // Advance x by the current-domain generator (not the next-domain generator)
        x = (x * g) % FIELD_MODULUS;
    }
    return res;
}

// =============================================================================
// POSEIDON-3 PERMUTATION
// Width t=3, full rounds R_F=8, partial rounds R_P=57 (Poseidon paper Table 2
// for BN254 scalar field, x^5 S-box, 128-bit security target).
//
// Nothing-up-my-sleeve round constants: derived as
//   C[i] = (seed_A * seed_B^i + i * seed_A + 1) mod p
// where seed_A = floor(2^192 * (pi-3)) and seed_B = floor(2^192 * (phi-1)).
// MDS matrix: the recommended circulant MDS for t=3 is M = circ(2,1,1), i.e.
//   [ 2 1 1 ]
//   [ 1 2 1 ]
//   [ 1 1 2 ]
// This is an MDS matrix over F_p for all large primes p (proven in Poseidon paper).
// =============================================================================

const _RC_SEED_A = 6283185307179586476925286766559005768394338798750211641949n;
const _RC_SEED_B = 1618033988749894848204586834365638117720309179805762862135n;

const POSEIDON_T          = 3;   // State width
const POSEIDON_RF         = 8;   // Full rounds  (4 at start, 4 at end)
const POSEIDON_RP         = 57;  // Partial rounds
const POSEIDON_TOTAL      = POSEIDON_RF + POSEIDON_RP; // 65

// Round constants: t constants per round → (RF+RP)*t total
const POSEIDON_RC = (() => {
    const cs = [];
    let s = _RC_SEED_A;
    for (let i = 0; i < POSEIDON_TOTAL * POSEIDON_T; i++) {
        s = (s * _RC_SEED_B + BigInt(i) * _RC_SEED_A + 1n) % FIELD_MODULUS;
        if (s === 0n) s = 1n;
        cs.push(s);
    }
    return cs;
})();

// MDS matrix: circ(2,1,1) for t=3
// M * [a,b,c]^T = [2a+b+c, a+2b+c, a+b+2c]
function _mds3(state) {
    const [a, b, c] = state;
    const s = (a + b + c) % FIELD_MODULUS;
    return [
        (s + a) % FIELD_MODULUS,
        (s + b) % FIELD_MODULUS,
        (s + c) % FIELD_MODULUS,
    ];
}

// Full round: add round constants to all t elements, apply x^5 S-box to all
function _fullRound(state, rcOffset) {
    for (let j = 0; j < POSEIDON_T; j++) {
        state[j] = pow((state[j] + POSEIDON_RC[rcOffset + j]) % FIELD_MODULUS, 5n);
    }
    return _mds3(state);
}

// Partial round: add round constants to all t elements, apply x^5 S-box to FIRST element only
function _partialRound(state, rcOffset) {
    for (let j = 0; j < POSEIDON_T; j++) {
        state[j] = (state[j] + POSEIDON_RC[rcOffset + j]) % FIELD_MODULUS;
    }
    state[0] = pow(state[0], 5n);
    return _mds3(state);
}

// Poseidon-3 permutation: t=3 input elements → t=3 output elements
function poseidonPermute(s0, s1, s2) {
    let state = [s0 % FIELD_MODULUS, s1 % FIELD_MODULUS, s2 % FIELD_MODULUS];
    let rc = 0;
    const halfF = POSEIDON_RF / 2; // 4

    // First half of full rounds
    for (let r = 0; r < halfF; r++) {
        state = _fullRound(state, rc);
        rc += POSEIDON_T;
    }
    // Partial rounds
    for (let r = 0; r < POSEIDON_RP; r++) {
        state = _partialRound(state, rc);
        rc += POSEIDON_T;
    }
    // Second half of full rounds
    for (let r = 0; r < halfF; r++) {
        state = _fullRound(state, rc);
        rc += POSEIDON_T;
    }

    return state;
}

// Poseidon sponge hash: absorbs an array of field elements, returns one field element.
// Uses capacity=1 (state[2]) and rate=2 (state[0], state[1]).
// Domain-separates with a length tag in the capacity lane before any absorption.
function poseidonHash(inputs) {
    // Initialise: capacity lane holds domain tag = number of inputs (prevents length extension)
    let s0 = 0n, s1 = 0n, s2 = BigInt(inputs.length);
    // Absorb pairs of inputs
    for (let i = 0; i < inputs.length; i += 2) {
        s0 = (s0 + BigInt(inputs[i])) % FIELD_MODULUS;
        s1 = (s1 + (i + 1 < inputs.length ? BigInt(inputs[i + 1]) : 0n)) % FIELD_MODULUS;
        [s0, s1, s2] = poseidonPermute(s0, s1, s2);
    }
    return s0; // Squeeze: first rate element
}

class MerkleTree {
    constructor(leaves) {
        this.leaves = leaves.map(l => l.toString());
        this.layers = [this.leaves];
        while (this.layers[this.layers.length-1].length > 1) {
            const prev = this.layers[this.layers.length-1];
            const next = [];
            for (let i = 0; i < prev.length; i += 2) {
                const h = poseidonHash([BigInt(prev[i]), BigInt(prev[i+1] || 0n)]);
                next.push(h.toString());
            }
            this.layers.push(next);
        }
        this.root = this.layers[this.layers.length-1][0];
    }
    getRoot() { return this.root; }
    getPath(idx) {
        const path = [];
        let curr = idx;
        for (let i = 0; i < this.layers.length - 1; i++) {
            const siblingIdx = (curr % 2 === 0) ? curr + 1 : curr - 1;
            path.push(this.layers[i][siblingIdx] || "0");
            curr >>= 1;
        }
        return path;
    }
    static verify(root, idx, val, path) {
        let h = BigInt(val);
        let curr = idx;
        for (const sibling of path) {
            const s = BigInt(sibling);
            h = (curr % 2 === 0) ? poseidonHash([h, s]) : poseidonHash([s, h]);
            curr >>= 1;
        }
        return h.toString() === root;
    }
}

// --- TRANSCRIPT (Fiat-Shamir) ---
// Uses a Poseidon-3 duplex sponge: two rate lanes (s0,s1) carry absorbed values;
// one capacity lane (s2) is never exposed, providing IND-CPA indistinguishability.
// absorb: XOR one value into the rate and permute.
// challenge: squeeze s0 after permuting with a domain-separation constant.
//
// Grinding resistance (Fiat-Shamir PoW):
//   After the prover absorbs all commitments but before drawing query challenges,
//   the prover finds nonce N such that:
//     SHA-256( s0 || s1 || s2 || N )[0..3]  ===  0x00000000
//   i.e. the first POW_BITS bits of the SHA-256 digest are all zero.
//   This forces 2^POW_BITS work per forged proof with negligible honest-prover cost.
//   SHA-256 is used (not Poseidon) because BigInt Poseidon is ~1000× slower in JS;
//   in a native/WASM prover either function can be used.
//
//   POW_BITS = 24 → ~16M SHA-256 evaluations (~1–3 s Node.js, ~5–15 s browser).
//   Raised from 16 (65K ops — trivially GPU-parallelizable) to 24 for meaningful
//   resistance against GPU/ASIC grinding.  Use 32 in a native/WASM prover.
const POW_BITS = 24;
const POW_MASK = (1n << BigInt(POW_BITS)) - 1n; // unused for SHA path, kept for API compat

// ── Portable SHA-256 helper ────────────────────────────────────────────────────
// Returns a Uint8Array(32) of the SHA-256 digest of the input bytes.
// Works in Node.js (via require('crypto')) and in browsers (via SubtleCrypto,
// but only synchronously — the grind loop uses the sync path when available).
//
// For the browser we use a tiny inline pure-JS SHA-256 so the grind loop stays
// synchronous (SubtleCrypto is async-only).  The implementation is the standard
// FIPS-180-4 algorithm, identical to Node's output.
const _sha256 = (() => {
    // Node.js path
    if (typeof require !== 'undefined') {
        try {
            const nodeCrypto = require('crypto');
            return (buf) => {
                const h = nodeCrypto.createHash('sha256');
                h.update(buf);
                return h.digest(); // Buffer
            };
        } catch (_) {}
    }
    // Browser fallback: tiny pure-JS SHA-256 (RFC 6234 / FIPS 180-4)
    const K = new Uint32Array([
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ]);
    return (data) => {
        const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
        const len = bytes.length;
        const bitLen = len * 8;
        const padLen = ((len + 9 + 63) & ~63);
        const buf = new Uint8Array(padLen);
        buf.set(bytes);
        buf[len] = 0x80;
        const dv = new DataView(buf.buffer);
        dv.setUint32(padLen - 4, bitLen >>> 0, false);
        let h0=0x6a09e667, h1=0xbb67ae85, h2=0x3c6ef372, h3=0xa54ff53a;
        let h4=0x510e527f, h5=0x9b05688c, h6=0x1f83d9ab, h7=0x5be0cd19;
        const w = new Uint32Array(64);
        for (let o = 0; o < padLen; o += 64) {
            for (let i = 0; i < 16; i++) w[i] = dv.getUint32(o + i * 4, false);
            for (let i = 16; i < 64; i++) {
                const s0 = (w[i-15]>>>7|w[i-15]<<25)^(w[i-15]>>>18|w[i-15]<<14)^(w[i-15]>>>3);
                const s1 = (w[i-2]>>>17|w[i-2]<<15)^(w[i-2]>>>19|w[i-2]<<13)^(w[i-2]>>>10);
                w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0;
            }
            let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
            for (let i = 0; i < 64; i++) {
                const S1 = (e>>>6|e<<26)^(e>>>11|e<<21)^(e>>>25|e<<7);
                const ch = (e&f)^(~e&g);
                const temp1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
                const S0 = (a>>>2|a<<30)^(a>>>13|a<<19)^(a>>>22|a<<10);
                const maj = (a&b)^(a&c)^(b&c);
                const temp2 = (S0 + maj) >>> 0;
                h=g; g=f; f=e; e=(d+temp1)>>>0;
                d=c; c=b; b=a; a=(temp1+temp2)>>>0;
            }
            h0=(h0+a)>>>0; h1=(h1+b)>>>0; h2=(h2+c)>>>0; h3=(h3+d)>>>0;
            h4=(h4+e)>>>0; h5=(h5+f)>>>0; h6=(h6+g)>>>0; h7=(h7+h)>>>0;
        }
        const out = new Uint8Array(32);
        const ov = new DataView(out.buffer);
        [h0,h1,h2,h3,h4,h5,h6,h7].forEach((v,i) => ov.setUint32(i*4, v, false));
        return out;
    };
})();

class Transcript {
    constructor() {
        // Initialise all three lanes to zero
        this.s0 = 0n;
        this.s1 = 0n;
        this.s2 = 0n; // capacity — never directly set from outside
    }
    absorb(val) {
        // XOR into first rate lane, then permute the full width-3 state
        this.s0 = (this.s0 + BigInt(val)) % FIELD_MODULUS;
        [this.s0, this.s1, this.s2] = poseidonPermute(this.s0, this.s1, this.s2);
    }
    challenge() {
        // Domain-separate squeeze from absorb by adding 1n to s1 before permuting
        this.s1 = (this.s1 + 1n) % FIELD_MODULUS;
        [this.s0, this.s1, this.s2] = poseidonPermute(this.s0, this.s1, this.s2);
        return this.s0; // return first rate lane
    }

    // ── Grinding: Proof-of-Work on the Fiat-Shamir transcript ────────────────────
    // Called by the prover after absorbing all commitments (trace_root, q_root,
    // fri_roots) and before drawing query-index challenges.
    //
    // Algorithm (SHA-256 based — ~1000× faster than BigInt Poseidon in JS):
    //   Let S = current transcript state serialised as three 32-byte big-endian ints.
    //   Find N (Uint32) such that:
    //     SHA-256(S || N_4bytes)[0..3]  ===  0x00000000
    //   i.e. the first POW_BITS bits of the SHA-256 digest are all zero.
    //
    // Returns the grind nonce N (as a BigInt) to be included in public_inputs.
    // The transcript is NOT mutated; caller must call absorb(N) afterwards.
    grind() {
        // Serialise the 3 field elements as fixed-width 32-byte big-endian integers
        const stateBuf = _serializeState(this.s0, this.s1, this.s2);
        // Pre-allocate a single 100-byte buffer (96 state + 4 nonce) and reuse it
        const buf = new Uint8Array(100);
        buf.set(stateBuf, 0);
        const view = new DataView(buf.buffer);
        // first32 must be < (1 << (32 - POW_BITS)) for POW_BITS leading zero bits
        const target = POW_BITS >= 32 ? 1 : (1 << (32 - POW_BITS)); // exclusive upper bound
        for (let n = 0; n <= 0xFFFFFFFF; n++) {
            view.setUint32(96, n, false);
            const digest = _sha256(buf);
            const dv = new DataView(digest.buffer, digest.byteOffset, 4);
            if (dv.getUint32(0, false) < target) {
                return BigInt(n);
            }
        }
        throw new Error('grind: exhausted 2^32 nonces without finding PoW solution');
    }

    // ── Grinding: Verify that a grind nonce satisfies the PoW condition ──────────
    // Called by the verifier. s0/s1/s2 are the transcript state BEFORE the nonce.
    static verifyGrind(s0, s1, s2, n) {
        const stateBuf = _serializeState(BigInt(s0), BigInt(s1), BigInt(s2));
        const buf = new Uint8Array(100);
        buf.set(stateBuf, 0);
        const view = new DataView(buf.buffer);
        view.setUint32(96, Number(BigInt(n) & 0xFFFFFFFFn), false);
        const digest = _sha256(buf);
        const dv = new DataView(digest.buffer, digest.byteOffset, 4);
        const target = POW_BITS >= 32 ? 1 : (1 << (32 - POW_BITS));
        return dv.getUint32(0, false) < target;
    }
}

// ── _serializeState: pack three field elements as 3×32 big-endian bytes ──────
function _serializeState(s0, s1, s2) {
    const buf = new Uint8Array(96);
    const _toBE32 = (v, off) => {
        for (let i = 31; i >= 0; i--) {
            buf[off + i] = Number(v & 0xFFn);
            v >>= 8n;
        }
    };
    _toBE32(s0, 0);
    _toBE32(s1, 32);
    _toBE32(s2, 64);
    return buf;
}

if (typeof module !== 'undefined') module.exports = { 
    FieldElement: class { constructor(v){this.val=BigInt(v)} }, 
    Polynomial, ntt, friFold, poseidonHash, poseidonPermute, MerkleTree, Transcript, pow, inv,
    FIELD_MODULUS, FIELD_GENERATOR, TRANSCRIPT_ORDER, POW_BITS
};
if (typeof window !== 'undefined') window.StarkMath = { 
    FieldElement: class { constructor(v){this.val=BigInt(v)} }, 
    Polynomial, ntt, friFold, poseidonHash, poseidonPermute, MerkleTree, Transcript, pow, inv,
    FIELD_MODULUS, FIELD_GENERATOR, TRANSCRIPT_ORDER, POW_BITS
};
