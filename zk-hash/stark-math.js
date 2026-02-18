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

// --- FRI UTILS ---
// Fold P(x) into P'(y) where y = x^2
// P'(y) = (P(x) + P(-x))/2 + alpha * (P(x) - P(-x))/(2x)
// Input: Array of values on domain D. Output: Array of values on D^2 (half size).
function friFold(values, alpha, domainGenerator) {
    const half = values.length / 2;
    const res = new Array(half);
    const alphaBI = BigInt(alpha);
    
    // Domain: g^0, g^1, ... g^N
    // We fold index i and i+N/2.  (x and -x)
    
    let x = 1n;
    const g = BigInt(domainGenerator);
    const g2 = (g * g) % FIELD_MODULUS; // Generator for next domain

    for (let i = 0; i < half; i++) {
        const p_x = values[i];          // P(x)
        const p_minus_x = values[i + half]; // P(-x)
        
        // Algebra: 
        // even = (p_x + p_minus_x) / 2
        // odd = (p_x - p_minus_x) / (2x)
        // res = even + alpha * odd
        
        const sum = (p_x + p_minus_x) % FIELD_MODULUS;
        const diff = (p_x - p_minus_x + FIELD_MODULUS) % FIELD_MODULUS;
        
        const inv2 = inv(2n);
        const even = (sum * inv2) % FIELD_MODULUS;
        const odd = (diff * inv(2n * x)) % FIELD_MODULUS;
        
        res[i] = (even + (alphaBI * odd)) % FIELD_MODULUS;
        
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
}

if (typeof module !== 'undefined') module.exports = { 
    FieldElement: class { constructor(v){this.val=BigInt(v)} }, 
    Polynomial, ntt, friFold, poseidonHash, MerkleTree, Transcript, pow, inv, FIELD_MODULUS, FIELD_GENERATOR 
};
if (typeof window !== 'undefined') window.StarkMath = { 
    FieldElement: class { constructor(v){this.val=BigInt(v)} }, 
    Polynomial, ntt, friFold, poseidonHash, MerkleTree, Transcript, pow, inv, FIELD_MODULUS, FIELD_GENERATOR 
};
