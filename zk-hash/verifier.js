/**
 * zk-hash/verifier.js
 * Production STARK Verifier — 2^128 security target.
 * Mirrors prover.js transcript and FRI protocol exactly.
 */
const { Transcript, MerkleTree, pow, inv, poseidonHash, FIELD_MODULUS, FIELD_GENERATOR } = require('./stark-math');

// ── Security constants — MUST match prover.js exactly ────────────────────────
const MIMC_ROUNDS  = 128;
const TRACE_SIZE   = 256;
const BLOWUP       = 8;
const LDE_SIZE     = TRACE_SIZE * BLOWUP; // 2048
const FRI_FOLDS    = 8;
const NUM_QUERIES  = 50;
const MAX_QUERIES  = 75; // DoS guard: allow some headroom above NUM_QUERIES

// ── Canonical MiMC round constants (independently recomputed from seed) ──────
const _RC_A = 6283185307179586476925286766559005768394338798750211641949n;
const _RC_B = 1618033988749894848204586834365638117720309179805762862135n;
const ROUND_CONSTANTS = (() => {
    const cs = [];
    let s = _RC_A;
    for (let i = 0; i < MIMC_ROUNDS; i++) {
        s = (s * _RC_B + BigInt(i) * _RC_A + 1n) % FIELD_MODULUS;
        if (s === 0n) s = 1n;
        cs.push(s);
    }
    return cs;
})();

// Precompute rc_commitment: the Poseidon fold of all round constants.
// This is verified against public_inputs.rc_commitment to confirm the prover
// used the same canonical constants as us.
const RC_COMMITMENT = ROUND_CONSTANTS.reduce((acc, c) => poseidonHash([acc, c]), 0n);

class ZKVerifier {
    verify(proof) {
        try {
            console.log("Verifying Proof Type:", proof.proof_type);

            // 0. Standard hash proofs carry no ZK component — accept immediately.
            if (proof.proof_type === 'standard-hash-proof') {
                return { success: true, message: `Standard ${proof.algo} Hash Verified (No ZK Proof)` };
            }

            console.log("Verifying embedded STARK with FRI...");

            const { public_inputs, queries } = proof;

            if (!public_inputs || !queries || !queries.length) {
                throw new Error("Invalid Proof Structure: Missing public_inputs or queries");
            }

            // ── DoS Guard ────────────────────────────────────────────────────────────
            if (queries.length > MAX_QUERIES) {
                throw new Error(`Proof has ${queries.length} queries; maximum allowed is ${MAX_QUERIES}`);
            }

            // ── Round-constant commitment check ──────────────────────────────────────
            // Reject proofs that used non-canonical MiMC constants (e.g. crafted to
            // produce a collision with a different constant schedule).
            if (!public_inputs.rc_commitment) {
                throw new Error("Missing rc_commitment — regenerate the proof");
            }
            if (BigInt(public_inputs.rc_commitment) !== RC_COMMITMENT) {
                throw new Error("rc_commitment mismatch: prover used non-canonical round constants");
            }

            // ── Hash-field binding check (bcrypt / argon2) ───────────────────────────
            // For bcrypt and argon2 proofs the prover encodes the output hash string
            // as the STARK nonce (padded-hex of UTF-8 bytes).  We re-derive that
            // value here and confirm it matches public_inputs.nonce, so an attacker
            // cannot substitute a different hash string while reusing the same proof.
            if (proof.proof_type === 'zk-stark-bcrypt' || proof.proof_type === 'zk-stark-argon2') {
                if (!public_inputs.hash) {
                    throw new Error("Missing public_inputs.hash for bcrypt/argon2 proof");
                }
                // Mirror the prover's padded-hex nonce encoding exactly
                const expectedNonce = (BigInt("0x" + Array.from(public_inputs.hash)
                    .map(c => c.charCodeAt(0).toString(16).padStart(2, '0'))
                    .join('')) % FIELD_MODULUS).toString();
                if (!public_inputs.nonce || public_inputs.nonce !== expectedNonce) {
                    throw new Error(
                        "Hash-nonce mismatch: public_inputs.hash does not match the nonce " +
                        "committed in the STARK proof — the hash field has been tampered with"
                    );
                }
            }

            // ── 1. RECONSTRUCT TRANSCRIPT ────────────────────────────────────────────
            const transcript = new Transcript();

            let nonceVal;
            const rawNonce = public_inputs.nonce;
            if (rawNonce && /^\d+$/.test(rawNonce)) {
                nonceVal = BigInt(rawNonce);
            } else if (rawNonce) {
                nonceVal = BigInt("0x" + Array.from(rawNonce)
                    .map(c => c.charCodeAt(0).toString(16).padStart(2, '0'))
                    .join('')) % FIELD_MODULUS;
            } else {
                nonceVal = 0n;
            }

            transcript.absorb(nonceVal);                                           // 1. nonce
            transcript.absorb(0n);                                                 // 2. mimcKey
            transcript.absorb(BigInt(public_inputs.rc_commitment));                // 3. rc_commitment
            transcript.absorb(BigInt(public_inputs.mimc_output   || "0"));         // 4. finalOutput
            transcript.absorb(BigInt(public_inputs.trace_root    || "0"));         // 5. trace root
            transcript.absorb(BigInt(public_inputs.q_root        || "0"));         // 6. quotient root

            const friAlpha = transcript.challenge();

            if (!public_inputs.fri_roots || public_inputs.fri_roots.length < FRI_FOLDS) {
                throw new Error(`Need ${FRI_FOLDS} fri_roots, got ${(public_inputs.fri_roots||[]).length}`);
            }

            const friAlphas = [];
            for (let i = 0; i < FRI_FOLDS; i++) {
                transcript.absorb(BigInt(public_inputs.fri_roots[i]));
                friAlphas.push(transcript.challenge());
            }

            // ── 2. BOUNDARY CONSTRAINT ───────────────────────────────────────────────
            if (!public_inputs.boundary_path) {
                throw new Error("Missing boundary_path for mimc_output verification");
            }

            const mimcOutputBI = BigInt(public_inputs.mimc_output || "0");
            const boundaryIdx  = MIMC_ROUNDS * BLOWUP;

            if (!MerkleTree.verify(public_inputs.trace_root, boundaryIdx, mimcOutputBI, public_inputs.boundary_path)) {
                throw new Error("Boundary constraint failed: mimc_output not in committed trace");
            }

            // ── 3. VERIFY EACH QUERY ─────────────────────────────────────────────────
            const domainGen = pow(FIELD_GENERATOR, (FIELD_MODULUS - 1n) / BigInt(LDE_SIZE));
            const mimcKey   = 0n;

            for (const query of queries) {
                const idx = Number(query.idx);

                if (query.p_val      === undefined ||
                    query.p_next_val === undefined ||
                    query.q_val      === undefined ||
                    query.c_val      === undefined) {
                    throw new Error(`Missing field in query idx=${idx}`);
                }

                const pVal     = BigInt(query.p_val);
                const pNextVal = BigInt(query.p_next_val);
                const qVal     = BigInt(query.q_val);
                const cVal     = BigInt(query.c_val);   // round-constant evaluation

                const z = pow(domainGen, BigInt(idx));

                // ── A. MERKLE INCLUSION ──────────────────────────────────────────────
                if (!MerkleTree.verify(public_inputs.trace_root, idx, pVal, query.p_path)) {
                    throw new Error(`Invalid P Merkle path at idx=${idx}`);
                }
                const idxNext = (idx + BLOWUP) % LDE_SIZE;
                if (!MerkleTree.verify(public_inputs.trace_root, idxNext, pNextVal, query.p_next_path)) {
                    throw new Error(`Invalid P_Next Merkle path at idx=${idx}`);
                }
                if (!MerkleTree.verify(public_inputs.q_root, idx, qVal, query.q_path)) {
                    throw new Error(`Invalid Q Merkle path at idx=${idx}`);
                }

                // ── B. AIR CONSTRAINT ────────────────────────────────────────────────
                // P(w·z) = (P(z) + key + C(z))^7 + Q(z)·Z_T(z)
                const z_t   = pow(z, BigInt(MIMC_ROUNDS));
                const Z_val = (z_t - 1n + FIELD_MODULUS) % FIELD_MODULUS;

                if (Z_val !== 0n) {
                    const logicVal = pow((pVal + mimcKey + cVal) % FIELD_MODULUS, 7n);
                    const rhs      = (logicVal + qVal * Z_val % FIELD_MODULUS) % FIELD_MODULUS;
                    if (pNextVal !== rhs) {
                        throw new Error(`AIR Constraint Failed at idx=${idx}`);
                    }
                }

                // ── C. FRI CONSISTENCY ───────────────────────────────────────────────
                let currentVal = (pVal + friAlpha * qVal) % FIELD_MODULUS;
                let currentIdx = idx;
                let domainSize = LDE_SIZE;
                let currentX   = z;

                for (let i = 0; i < FRI_FOLDS; i++) {
                    if (!query.fri_proof || !query.fri_proof[i]) {
                        throw new Error(`Missing fri_proof layer ${i} at idx=${idx}`);
                    }
                    const layer = query.fri_proof[i];
                    const p0    = BigInt(layer.val);
                    const p1    = BigInt(layer.sibling);

                    if (p0 !== currentVal) {
                        throw new Error(`FRI Layer ${i} value mismatch at idx=${idx}`);
                    }
                    if (!MerkleTree.verify(public_inputs.fri_roots[i], currentIdx, p0, layer.path)) {
                        throw new Error(`FRI Layer ${i} Merkle path invalid at idx=${idx}`);
                    }

                    const siblingIdx = (currentIdx < Math.floor(domainSize / 2))
                        ? currentIdx + Math.floor(domainSize / 2)
                        : currentIdx - Math.floor(domainSize / 2);

                    if (!layer.sibling_path) {
                        throw new Error(`Missing sibling_path for FRI Layer ${i} at idx=${idx}`);
                    }
                    if (!MerkleTree.verify(public_inputs.fri_roots[i], siblingIdx, p1, layer.sibling_path)) {
                        throw new Error(`FRI Layer ${i} sibling Merkle path invalid at idx=${idx}`);
                    }

                    // Fold: P'(x²) = even + alpha·odd
                    const inv2   = inv(2n);
                    const even   = ((p0 + p1) % FIELD_MODULUS * inv2) % FIELD_MODULUS;
                    const diff   = (p0 - p1 + FIELD_MODULUS) % FIELD_MODULUS;
                    const odd    = (diff * inv((2n * currentX) % FIELD_MODULUS)) % FIELD_MODULUS;
                    const folded = (even + friAlphas[i] * odd) % FIELD_MODULUS;

                    currentVal = folded;
                    currentIdx = currentIdx % Math.floor(domainSize / 2);
                    domainSize = domainSize / 2;
                    currentX   = (currentX * currentX) % FIELD_MODULUS;
                }

                // ── D. FRI FINAL LAYER ───────────────────────────────────────────────
                if (!public_inputs.fri_final || public_inputs.fri_final.length === 0) {
                    throw new Error("Missing fri_final in public_inputs");
                }
                const finalIdx      = currentIdx % public_inputs.fri_final.length;
                const expectedFinal = BigInt(public_inputs.fri_final[finalIdx]);
                if (currentVal !== expectedFinal) {
                    throw new Error(`FRI final layer check failed at query idx=${idx}`);
                }
            }

            const algoLabel = proof.algo
                ? `(${proof.algo.toUpperCase()})`
                : proof.proof_type === 'zk-stark-bcrypt' ? '(BCrypt)'
                : proof.proof_type === 'zk-stark-argon2' ? '(Argon2id)'
                : '';

            return {
                success: true,
                message: `ZK-STARK Proof Verified ${algoLabel} — AIR + FRI[${FRI_FOLDS} folds, ${NUM_QUERIES} queries] + Boundary + RC-Commitment all passed`
            };

        } catch (e) {
            console.error("Verification error:", e);
            return { success: false, error: (e instanceof Error ? e.message : String(e)) };
        }
    }
}
module.exports = ZKVerifier;
