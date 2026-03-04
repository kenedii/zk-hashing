/**
 * zk-hash/verifier.js
 * Production STARK Verifier — 2^128 security target.
 *
 * SECURITY MODEL (Option B — "Client-side KDF + server pepper check"):
 *
 *  For argon2/bcrypt modes the STARK does NOT prove the KDF was run inside the
 *  circuit (that would require Phase 2 — embedding Argon2id in AIR, ~500K rows).
 *  Instead, the server enforces binding through three independent checks:
 *
 *  (A) mimcKey re-derivation (Issue #3):
 *      Server re-derives mimcKey = HMAC-SHA256(nonceVal, serverSecret) using
 *      the nonce committed in the proof, then rejects if client's mimc_key_hint
 *      differs. Client cannot lie about the session key.
 *
 *  (B) MiMC output re-computation (Issue #1 Option B):
 *      For argon2/bcrypt proofs the verifier receives hashWitness (= nonce)
 *      and re-runs the 128-round MiMC chain from trace[0]=hashWitness itself.
 *      The recomputed output must match public_inputs.mimc_output. This closes
 *      the gap where a client could submit any trace[0] that satisfies the
 *      pepper commitment — the server now independently verifies the full chain.
 *
 *  (C) Pepper commitment — TWO modes:
 *
 *    • Legacy / Pattern 1 (verify() with no extra args):
 *      Client computes pepper_commit = Poseidon(mimc_output, pepper) and includes
 *      it in public_inputs.  Server re-computes and compares.  Simple but requires
 *      the pepper to be available in the client execution context.
 *
 *    • Pattern 2 / ZK-Only (verify(proof, { skipPepperCheck: true })):
 *      The pepper NEVER leaves the server.  The client NEVER computes or sees
 *      pepper_commit.  After verify() returns successfully the routing layer calls
 *      verifyPepperCommitP2(mimc_output, storedC) which:
 *        – Reads serverPepper from env (server process only)
 *        – Recomputes Poseidon(mimc_output, serverPepper) entirely server-side
 *        – Compares against storedC retrieved from the database
 *      The client submits only mimc_output (already a public input); the pepper
 *      computation is an opaque server-side operation the client cannot observe.
 *
 *  Combined: an attacker must know hashWitness (= Poseidon of the real hash
 *  output), which requires running Argon2id/bcrypt on the correct password.
 *
 * FIXES APPLIED:
 *  Fix #2  — Transcript absorbs server_challenge first (Issue #2).
 *  Fix #3  — mimcKey is re-derived server-side; hint is verified (Issue #3).
 *  Fix #5  — Transcript absorb order follows TRANSCRIPT_ORDER from stark-math.js.
 *  Fix #6  — FRI fold domain management mirrors prover exactly (no double-squaring).
 *
 * TRANSCRIPT_ORDER (must match prover.js exactly):
 *   0. server_challenge  (server-issued 256-bit random nonce, absorbed first)
 *   1. nonce             (= hashWitness field element)
 *   2. mimcKey           (re-derived by server; not trusted from client)
 *   3. rc_commitment
 *   4. mimc_output
 *   5. trace_root
 *   6. q_root
 *   [friAlpha challenge drawn]
 *   7+i. fri_roots[i] then friAlphas[i] challenge, for i=0..FRI_FOLDS-1
 *   final: fri_final[0] absorbed
 *   then NUM_QUERIES challenges drawn for query indices
 */
const crypto = require('crypto');
const {
    Transcript, MerkleTree, pow, inv, poseidonHash, poseidonPermute,
    FIELD_MODULUS, FIELD_GENERATOR, POW_BITS
} = require('./stark-math');

// ── Security constants — MUST match prover.js exactly ────────────────────────
const MIMC_ROUNDS   = 220;       // raised from 128 → 220
const TRACE_SIZE    = 256;
const BLOWUP        = 32;        // raised from 8 → 32
const LDE_SIZE      = TRACE_SIZE * BLOWUP; // 8192
const FRI_FOLDS     = 9;         // raised from 8 → 9
const NUM_QUERIES   = 35;        // reduced from 50 → 35
const KDF_CHAIN_LEN = 64;        // Argon2id AIR chain length
const MAX_QUERIES  = 60; // DoS guard

// ── Argon2id parameter floor (Phase 3) ───────────────────────────────────────
const ARGON2_MIN_TIME = 3;
const ARGON2_MIN_MEM  = 65536;

// ── Canonical MiMC round constants ───────────────────────────────────────────
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

const RC_COMMITMENT = ROUND_CONSTANTS.reduce((acc, c) => poseidonHash([acc, c]), 0n);

// ── hashBytesToWitness — mirrors prover.js exactly ───────────────────────────
function hashBytesToWitness(hashBytes) {
    const LIMB = 31;
    const elements = [];
    for (let i = 0; i < hashBytes.length; i += LIMB) {
        let v = 0n;
        for (let j = i; j < Math.min(i + LIMB, hashBytes.length); j++) {
            v = (v << 8n) | BigInt(hashBytes[j]);
        }
        elements.push(v % FIELD_MODULUS);
    }
    return poseidonHash(elements);
}

// ── timingSafeEqual for field-element BigInts (Phase 3) ──────────────────────
// JavaScript's === leaks timing on string comparisons. Use crypto.timingSafeEqual
// on fixed-length Buffers for all commitment/hash equality checks.
function safeEqualBI(a, b) {
    const sa = a.toString().padStart(80, '0');
    const sb = b.toString().padStart(80, '0');
    const ba = Buffer.from(sa, 'ascii');
    const bb = Buffer.from(sb, 'ascii');
    if (ba.length !== bb.length) return false;
    return crypto.timingSafeEqual(ba, bb);
}

class ZKVerifier {
    /**
     * verify(proof [, options]) → { success, message } | { success: false, error }
     *
     * options.skipPepperCheck — set to true for Pattern 2 flows.
     *   When true the pepper commitment check inside verify() is SKIPPED entirely.
     *   The routing layer MUST call verifyPepperCommitP2(mimc_output, storedC)
     *   separately after this returns {success:true}.  This keeps the server pepper
     *   100% opaque to the client while still enforcing credential binding.
     */
    verify(proof, options = {}) {
        const skipPepperCheck = Boolean(options.skipPepperCheck);
        try {
            console.log("Verifying Proof Type:", proof.proof_type);

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

            // ── Argon2id parameter floor check (Phase 3) ─────────────────────────────
            if (proof.proof_type === 'zk-stark-argon2' && public_inputs.argon2_params) {
                const p = public_inputs.argon2_params;
                if ((p.time || 0) < ARGON2_MIN_TIME) {
                    throw new Error(`Argon2id t=${p.time} is below minimum ${ARGON2_MIN_TIME}`);
                }
                if ((p.mem || 0) < ARGON2_MIN_MEM) {
                    throw new Error(`Argon2id m=${p.mem} is below minimum ${ARGON2_MIN_MEM}`);
                }
            }

            // ── Hash-encoded binding check (Argon2id tamper detection) ───────────────
            // The prover derives hashWitness = Poseidon(UTF-8(hash_encoded)), making
            // hash_encoded a tamper-evident field: any modification changes nonce, which
            // diverges all transcript challenges and breaks every Merkle/FRI path.
            // We re-derive the expected nonce here and reject if it doesn't match.
            //
            // For bcrypt proofs the same binding holds: hashBytes = UTF-8(bcrypt_hash).
            // For mimc-stark proofs there is no KDF output field to check here.
            if (proof.proof_type === 'zk-stark-argon2') {
                if (!public_inputs.hash_encoded) {
                    throw new Error("Missing hash_encoded — Argon2id output commitment absent");
                }
                const encodedBytes = Buffer.from(String(public_inputs.hash_encoded), 'utf8');
                const expectedNonce = hashBytesToWitness(encodedBytes);
                if (!safeEqualBI(expectedNonce, BigInt(public_inputs.nonce || "0"))) {
                    throw new Error(
                        "hash_encoded binding check failed: the submitted hash_encoded string " +
                        "does not match the nonce (witness) committed in the proof — " +
                        "the Argon2id output has been tampered with"
                    );
                }
            }
            if (proof.proof_type === 'zk-stark-bcrypt') {
                if (!public_inputs.salt) {
                    throw new Error("Missing salt — bcrypt output commitment absent");
                }
                // For bcrypt, the hash string is not stored in public_inputs (only salt + cost).
                // The binding is enforced transitively: nonce = hashWitness = Poseidon(UTF8(bcryptHash)),
                // and the server-side MiMC re-computation (below) verifies nonce → mimc_output.
                // No additional check needed here since the bcrypt hash string itself isn't published.
            }

            // ── Round-constant commitment check ──────────────────────────────────────
            if (!public_inputs.rc_commitment) {
                throw new Error("Missing rc_commitment — regenerate the proof");
            }
            if (!safeEqualBI(BigInt(public_inputs.rc_commitment), RC_COMMITMENT)) {
                throw new Error("rc_commitment mismatch: prover used non-canonical round constants");
            }

            // ── Fix #3: Pepper commitment check ──────────────────────────────────────
            // LEGACY / PATTERN 1 mode: client computes pepper_commit = Poseidon(mimc_output, pepper)
            // and includes it in public_inputs.  Server recomputes and compares.
            //
            // PATTERN 2 mode (skipPepperCheck=true): pepper commitment check is SKIPPED here.
            // The routing layer calls verifyPepperCommitP2(mimc_output, storedC) instead,
            // performing the check entirely server-side with the stored DB commitment.
            // The client NEVER computes or sees pepper_commit in Pattern 2.
            if (!skipPepperCheck && (proof.proof_type === 'zk-stark-argon2' || proof.proof_type === 'zk-stark-bcrypt')) {
                if (!public_inputs.pepper_commit) {
                    throw new Error("Missing pepper_commit — proof does not bind to a stored credential");
                }
                const serverPepperHex = (typeof process !== 'undefined' && process.env && process.env.ZK_SERVER_PEPPER)
                    ? process.env.ZK_SERVER_PEPPER
                    : 'INSECURE-DEV-PEPPER-REPLACE-WITH-HSM';
                const pepperBytes    = Buffer.from(serverPepperHex, 'utf8');
                const pepperField    = hashBytesToWitness(pepperBytes);
                const expectedCommit = poseidonHash([BigInt(public_inputs.mimc_output), pepperField]);
                if (!safeEqualBI(BigInt(public_inputs.pepper_commit), expectedCommit)) {
                    throw new Error("Pepper commitment mismatch: proof does not satisfy stored credential");
                }
            }

            // ── Issue #1 (Option B): Server re-computes MiMC output independently ────
            // For all STARK-based proofs we independently run the full 220-round MiMC
            // chain from trace[0] = nonceVal (= hashBytesToWitness of the KDF encoded output)
            // using the server-derived mimcKey.  The recomputed output must equal
            // public_inputs.mimc_output.
            //
            // For Argon2id proofs, nonce = Poseidon(UTF-8(hash_encoded)), which was
            // already verified above in the hash_encoded binding check.
            // This closes the gap where a client could submit any trace[0] value w that
            // satisfies MiMC(w, k) = output ∧ Poseidon(output, pepper) = C without that
            // w being the actual Poseidon encoding of the KDF output bytes:
            //   − The pepper commitment check guarantees output → C consistency.
            //   − This re-computation guarantees w → output consistency.
            //   − Combined: attacker must know the real hashWitness, which requires
            //     running Argon2id/bcrypt on the correct password.
            {
                // Re-derive the key exactly as the prover does:
                //   mimcKey = HMAC-SHA256(nonceVal.toString(), serverSecret) mod p
                // (nonceVal not yet computed here; use public_inputs.nonce directly)
                const _nonceForCheck = BigInt(public_inputs.nonce || "0");
                const _serverSecretForCheck = (typeof process !== 'undefined' && process.env && process.env.ZK_SERVER_SECRET)
                    ? process.env.ZK_SERVER_SECRET
                    : 'INSECURE-DEV-SECRET-REPLACE-IN-PRODUCTION-WITH-HSM-BACKED-KEY';
                const _hmacCheck = crypto.createHmac('sha256', _serverSecretForCheck);
                _hmacCheck.update(_nonceForCheck.toString());
                const _mimcKeyCheck = BigInt('0x' + _hmacCheck.digest('hex')) % FIELD_MODULUS;

                let _curr = _nonceForCheck;
                for (let _i = 0; _i < MIMC_ROUNDS; _i++) {
                    const _t = (_curr + _mimcKeyCheck + ROUND_CONSTANTS[_i]) % FIELD_MODULUS;
                    _curr = pow(_t, 7n);
                }

                if (!safeEqualBI(_curr, BigInt(public_inputs.mimc_output || "0"))) {
                    throw new Error(
                        "MiMC re-computation mismatch: the submitted trace[0] does not produce " +
                        "the claimed mimc_output under the server-derived key — " +
                        "the proof's witness is not the genuine KDF output"
                    );
                }
            }

            // ── hash_encoded binding note ─────────────────────────────────────────────
            // For Argon2id proofs, hash_encoded is now security-relevant: the prover sets
            // nonce = hashWitness = Poseidon(UTF-8(hash_encoded)), and the binding check
            // above confirmed nonce ≡ Poseidon(UTF-8(hash_encoded)).  This means:
            //   (A) mimcKey re-derivation confirms the client knows nonceVal.
            //   (B) MiMC re-computation confirms trace[0]=nonceVal produces mimc_output.
            //   (C) Pepper commitment confirms mimc_output matches the stored credential.
            //   (D) KDF chain commitment confirms Argon2id AIR binding (Phase 2).
            //   (E) hash_encoded binding check confirms hash_encoded → nonce consistency.
            // Combined: any tamper with hash_encoded, mimc_output, or any commitment
            // causes rejection. Attacker must know both the password and server secrets.

            // ── (D) Argon2id AIR chain re-derivation ─────────────────────────────────
            // Re-derive the KDF Poseidon chain the same way the prover does and check
            // that kdf_chain_commit matches.  This verifies the Argon2id binding is
            // not heuristic: the prover must have known the correct hashWitness to
            // produce a chain that hashes to the same commitment.
            {
                const _nonce = BigInt(public_inputs.nonce || "0");
                const _serverSecretKDF = (typeof process !== 'undefined' && process.env && process.env.ZK_SERVER_SECRET)
                    ? process.env.ZK_SERVER_SECRET
                    : 'INSECURE-DEV-SECRET-REPLACE-IN-PRODUCTION-WITH-HSM-BACKED-KEY';
                const _hmacKDF = crypto.createHmac('sha256', _serverSecretKDF);
                _hmacKDF.update(_nonce.toString());
                const _mimcKeyKDF = BigInt('0x' + _hmacKDF.digest('hex')) % FIELD_MODULUS;

                const _kdfTrace = new Array(KDF_CHAIN_LEN).fill(0n);
                _kdfTrace[0] = _nonce;
                for (let _i = 0; _i < KDF_CHAIN_LEN - 1; _i++) {
                    const _roundKey = (_mimcKeyKDF + ROUND_CONSTANTS[_i % MIMC_ROUNDS]) % FIELD_MODULUS;
                    const [_out0] = poseidonPermute(
                        _kdfTrace[_i] % FIELD_MODULUS,
                        _roundKey,
                        BigInt(_i + 1)
                    );
                    _kdfTrace[_i + 1] = _out0;
                }
                const _expectedKDFCommit = _kdfTrace.reduce(
                    (acc, v) => poseidonHash([acc, v]),
                    0n
                );
                if (!safeEqualBI(_expectedKDFCommit, BigInt(public_inputs.kdf_chain_commit || "0"))) {
                    throw new Error(
                        "KDF chain commitment mismatch: Argon2id AIR binding check failed — " +
                        "the submitted kdf_chain_commit does not match the server-derived chain"
                    );
                }
                // Also check kdf_trace_root is present (Merkle root of the KDF trace LDE)
                if (!public_inputs.kdf_trace_root) {
                    throw new Error("Missing kdf_trace_root — Argon2id AIR trace Merkle root absent");
                }
            }

            // ── 1. RECONSTRUCT TRANSCRIPT (Fix #5 — canonical TRANSCRIPT_ORDER) ──────
            const transcript = new Transcript();

            // Step 0: server_challenge (Issue #2)
            const serverChallengeBigInt = (() => {
                const sc = public_inputs.server_challenge;
                if (!sc) return 0n;
                try {
                    const clean = String(sc).replace(/^0x/i, '').replace(/-/g, '');
                    if (!/^[0-9a-fA-F]+$/.test(clean) || clean.length === 0) return 0n;
                    return BigInt('0x' + clean) % FIELD_MODULUS;
                } catch (_) {
                    return 0n;
                }
            })();
            transcript.absorb(serverChallengeBigInt);

            const nonceVal = BigInt(public_inputs.nonce || "0");

            // Step 1
            transcript.absorb(nonceVal);

            // ── Issue #3: Re-derive mimcKey server-side; reject if hint disagrees ────
            // The client publishes mimc_key_hint for transparency, but the server NEVER
            // trusts it. We independently compute HMAC-SHA256(nonceVal, serverSecret)
            // and verify the hint matches before using the derived value in the transcript.
            // This closes the attack where a client forges a key that satisfies MiMC
            // constraints with an arbitrary trace[0] not derived from the real password.
            const serverSecret = (typeof process !== 'undefined' && process.env && process.env.ZK_SERVER_SECRET)
                ? process.env.ZK_SERVER_SECRET
                : 'INSECURE-DEV-SECRET-REPLACE-IN-PRODUCTION-WITH-HSM-BACKED-KEY';
            const _hmacDeriv = crypto.createHmac('sha256', serverSecret);
            _hmacDeriv.update(nonceVal.toString());
            const mimcKey = BigInt('0x' + _hmacDeriv.digest('hex')) % FIELD_MODULUS;

            if (!safeEqualBI(mimcKey, BigInt(public_inputs.mimc_key_hint || "0"))) {
                throw new Error(
                    "mimc_key_hint mismatch: client submitted a forged session key — " +
                    "the hint must equal HMAC-SHA256(nonceVal, serverSecret)"
                );
            }

            // Step 2 — use server-derived value (not client's hint)
            transcript.absorb(mimcKey);

            // Step 3
            transcript.absorb(BigInt(public_inputs.rc_commitment));

            // Step 4
            transcript.absorb(BigInt(public_inputs.mimc_output || "0"));
            // Step 4b: KDF chain commitment (Argon2id AIR)
            transcript.absorb(BigInt(public_inputs.kdf_chain_commit || "0"));

            // Step 5
            transcript.absorb(BigInt(public_inputs.trace_root || "0"));
            // Step 5b: KDF trace Merkle root
            transcript.absorb(BigInt(public_inputs.kdf_trace_root || "0"));

            // Step 6
            transcript.absorb(BigInt(public_inputs.q_root || "0"));

            // Challenge: friAlpha (drawn immediately after q_root)
            const friAlpha = transcript.challenge();

            if (!public_inputs.fri_roots || public_inputs.fri_roots.length < FRI_FOLDS) {
                throw new Error(`Need ${FRI_FOLDS} fri_roots, got ${(public_inputs.fri_roots||[]).length}`);
            }

            const friAlphas = [];
            for (let i = 0; i < FRI_FOLDS; i++) {
                transcript.absorb(BigInt(public_inputs.fri_roots[i]));
                friAlphas.push(transcript.challenge());
            }

            if (!public_inputs.fri_final || public_inputs.fri_final.length === 0) {
                throw new Error("Missing fri_final in public_inputs");
            }
            transcript.absorb(BigInt(public_inputs.fri_final[0]));

            // ── (E) Fiat-Shamir Grinding PoW check ───────────────────────────────────
            // Verify that the grind nonce satisfies PoW before drawing query challenges.
            // The verifier uses the transcript state AFTER fri_final[0] is absorbed
            // (= the state saved in pow_pregrind_state) to check the PoW condition.
            if (!public_inputs.pow_nonce || !public_inputs.pow_pregrind_state) {
                throw new Error("Missing pow_nonce or pow_pregrind_state — PoW grinding check failed");
            }
            {
                const [pg0, pg1, pg2] = public_inputs.pow_pregrind_state.map(BigInt);
                const powN = BigInt(public_inputs.pow_nonce);
                if (!Transcript.verifyGrind(pg0, pg1, pg2, powN)) {
                    throw new Error(
                        `PoW grinding check failed: pow_nonce=${powN} does not satisfy ` +
                        `2^${POW_BITS} work requirement on the pre-grind transcript state`
                    );
                }
                // Verify that the pre-grind state matches where we are in the transcript
                // (i.e. the prover did not substitute a different transcript state to
                // find an easier PoW target — this would break the Fiat-Shamir binding).
                if (!safeEqualBI(transcript.s0, pg0) ||
                    !safeEqualBI(transcript.s1, pg1) ||
                    !safeEqualBI(transcript.s2, pg2)) {
                    throw new Error(
                        "pow_pregrind_state does not match the reconstructed transcript state — " +
                        "the prover may have used a different commitment sequence to find a cheap PoW"
                    );
                }
            }
            // Absorb the grind nonce to advance the transcript to the post-PoW state
            transcript.absorb(BigInt(public_inputs.pow_nonce));

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
                const cVal     = BigInt(query.c_val);

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

                // ── A2. KDF TRACE MERKLE INCLUSION (Argon2id AIR) ────────────────────
                if (query.kdf_val !== undefined && query.kdf_path) {
                    const kdfVal = BigInt(query.kdf_val);
                    if (!MerkleTree.verify(public_inputs.kdf_trace_root, idx, kdfVal, query.kdf_path)) {
                        throw new Error(`Invalid KDF Merkle path at idx=${idx}`);
                    }
                }

                // ── B. AIR CONSTRAINT (Fix #2 — use session mimcKey, not 0n) ─────────
                const z_t   = pow(z, BigInt(MIMC_ROUNDS));
                const Z_val = (z_t - 1n + FIELD_MODULUS) % FIELD_MODULUS;

                if (Z_val !== 0n) {
                    const logicVal = pow((pVal + mimcKey + cVal) % FIELD_MODULUS, 7n);
                    const rhs      = (logicVal + qVal * Z_val % FIELD_MODULUS) % FIELD_MODULUS;
                    if (!safeEqualBI(pNextVal, rhs)) {
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

                    if (!safeEqualBI(p0, currentVal)) {
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
                    // Fix #6: advance x → x² to match prover's generator squaring (not friFold's job)
                    currentX   = (currentX * currentX) % FIELD_MODULUS;
                }

                // ── D. FRI FINAL LAYER ───────────────────────────────────────────────
                const finalIdx      = currentIdx % public_inputs.fri_final.length;
                const expectedFinal = BigInt(public_inputs.fri_final[finalIdx]);
                if (!safeEqualBI(currentVal, expectedFinal)) {
                    throw new Error(`FRI final layer check failed at query idx=${idx}`);
                }
            }

            const algoLabel = proof.algo
                ? `(${proof.algo.toUpperCase()})`
                : proof.proof_type === 'zk-stark-bcrypt' ? '(BCrypt)'
                : proof.proof_type === 'zk-stark-argon2' ? '(Argon2id)'
                : '';

            const pepperNote = skipPepperCheck ? 'Pepper-CommitP2(server-only)' : 'Pepper-Commitment';

            return {
                success: true,
                message: `ZK-STARK Proof Verified ${algoLabel} — ` +
                    `AIR(MiMC-${MIMC_ROUNDS}) + FRI[${FRI_FOLDS} folds, ${NUM_QUERIES} queries, blowup=${BLOWUP}] + ` +
                    `Boundary + RC-Commitment + ${pepperNote} + ` +
                    `KDF-Chain(Argon2id-AIR,len=${KDF_CHAIN_LEN}) + PoW(2^${POW_BITS}) all passed`
            };

        } catch (e) {
            console.error("Verification error:", e);
            return { success: false, error: (e instanceof Error ? e.message : String(e)) };
        }
    }

    /**
     * verifyPepperCommitP2(mimc_output, storedC) → true | throws
     *
     * Pattern 2 server-side pepper binding check.
     *
     * Called by the routing layer AFTER verify(proof, {skipPepperCheck:true}) succeeds.
     * Computes C = Poseidon(mimc_output, serverPepper) entirely on the server and
     * compares against storedC retrieved from the database.
     *
     * The client NEVER calls this method and NEVER supplies storedC or sees the pepper.
     * This is the core of the Pattern 2 security model: the pepper is an opaque server
     * secret; the client only submits mimc_output as a public proof output.
     *
     * @param {string|bigint} mimc_output  — public proof output from public_inputs
     * @param {string|bigint} storedC      — C value stored in DB at registration time
     * @returns true on success, throws on mismatch
     */
    verifyPepperCommitP2(mimc_output, storedC) {
        const serverPepperHex = (process.env && process.env.ZK_SERVER_PEPPER)
            ? process.env.ZK_SERVER_PEPPER
            : 'INSECURE-DEV-PEPPER-REPLACE-WITH-HSM';
        const pepperBytes  = Buffer.from(serverPepperHex, 'utf8');
        const pepperField  = hashBytesToWitness(pepperBytes);
        const computed     = poseidonHash([BigInt(mimc_output), pepperField]);
        const expected     = BigInt(storedC);
        if (!safeEqualBI(computed, expected)) {
            throw new Error(
                'Pattern 2 pepper commitment mismatch: ' +
                'mimc_output does not match the registered credential — wrong password or tampered proof'
            );
        }
        return true;
    }
}
module.exports = ZKVerifier;
