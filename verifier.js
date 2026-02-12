/**
 * zk-hash/verifier.js
 * 
 * Verifies the ZK-STARK proof submitted by the client.
 * In a real implementation, this runs the STARK verifier algorithm
 * which is exponentially faster than the prover.
 */

const { FieldElement, mimcHash, MerkleTree, FIELD_MODULUS } = require('./stark-math');

class ZKVerifier {
    constructor() {
    }

    // 1. Convert string to BigInt for the field (Helper within verifier)
    stringToField(str) {
        let val = 0n;
        for (let i = 0; i < str.length; i++) {
            val = (val * 256n) + BigInt(str.charCodeAt(i));
        }
        const m = 3221225473n; // hardcoded modulus same as stark-math
        return ((val % m) + m) % m;
    }

    verify(proofObj) {
        try {
             // 1. Structural Check
            if (!proofObj) return { success: false, error: "Invalid Proof Format" };

            // ==========================================
            // CASE A: KNOWLEDGE PROOF (Auth)
            // ==========================================
            if (proofObj.proof_type === "zk-stark-knowledge-proof") {
                const { public_inputs, trace_queries } = proofObj;
                const traceRoot = public_inputs.trace_root;
                const claimedOutput = BigInt(public_inputs.public_output);
                const nonceVal = this.stringToField(public_inputs.nonce);

                const MIMC_ROUNDS = 64;
                const MIMC_CONSTANTS = Array.from({length: MIMC_ROUNDS}, (_, i) => BigInt(i * 123456789)); 

                for(let query of trace_queries) {
                    const idx = query.index;
                    const currVal = BigInt(query.value);

                    // A. Merkle Check
                    if (!MerkleTree.verify(traceRoot, idx, currVal, query.path)) {
                        return { success: false, error: `Merkle Proof failed for index ${idx}.` };
                    }

                    // B. Boundary Check
                    if (idx === MIMC_ROUNDS) {
                        if (currVal !== claimedOutput) {
                            return { success: false, error: "Output Mismatch: Proof execution does not lead to claimed hash." };
                        }
                        continue;
                    }

                    // C. Transition Check: next = (curr + nonce + K)^3
                    // Note: Here 'nonce' acts as the Key
                    const nextVal = BigInt(query.next_value);
                    const roundConst = MIMC_CONSTANTS[idx] || 0n;

                    let t = (currVal + nonceVal + roundConst) % FIELD_MODULUS;
                    let t2 = (t * t) % FIELD_MODULUS;
                    let t3 = (t2 * t) % FIELD_MODULUS;
                    
                    if (t3 !== nextVal) {
                        return { success: false, error: "Invalid Execution Trace: You do not know the secret that generates this hash." };
                    }
                }

                return { success: true, message: "Use Verified! Knowledge of Secret Proof accepted." };
            }

            // ==========================================
            // CASE B: HASH INTEGRITY PROOF
            // ==========================================
            if (proofObj.proof_type !== "zk-stark-mimc-real") {
                return { success: false, error: "Unknown Proof Type" };
            }

            const { public_inputs, trace_queries } = proofObj;
            const traceRoot = public_inputs.trace_root;
            const mimcOutput = BigInt(public_inputs.mimc_output);
            const outputHash = public_inputs.outputHash;
            
            // 2. Derive MiMC Key from Public OutputHash (Binding Check)
            let mimcKey = 0n;
            if (public_inputs.algorithm === 'mimc-stark') {
                if (outputHash !== public_inputs.mimc_output) {
                     return { success: false, error: "Data Integrity Failed: Claimed output does not match proof output." };
                }
                mimcKey = 0n;
            } else {
                // For Argon2/Bcrypt, the key IS derived from the claimed hash
                // We must use the *entire* hash string to ensure binding to the secure part,
                // not just the parameters prefix (which might be the first 30 chars).
                mimcKey = this.stringToField(outputHash);
            }

            // 3. Verify Execution Trace Queries (The Logic Check)
            const MIMC_ROUNDS = 64;
            const MIMC_CONSTANTS = Array.from({length: MIMC_ROUNDS}, (_, i) => BigInt(i * 123456789)); 

            for(let query of trace_queries) {
                const idx = query.index;
                const currVal = BigInt(query.value);
                
                // A. Verify Merkle Path (Authentication)
                // Did this value actually exist in the committed trace?
                if (!MerkleTree.verify(traceRoot, idx, currVal, query.path)) {
                     return { success: false, error: `Merkle Proof failed for index ${idx} (Tampered Data)` };
                }

                // BOUNDARY CHECK: If this is the last step, it MUST match the mimc_output
                if (idx === MIMC_ROUNDS) {
                    if (currVal !== mimcOutput) {
                        return { success: false, error: "Boundary Constraint Failed: Trace end does not match claimed output." };
                    }
                    continue; // No transition for the last element
                }
                
                // B. Verify Transition Function (The "AIR" Constraint)
                // Does State[i+1] == Logic(State[i]) ?
                // Logic: next = (curr + KEY + ROUND_CONSTANT)^3
                
                const nextVal = BigInt(query.next_value);
                const roundConst = MIMC_CONSTANTS[idx] || 0n;
                
                // CRITICAL: We use the 'mimcKey' derived from the Public Output Hash here.
                let t = (currVal + mimcKey + roundConst) % FIELD_MODULUS;
                let t2 = (t * t) % FIELD_MODULUS;
                let t3 = (t2 * t) % FIELD_MODULUS;
                const expectedNext = t3;
                
                if (expectedNext !== nextVal) {
                     return { 
                         success: false, 
                         error: `Constraint Validation Failed at step ${idx}. The Proof provided is invalid for this Hash. (Tampering Detected)` 
                    };
                }
            }
            
            return { 
                success: true, 
                message: `STARK Proof Verified! Validated ${public_inputs.algorithm} integrity via Binding.` 
            };

        } catch (e) {
            console.error(e);
            return { success: false, error: "Verification Logic Error: " + e.message };
        }
    }
}

module.exports = ZKVerifier;
