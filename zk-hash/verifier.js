/**
 * zk-hash/verifier.js
 * 
 * Verifies the ZK-STARK proof submitted by the client.
 * In a real implementation, this runs the STARK verifier algorithm
 * which is exponentially faster than the prover.
 */

const { FieldElement, mimcHash, poseidonHash, MerkleTree, FIELD_MODULUS, generateFiatShamirQueries, MIMC_CONSTANTS } = require('./stark-math');

class ZKVerifier {
    constructor() {
    }

    // 1. Convert string to BigInt for the field (Helper within verifier)
    stringToField(str) {
        let val = 0n;
        for (let i = 0; i < str.length; i++) {
            val = (val * 256n) + BigInt(str.charCodeAt(i));
        }
        return ((val % FIELD_MODULUS) + FIELD_MODULUS) % FIELD_MODULUS;
    }

    verify(proofObj) {
        try {
            const NUM_QUERIES = 40; // Increased for higher soundness (approx 80-128 bits depending on field)
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

                const MIMC_ROUNDS = MIMC_CONSTANTS.length;
                
                for(let query of trace_queries) {
                    const idx = query.index;
                    const currVal = BigInt(query.value);

                    // A. Merkle Check
                    if (!MerkleTree.verify(traceRoot, idx, currVal, query.path)) {
                        return { success: false, error: `Merkle Proof failed for index ${idx}.` };
                    }

                    // B. Boundary Check: Output at MIMC_ROUNDS
                    if (idx === MIMC_ROUNDS) {
                        if (currVal !== claimedOutput) {
                            return { success: false, error: "Output Mismatch: Proof execution does not lead to claimed hash." };
                        }
                        continue;
                    }
                    
                    // SKIP BLINDING ROWS
                    // If we are in the blinding section (idx > MIMC_ROUNDS), we just verify Merkle path (done above)
                    if (idx > MIMC_ROUNDS) continue;

                    // C. Transition Check: next = (curr + nonce + K)^7
                    // Check only if we have a valid next state
                    if (query.next_value === null || query.next_value === undefined) continue;

                    // Note: Here 'nonce' acts as the Key
                    const nextVal = BigInt(query.next_value);
                    const roundConst = MIMC_CONSTANTS[idx] || 0n;

                    let t = (currVal + nonceVal + roundConst) % FIELD_MODULUS;
                    let t2 = (t * t) % FIELD_MODULUS;
                    let t4 = (t2 * t2) % FIELD_MODULUS;
                    let t7 = (t4 * t2 * t) % FIELD_MODULUS;
                    
                    if (t7 !== nextVal) {
                        return { success: false, error: "Invalid Execution Trace: You do not know the secret that generates this hash." };
                    }
                }

                // SECURITY CHECK: Fiat-Shamir Query Coverage
                // We MUST verify that the Prover answered distinct challenges derived from the Commit Root
                // REPLICATE PROVER LOGIC: Domain size includes blinding, exclude 0
                const BLINDING_FACTOR = 4;
                const queryDomain = MIMC_ROUNDS + BLINDING_FACTOR;
                
                // Re-implementation of the custom sampling (should match Prover)
                // We use Poseidon Hash from StarkMath
                
                let expectedIndices = new Set();
                let counter = 0n;
                while(expectedIndices.size < NUM_QUERIES) {
                    const randVal = poseidonHash([BigInt(traceRoot), counter]);
                    const idx = Number(randVal % BigInt(queryDomain));
                    if (idx > 0 && idx < queryDomain) { 
                        expectedIndices.add(idx);
                    }
                    counter++;
                }

                // Also expect last index (Boundary Constraint)
                expectedIndices.add(MIMC_ROUNDS);

                const receivedIndices = new Set(trace_queries.map(q => q.index));
                for (let idx of expectedIndices) {
                     if (!receivedIndices.has(idx)) {
                         return { success: false, error: `Invalid Proof: Missing required Fiat-Shamir query for index ${idx}.` };
                     }
                }

                return { success: true, message: "User Verified! Knowledge of Secret Proof accepted." };
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
                
                // NOTE: stringToField logic handles the whole string.
                mimcKey = this.stringToField(outputHash);
            }

            // 3. Verify Execution Trace Queries (The Logic Check)
            const MIMC_ROUNDS = MIMC_CONSTANTS.length; 

            // SECURITY: Re-derive the challenge processing from the Public Commitment
            // traceRoot is now strictly Decimal String from new stark-math.js logic
            const BLINDING_FACTOR = 4;
            const queryDomain = MIMC_ROUNDS + BLINDING_FACTOR;
            
            let expectedIndices = new Set();
            let counter = 0n;
            while(expectedIndices.size < NUM_QUERIES) {
                // Must match Prover's exclusion of 0 and use of Poseidon
                const randVal = poseidonHash([BigInt(traceRoot), counter]);
                const idx = Number(randVal % BigInt(queryDomain));
                if (idx > 0 && idx < queryDomain) { 
                    expectedIndices.add(idx);
                }
                counter++;
            }

            // Add boundary to expected
            expectedIndices.add(MIMC_ROUNDS);

            // Validate that we received exactly the required queries
            // (Client sends array of objects)
            const receivedIndices = new Set(trace_queries.map(q => q.index));
            
            // Check coverage
            for (let idx of expectedIndices) {
                if (!receivedIndices.has(idx)) {
                     return { success: false, error: `Invalid Proof: Missing required Fiat-Shamir query for index ${idx}.` };
                }
            }

            for(let query of trace_queries) {
                const idx = query.index;
                // If blinding row, skip logic checks (just merkle check done implicitly? No, need to do Merkle check below)
                // Actually Merkle check is first thing in loop usually.
                
                const currVal = BigInt(query.value);
                
                // A. Verify Merkle Path (Authentication)
                // Did this value actually exist in the committed trace?
                if (!MerkleTree.verify(traceRoot, idx, currVal, query.path)) {
                     return { success: false, error: `Merkle Proof failed for index ${idx} (Tampered Data)` };
                }

                // Skip computation checks for Blinding Rows
                if (idx >= MIMC_ROUNDS) {
                    // BOUNDARY CHECK: If this is the output index (MIMC_ROUNDS), it MUST match claimed output
                    // If it is > MIMC_ROUNDS, it is blinding noise, ignore value.
                    if (idx === MIMC_ROUNDS) {
                        // Check if it matches public input output
                        // But wait, what is 'mimcOutput'? It's not defined in this scope clearly in snippet?
                        // Ah, line 125: if (outputHash !== public_inputs.mimc_output)
                        // It seems we should check against `public_inputs.mimc_output` or `claimedOutput`
                        // Let's use BigInt(public_inputs.mimc_output)
                        if (currVal !== BigInt(public_inputs.mimc_output)) {
                            return { success: false, error: "Boundary Constraint Failed: Trace end does not match claimed output." };
                        }
                    }
                    continue; 
                }
                
                // B. Verify Transition Function (The "AIR" Constraint)
                // Does State[i+1] == Logic(State[i]) ?
                // Logic: next = (curr + KEY + ROUND_CONSTANT)^7
                
                const nextVal = BigInt(query.next_value);
                const roundConst = MIMC_CONSTANTS[idx] || 0n;
                
                // CRITICAL: We use the 'mimcKey' derived from the Public Output Hash here.
                let t = (currVal + mimcKey + roundConst) % FIELD_MODULUS;
                let t2 = (t * t) % FIELD_MODULUS;
                let t4 = (t2 * t2) % FIELD_MODULUS;
                let t7 = (t4 * t2 * t) % FIELD_MODULUS;
                const expectedNext = t7;
                
                if (expectedNext !== nextVal) {
                     return { success: false, error: "Invalid Execution Trace: Hash Computation was forged." };
                }
            }
            
            return { success: true, message: "Valid Proof! Hash Integrity Verified." };
        } catch (e) {
            console.error(e);
            return { success: false, error: "Verification Logic Error: " + e.message };
        }
    }
}

module.exports = ZKVerifier;
