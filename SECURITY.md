# Security notes

This is research code. It has not had an independent audit, and it should not protect real accounts.

## Claim being proved

For a fixed program hash `P`, independently registered credential `C`, expected algorithm parameters, salt `S`, and one-time challenge `N`, an accepted Miden proof establishes that the selected program executed successfully with some private password witness and returned `[1]`.

The three programs constrain:

- **Argon2id:** `Argon2id_v19(password,S,m,t,p,tagLength=32)` is computed in the trace. `C` is a domain-separated Poseidon2 commitment to every tag byte, salt byte, and parameter.
- **bcrypt 2b:** the NUL-terminated password, EksBlowfish expansion, `2^cost` alternating key/salt expansions, and final 64 encryptions of `OrpheanBeholderScryDoubt` are computed in the trace. `C` binds the standard 23 output bytes, salt, and cost. All 1,042 Blowfish P/S words are range-checked advice and must match a separate in-circuit Poseidon2 commitment to the standard tables.
- **MiMC-7:** a domain-separated Poseidon2 absorption binds password length, all 64 padded password-byte slots, and salt; all 220 MiMC-7 rounds then execute in the trace. `C` binds the MiMC output, salt, password length, and round count.

The verifier pins the algorithm-specific MASP program hash, requires output `[1]`, and compares the envelope with an independent expected statement before decoding or verifying the STARK. The untrusted envelope cannot select its own program, credential, challenge, salt, parameters, output, or format.

## Encoding and binding defenses

- Password and salt witness values are range-checked as bytes inside each circuit.
- Password length is constrained to 1–64; bcrypt adds its required NUL terminator inside the circuit.
- Salt is exactly 16 bytes and uses strict even-length hexadecimal parsing.
- Credential limbs are checked as canonical Goldilocks field elements before public-stack construction.
- Domain tags and explicit lengths prevent cross-protocol and concatenation ambiguity.
- Every digest and salt byte occupies its own field element rather than an ambiguous packed representation.
- Algorithm, exact parameters, format, credential, challenge, salt, program hash, and output are checked independently.
- The Miden `ExecutionProof` decoder and verifier fail closed on malformed Base64 or proof bytes.
- Proof envelopes contain no password field or password bytes.
- Native proof JSON is parsed in the browser without routing 64-bit fields through lossy IEEE-754 `Number` values.

## Replay protection

The STARK example's four-word challenge is a 128-bit application nonce. The relying party must generate it uniformly, tie it to a session/statement, and mark it spent after successful verification. It is not a password salt and it is not one of the STARK's internal Fiat–Shamir challenges. Reusing it permits proof replay. The published STARK example uses a fixed statement for local verification and is not a live login endpoint.

## Interactive Argon2id + Schnorr demo

The home page's live flow is a separate password-derived signing-key protocol. Browser Argon2id uses 32 MiB, 3 passes, one lane, a fresh 16-byte salt and a 32-byte output. Domain-separated HKDF-SHA256 expands the output to 48 bytes, which are reduced to a nonzero secp256k1 scalar. The server receives a BIP340 public key, salt and fixed settings at registration; at login it receives only an account identifier, challenge identifier and 64-byte Schnorr signature. The message binds the protocol identifier, account, challenge identifier and a server-issued random 256-bit challenge. The server computes this message independently and verifies against its stored public key using `@noble/curves`.

Challenges expire after two minutes and are consumed atomically before verification, including failed attempts. Accounts expire after 30 minutes. Accounts and pending challenges exist only in bounded process memory; the Cloud Run demo is limited to one instance, and restarts discard all records. There are no durable accounts or login sessions. Strict request schemas reject additional fields; request bodies, hashes, keys and passwords are never logged by the application. Responses return public storage data and received field names so visitors can inspect the actual behavior.

A Schnorr signature proves possession of the derived signing key, not execution of Argon2id or adherence to the settings. A client holding that key can authenticate without the original password. This is not a full STARK and does not inherit the Miden circuit's computation guarantees. A leaked public key supports offline password guessing, and the demonstration has not been audited. The local hash is available for explicit display in the browser only; browser compromise or developer tools can expose local secrets. Use throwaway passwords.

## Security level and performance

The installed Miden 0.25.8 proof options used here report 96-bit conjectured security. The UI no longer offers the earlier “128-bit proof security” wording or a fake low-security prover switch. The **128-bit challenge** describes nonce entropy only; it is not the STARK security level.

Lowering FRI query/security parameters would not solve the dominant Argon2id/bcrypt memory problem: this generic prover first materializes the padded VM execution matrices. The observed minimum Argon2id allocation is about 102 GiB before normal overhead, and bcrypt cost 4 pads to `2^29` rows (~1.6 TiB by the same measured ratio).

## Testing performed

- Argon2id differential equivalence with RustCrypto over named edge cases and a deterministic 64-case parameter/password matrix.
- 64-bit add, rotate, XOR, and BlaMka equivalence over boundaries and 4,096 deterministic pseudorandom pairs.
- bcrypt differential vectors against RustCrypto, including embedded zero bytes and multiple password lengths.
- Full Miden executions for all three circuits, with measured cycle lower bounds that would fail if the expensive hash path were bypassed.
- A real MiMC STARK generated natively, accepted at security level 96, imported/accepted in browser Wasm, and rejected after a one-bit mutation.
- Independent mismatch tests for credential, challenge, salt, parameters, program hash, output, format, and algorithm.
- Cross-algorithm rejection, malformed inputs/proofs, noncanonical fields, incorrect prover-supplied credentials, and witness-leakage schema checks.
- Browser checks for Wasm startup, all program hashes/credentials, resource warnings, disabled unsafe proving controls, native command/download, proof import, verification, and tamper rejection with no console errors.

Commands to rerun these checks are in the README under **Testing**.

## Residual risks and non-claims

- No Argon2id or bcrypt STARK has been produced yet; the generic prover needs more memory than a 128 GiB machine has. Their complete VM executions pass, but valid-proof mutation coverage exists only for MiMC until a sufficiently large or specialized prover is used.
- Browser MiMC proving also did not complete: Chromium reached approximately 4.0 GiB and stalled at the wasm32 address-space ceiling. Use the native prover and browser verifier.
- MiMC is circuit-friendly but not memory-hard and must not replace Argon2id/bcrypt as a production password-storage KDF.
- bcrypt cost 4 is demonstration-only and far below a contemporary password-storage work factor.
- Miden VM and the Rust-to-Miden compiler are experimental dependencies, and this code has not received an independent cryptographic audit.
- Zero-knowledge (that a proof reveals nothing about the password) has not been confirmed for the Miden version and proof options used here. Treat proofs as proofs of correct computation until that is checked.
- A leaked database exposes the stored commitments to offline guessing, exactly like a leaked password-hash table. MiMC-7 is fast, so MiMC commitments are cheap to attack.
- Circuit execution is not constant-time at the VM trace level. Argon2id intentionally uses data-dependent addressing after the first half of pass zero; deployment timing/resource side channels need separate analysis.
- The browser holds the plaintext in the DOM/Wasm memory while working. It is absent from proof JSON, but XSS, browser extensions, memory snapshots, and a compromised origin remain threats.
- The Argon2id profile omits optional secret-key and associated-data inputs and bounds passwords to 64 bytes, salts/tags to 16/32 bytes, and lanes to 1–4.
- A production relying party must store expected credentials/parameters, issue and consume challenges atomically, serve a restrictive CSP with no third-party scripts, pin artifacts, and arrange an external audit.
