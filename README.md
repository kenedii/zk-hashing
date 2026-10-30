# zk-hashing

Zero-knowledge-style password authentication. The client computes the full password hash
(Argon2id, bcrypt, or MiMC-7) **inside a Miden VM STARK**. The server checks the proof
against a stored credential and never receives the password, the hash output, or anything
password-equivalent.

The system works as an expensive login: proving costs a lot, verifying is cheap.

- **MiMC-7** is proven and verified end to end today. Proving takes about 40 s natively, and
  the browser verifies the result locally.
- **Argon2id and bcrypt** run fully in the VM and are pinned by the verifier. Their proofs
  need far more memory than the MiMC proof: about 102 GiB for the smallest Argon2id setting
  and about 1.6 TiB for bcrypt cost 4 with the generic Miden prover. Neither proof has been
  generated yet.

> This is research software. It has not been independently audited and must not protect
> real accounts yet. See [Security model](#security-model).

## How it works

```
 relying party (server)                         prover (client)
 ──────────────────────                         ───────────────
 stores C, salt, params        ──challenge N──▶  password (private, never sent)
                                                 run Miden program P:
                                                   tag = KDF(password, salt, params)   ← in the trace
                                                   assert Poseidon2(tag, salt, params) == C
                                                   return 1
 verify(P, C, N, salt, params, proof)  ◀─proof──
   P pinned · C/N/salt/params from server state · output must be [1] · ≥96-bit
```

- **Statement:** for a fixed program hash `P`, the prover knows a password witness such that
  the selected KDF, run with the stored salt and parameters, gives a tag whose domain-separated
  Poseidon2 commitment equals the registered credential `C`.
- **Public inputs:** `C`, which is four Goldilocks field elements sent as eight 32-bit limbs,
  and a 128-bit one-time challenge `N`. The STARK statement binds both, so a proof made for
  one challenge fails for any other.
- **Private advice:** the password (1–64 bytes, range-checked as bytes in the circuit) and the
  salt. Every parameter is committed inside `C`.
- **The verifier fails closed.** It takes the program, credential, challenge, salt, parameters
  and format from trusted server state, never from the proof envelope. It also rejects
  cross-algorithm envelopes, non-canonical fields, malformed proofs, and security levels
  below 96 bits.

### Circuits

| Circuit | What runs in the trace | Cycles | Trace | Proof |
| --- | --- | --- | --- | --- |
| Argon2id v1.3 (RFC 9106), `m=8 KiB, t=1, p=1` | Blake2b, H′, 1 KiB blocks, BlaMka, data-independent and data-dependent addressing, passes, slices, 1–4 lanes | 19,593,971 | 2^25 | Needs about 102 GiB plus overhead |
| bcrypt 2b, cost 4 | Full EksBlowfish key schedule, 2^cost expansions, 64 final encryptions; P/S tables committed and checked in the circuit | 367,224,034 | 2^29 | Needs about 1.6 TiB |
| MiMC-7, 220 rounds | Domain-separated Poseidon2 absorption of password and salt, then all 220 rounds | 430,204 | 2^19 | **Done:** 39 s natively, 172,647-byte envelope, verifies at 96-bit security |

Correctness evidence:

- The Argon2id circuit logic matches RustCrypto `argon2` 0.5.3 on named vectors plus more than
  460 deterministic and randomized cases. These cover 1–4 lanes, 1–4 passes, memory rounding,
  passwords 1–64 bytes and embedded NULs.
- The bcrypt circuit logic matches RustCrypto `bcrypt` 0.19.2 on fixed and randomized vectors.
- All three programs run completely in the Miden VM. Cycle-count lower bounds in the tests
  catch any regression in which the hash is computed on the host instead of in the circuit.
- A real MiMC proof is accepted natively and in browser Wasm. A one-bit mutation and a wrong
  challenge are both rejected.

## Repository layout

```
argon2id-zk-stark/
  circuit/           Argon2id Miden circuit (Rust → Wasm → MASM/MASP)
  bcrypt-circuit/    bcrypt 2b Miden circuit
  mimc-circuit/      MiMC-7 Miden circuit
  artifacts/         compiled, verifier-pinned .wasm/.masm/.masp programs
  runtime/           shared native/Wasm prover, strict verifier, proof envelopes, CLI
  web/               dependency-free local verifier page (imports native proofs)
  tests/             Argon2id reference tests, proof fixtures (valid + tampered), browser smoke test
frontend/, zk-hash/  toy web walkthrough deployed at zkhash.tensors.vip (see below)
```

## Quick start

The circuits are built with `nightly-2026-04-30`, Miden SDK `0.14.0-rc.1`, `midenc`
`0.10.0-rc.1`, and Miden VM `0.25.8`. The runtime builds with stable Rust 1.96.1 or later.

```sh
cd argon2id-zk-stark/runtime
cargo test --release --locked --test security     # bindings, full executions, fail-closed verifier

cd ../tests/circuit-reference
cargo test --release --locked                     # Argon2id vs RustCrypto
```

The CLI (`argon2id-zk-cli`) can be built from `runtime/`. A prebuilt Windows binary is
published on the GitHub Releases page.

```sh
argon2id-zk-cli program-hashes
argon2id-zk-cli credential-mimc hunter2 000102030405060708090a0b0c0d0e0f
argon2id-zk-cli prove-mimc hunter2 000102030405060708090a0b0c0d0e0f \
  305419896 2596069104 267242409 2271560481 --out proof.json
argon2id-zk-cli verify-file proof.json expected.json
```

`expected.json` must come from trusted server state, never from the proof envelope. See
`argon2id-zk-stark/tests/fixtures/mimc-expected.json`. JavaScript clients must keep the
64-bit fields as decimal strings or `BigInt`.

To verify in the browser locally, serve `argon2id-zk-stark/web/` over HTTP and import a
native proof. Browser *proving* is disabled because wasm32 reaches its 4 GiB limit before
the MiMC proof completes.

## Security model

**What an accepted proof establishes:** the pinned program ran successfully with *some*
password witness that produces the registered credential under the stored salt and
parameters, for this challenge.

**Integrator responsibilities:**
- Generate challenges uniformly at random, tie each one to a session, and mark it spent
  atomically. Reusing a challenge allows replay. The demo runtime has no challenge store.
- Store `C`, the salt and the parameters on the server.
- Pin the artifacts, serve a restrictive CSP, and get an external audit before real use.

**Known limitations and non-claims:**
- **Proofs are not formally zero-knowledge.** Miden VM 0.25.8 uses a non-hiding commitment
  scheme and does not mask the trace. Proof envelopes contain no password field, and the
  openings do not make guessing cheaper than the credential already does: either way an
  attacker must run the full KDF per guess. Still, "zero-knowledge" here means
  "password not transmitted", not the formal ZK property.
- `C` is a deterministic function of the password and salt. If `C` leaks, an attacker can
  guess passwords offline at the cost of the KDF, exactly as with a stored password hash.
  The demo parameters (Argon2id `m=8 KiB`, bcrypt cost 4) are far too weak for production.
- **MiMC-7 is not memory-hard** and its credential reduces the password to one ~64-bit
  field element before the rounds. It demonstrates a complete proof path; it is not a
  password-storage KDF.
- Argon2id and bcrypt proofs need a specialized AIR or an out-of-core/streaming prover to
  be practical. Only MiMC has valid-proof mutation tests so far.
- Execution in the circuit is not constant-time; Argon2id's data-dependent addressing is
  intentional. Plaintext passwords sit in client memory while proving.
- Miden VM and the Rust-to-Miden compiler are pre-1.0 dependencies.
- Profile limits: passwords up to 64 bytes, 16-byte salts, 32-byte Argon2id tags, 1–4
  lanes, no Argon2 secret key or associated data, bcrypt cost capped at 16.

## Web walkthrough (toy demo)

[zkhash.tensors.vip](https://zkhash.tensors.vip) hosts an interactive walkthrough of the
protocol flow: challenge issue, client-side Argon2id, proof submission, and the server-side
pepper check. **Its proof is a simplified JavaScript mock and is not sound.** The Argon2id
output is computed outside the proof and is effectively sent to the server, so a captured
request can be replayed. The mock's quotient and FRI layers illustrate a STARK's structure
without its soundness. Use it to understand the flow; the security properties above belong
only to the Miden implementation.

Running it locally:

```sh
cd frontend && npm install && npm start    # uses public development secrets by default
```

## License

No license has been granted yet; all rights reserved by the author.
