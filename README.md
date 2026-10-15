# zk-hashing

Password login by zero-knowledge proof. The browser runs a real password hash (Argon2id, bcrypt or MiMC-7) inside a STARK-provable virtual machine and proves that the result matches what the server stored. The server never receives the password, or a hash it could replay.

**Live site:** https://zkhash.ckenedi.vip. It is organized into *Info* pages (a plain-language introduction with an interactive zero-knowledge example, a technical description, results and a security analysis) and *Demos* (an in-browser verifier, a proof gallery with experiment data, a classical password-flow baseline and the circuit lab).

The home page also has an interactive **Argon2id + Schnorr password demo**. Register any throwaway password, enter it again, and the real Cloud Run server verifies a fresh Schnorr signature against the registered public key. The browser computes Argon2id locally (32 MiB, 3 passes, 1 lane), derives a signing key through domain-separated HKDF, and sends only the public key at registration and the signature at login. The page displays the exact network bodies and the server's actual stored record. A wrong password and a replay are rejected by the server.

This interactive proof establishes possession of the password-derived signing key. It does **not** prove that the client performed Argon2id or used the advertised settings. The full Miden STARK example and lab remain separate and continue to verify the hash computation. Demo accounts live in bounded server memory and expire after 30 minutes or a restart; Cloud Run uses one instance for this ephemeral demo.

> This is research code. It has not been audited and must not protect real accounts. See [SECURITY.md](SECURITY.md).

## The idea

Most password logins send the password to the server, which hashes and compares it. Hashing it in the browser instead doesn't help on its own, because the hash becomes the new password. zk-hashing replaces "send the secret" with "prove you know the secret":

1. **Register (browser).** Pick a random 16-byte salt, hash the password, and send a commitment `C` to the hash output, along with the salt and hash settings. The server stores `C`, the salt and the settings.
2. **Challenge (server).** At login, send a fresh, single-use 128-bit challenge.
3. **Prove (browser).** Run the full hash inside the [Miden VM](https://github.com/0xMiden/miden-vm), with the password as private input. Produce a STARK proof that the program output `[1]`, meaning the computed hash commits to `C`. The challenge is a public input, so the proof is tied to it.
4. **Verify (server).** Check the proof against the stored `C`, the challenge it issued, the expected settings and the hash of the exact compiled program. Then mark the challenge used.

The verifier only accepts the pinned compiled program, so a client can't substitute a cheaper computation. Every public value is compared against the server's own records, never against values taken from the proof envelope.

## Status

All three hashes run end to end inside the circuit, and each matches a reference implementation. Only MiMC-7 has been proved so far.

| Circuit | Computed in the circuit | VM cycles | Trace rows | Proof generation |
| --- | --- | ---: | ---: | --- |
| Argon2id v1.3 (`m=8 KiB, t=1, p=1`) | RFC 9106 in full: Blake2b, H′, 1 KiB blocks, BlaMka, hybrid addressing, passes, slices, lanes | 19,593,971 | 2²⁵ | Not completed on 128 GiB RAM. Largest allocation 102 GiB; peak estimated ~270 GiB |
| bcrypt 2b (cost 4) | Full EksBlowfish key schedule, 2^cost expansions, 64 encryptions of `OrpheanBeholderScryDoubt` | 367,224,034 | 2²⁹ | Estimated ~4 TiB peak |
| MiMC-7, native | Poseidon2 absorption of password and salt, then 220 MiMC-7 rounds | 430,204 | 2¹⁹ | Proved: 39 s on a workstation, 172 KB proof, 4.25 GiB peak RSS, verified at 96-bit security |
| MiMC-7, browser (wasm32) | Same program and prover in a Chromium tab | 430,204 | 2¹⁹ | Stalls at the 4 GiB wasm32 address-space ceiling |

**Measurements.** On a 2-vCPU Linux machine, MiMC-7 proving takes 88 s with the single-threaded prover and 50 s with Miden's `concurrent` feature. Native builds now enable that feature. Peak resident memory is 4.25 GiB in both cases, about 8.5 KB per padded trace row. The larger-circuit estimates scale that figure by trace length, so treat them as orders of magnitude.

**Browser proving.** Headless Chromium running the wasm32 bundle reaches about 4.0 GiB after roughly four minutes of CPU time, then stops making progress without producing a proof or an error. That matches the earlier Windows observation. The cause is that the prover's peak exceeds the 32-bit address space. A Memory64 (`wasm64`) build, supported in Chrome 133+ and Firefox 134+ with a 16 GiB JavaScript API limit, is the next step.

**Experiment log.** The site's *Experiment log* section publishes every proof file with a one-click verifier, the raw monitoring data (`web/data/`), and the analysis. An Argon2id `m=8 KiB` proof attempt on a 125.6 GiB workstation with a page file on a hard drive committed 218 GiB of memory. After the first few minutes it was almost entirely waiting on the disk: it used 31.6 CPU-minutes in 7 hours and produced no proof. A page file on disk is not a substitute for RAM for this workload.

**MiMC-7 is a protocol stand-in.** It's cheap to prove but not memory-hard, so it must not be used to store real passwords.

## Repository layout

```
circuits/
  argon2id/          Argon2id circuit (Rust, compiled to Miden assembly)
  bcrypt/            bcrypt 2b circuit, including EksBlowfish tables
  mimc/              MiMC-7 circuit
  reference-tests/   Argon2id differential tests against RustCrypto
artifacts/           Compiled circuits (.masp packages the verifier pins, .masm for review)
runtime/             Prover and verifier library, CLI, WebAssembly bindings, security tests
site-src/            Page sources: layout, pages and shared fragments (TeX rendered to MathML at build time)
scripts/             build-pages.mjs: builds the web/*.html pages from site-src/
web/
  *.html             Generated pages: overview, What is this?, How it works, Results, Security,
                     Future work, Verify, Experiments, Password flow (run `npm run build:pages`)
  lab/               Full lab: compute commitments for all three algorithms, verify proof files
  pkg/               The runtime compiled to WebAssembly (wasm-bindgen output)
  lib/               Lossless JSON parsing for 64-bit proof fields
  proofs/            Published proofs: a valid MiMC-7 proof, a tampered copy, the expected statement
tests/               JavaScript tests (JSON precision, browser end-to-end smoke test)
server/              Live password demo API and shared challenge-message definition
deploy/              Node container and Cloud Build config for Cloud Run
```

## Quick start

### Run the site locally

The HTML pages in `web/` are generated from `site-src/`. After editing a page or fragment, run `npm run build:pages`.

The interactive home page needs the included Node server:

```sh
npm ci
npm run build
npm start
```

Open http://localhost:8080/ for the password demo and overview, or http://localhost:8080/lab/ for the STARK lab. Run `npm test` for protocol and request-schema tests, and `npm run smoke` for browser checks (Edge on Windows by default; set `BROWSER_EXE` for another Chromium executable).

For the static STARK example and lab alone, serve `web/` over HTTP. The live password API is unavailable in this mode:

```sh
python web/server.py --directory web --port 4173
```

Open http://127.0.0.1:4173/ for the overview, or http://127.0.0.1:4173/lab/ for the full lab.

### Verify the published proof from the command line

Requires a stable Rust toolchain (edition 2024).

```sh
cd runtime
cargo run --release --bin argon2id-zk-cli -- verify-file ../web/proofs/mimc-proof.json ../web/proofs/mimc-expected.json
```

### Make your own proof

```sh
cd runtime
# MiMC-7: password, salt (hex), four 32-bit challenge words
cargo run --release --bin argon2id-zk-cli -- prove-mimc 'hunter2' 000102030405060708090a0b0c0d0e0f \
  305419896 2596069104 267242409 2271560481 --out proof.json

# Commitments for each algorithm
cargo run --release --bin argon2id-zk-cli -- credential hunter2 000102030405060708090a0b0c0d0e0f 8 1 1   # Argon2id m t p
cargo run --release --bin argon2id-zk-cli -- credential-bcrypt hunter2 000102030405060708090a0b0c0d0e0f 4 # bcrypt cost
cargo run --release --bin argon2id-zk-cli -- credential-mimc hunter2 000102030405060708090a0b0c0d0e0f

# Program hashes the verifier pins
cargo run --release --bin argon2id-zk-cli -- program-hashes
```

`prove` (Argon2id) and `prove-bcrypt` take the same shape of arguments. They run the complete circuits, but they need the memory listed in **Status**. `execute`, `execute-bcrypt` and `execute-mimc` run a circuit without proving it, which is how the cycle counts above were measured.

Prebuilt Windows binaries are attached to [GitHub releases](https://github.com/kenedii/zk-hashing/releases) when available.

The expected-statement file must come from the verifier's own records, never from the proof envelope:

```json
{
  "credential": [8370215289663149514, 8090811050392849221, 9444347110279816554, 1235188709954996380],
  "challenge": [305419896, 2596069104, 267242409, 2271560481],
  "saltHex": "000102030405060708090a0b0c0d0e0f",
  "params": { "algorithm": "mimc7", "parameters": { "rounds": 220 } }
}
```

JavaScript callers must keep commitment and program-hash fields as decimal strings or `BigInt`, because they exceed the range of exact IEEE-754 integers. `web/lib/envelope-json.js` handles this.

## Building from source

### Pinned components

| Component | Version |
| --- | --- |
| Circuit Rust toolchain | `nightly-2026-04-30` with `rust-src`, `llvm-tools`, target `wasm32-wasip1` (set per circuit in `rust-toolchain.toml`) |
| Miden SDK (circuits) | `0.14.0-rc.1` |
| Miden VM (runtime) | `0.25.8` |
| `midenc` / `cargo-miden` | `0.10.0-rc.1` |
| `wasm-bindgen` CLI | `0.2.127` |
| Reference implementations | RustCrypto `argon2` 0.5.3, `bcrypt` 0.19.2 |

### Circuits → `artifacts/`

Each circuit compiles to Wasm and then to a Miden package (`.masp`). For example, Argon2id:

```sh
export RUSTFLAGS='--cfg miden -Zunstable-options -Cpanic=immediate-abort'
cargo +nightly-2026-04-30 -Zbuild-std=core,alloc build --release \
  --target wasm32-wasip1 --manifest-path circuits/argon2id/Cargo.toml
midenc circuits/argon2id/target/wasm32-wasip1/release/argon2id_miden_circuit.wasm \
  --entrypoint argon2id_miden_circuit::entrypoint --optimize balanced --debug none
```

Do the same for `circuits/bcrypt` (`bcrypt_password_miden_circuit`) and `circuits/mimc` (`mimc_password_miden_circuit`). Then copy the `.masp` and `.masm` outputs into `artifacts/`. The runtime embeds the `.masp` files at compile time.

A changed program hash invalidates every existing commitment and proof. Treat it as a migration, not a cosmetic rebuild.

### Runtime → CLI and browser bundle

```sh
# Native CLI
cargo build --release --manifest-path runtime/Cargo.toml --bin argon2id-zk-cli

# Browser bundle
cargo build --release --manifest-path runtime/Cargo.toml --target wasm32-unknown-unknown --lib
wasm-bindgen runtime/target/wasm32-unknown-unknown/release/argon2id_zk_runtime.wasm \
  --target web --out-dir web/pkg
```

When you replace `web/pkg`, bump `bundleVersion` in `web/lab/app.js` and the query string in `web/lab/index.html` so browsers don't use a cached copy.

## Testing

```sh
# Runtime security suite: program hashes, full circuit executions, every binding check,
# cross-algorithm rejection, malformed inputs, password never present in the envelope
cargo test --release --manifest-path runtime/Cargo.toml --test security

# Argon2id circuit code vs RustCrypto (named edge cases + 64-case parameter matrix)
cargo test --release --manifest-path circuits/reference-tests/Cargo.toml

# bcrypt circuit code vs RustCrypto
cargo test --release --manifest-path circuits/bcrypt/Cargo.toml

# JSON precision for 64-bit fields
node tests/envelope-json.test.cjs

# Browser end-to-end against the lab page (serve web/ first). BROWSER_EXE points at any
# Chromium-based browser; it defaults to Edge on Windows.
cd tests && npm install && BROWSER_EXE=/path/to/chromium npm run smoke
```

The security suite asserts minimum cycle counts (more than 19M, 360M and 400k). Those checks would fail if a circuit were accidentally changed to hash outside the VM.

## Deploying

The site and interactive demo API run in a Node 22 container on Cloud Run (service `zk-hash-frontend`, region `us-central1`). From the repository root:

```sh
gcloud builds submit --config deploy/cloudbuild.yaml --project ckenedi-portfolio .
```

The server sets a strict Content Security Policy with no third-party origins; `'wasm-unsafe-eval'` allows the local Argon2id and STARK WebAssembly modules to compile. It serves `.wasm` with the correct MIME type. The deployment uses one instance so ephemeral accounts and single-use challenges stay in one process. Restarts clear the demo's records.

## What's next

- **Publish a real Argon2id proof.** Prove once on a cloud machine with 256 GiB or more of memory, then publish the proof so anyone can verify it in the browser.
- **Memory64 browser proving.** MiMC-7 needs 4.25 GiB, just above the wasm32 limit, so a wasm64 build should allow the first in-browser proof.
- **Segmented proving.** bcrypt and small-memory Argon2id carry little state between rounds. Splitting execution into segments linked by blinded state commitments would allow independent, parallel proofs of roughly 13 GiB each.
- **A prover built for password hashes.** A specialized constraint system or a streaming, out-of-core prover is the open problem between this project and a practical login.

## Limitations

- The Miden VM is alpha software, and none of this has had an independent audit.
- Proofs use Miden's 96-bit conjectured security level.
- Zero-knowledge (that a proof reveals nothing about the password) hasn't been confirmed for this Miden version and its proof options. Treat proofs as proofs of correct computation.
- A leaked database exposes the commitments to offline guessing, like any password-hash table.
- Argon2id at 8 KiB and bcrypt at cost 4 are demonstration settings, far below what real password storage needs.
- The circuit profile has no Argon2id secret key or associated data, passwords are limited to 1–64 bytes, salts are fixed at 16 bytes, and Argon2id lanes are limited to 1–4.
- If you need password login without sending passwords today, use [OPAQUE (RFC 9807)](https://www.rfc-editor.org/rfc/rfc9807.html).

## History

The first version of this project was a JavaScript prototype (`zk-hash/`, `frontend/`). It wrapped a client-side KDF output in a MiMC/FRI consistency proof but did not prove the hash itself. It was replaced by the in-circuit implementation in this repository and remains in the git history before this restructure.
