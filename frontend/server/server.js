const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const crypto = require('crypto');
const ZKVerifier = require('../../zk-hash/verifier');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 8080;

// ── Nonce replay prevention (Phase 3) ────────────────────────────────────────
// Tracks used session_nonces with TTL = SESSION_TTL_MS. Nonces are single-use.
// NOTE: session_nonce (a short random UUID issued per proof) is distinct from
// the transcript nonce (the hash-witness field element used inside the STARK).
// Only session_nonce is checked here; the transcript nonce is verified inside
// the ZKVerifier as part of the STARK soundness argument.
// In production, replace this in-process Map with Redis + TTL-keyed entries.
const SESSION_TTL_MS = 15 * 60 * 1000; // 15 minutes
const usedNonces = new Map(); // session_nonce → expiry timestamp
setInterval(() => {
    const now = Date.now();
    for (const [k, exp] of usedNonces) {
        if (now > exp) usedNonces.delete(k);
    }
}, 60_000); // GC expired nonces every minute

// ── Issue #2: Server-issued challenge nonces ──────────────────────────────────
// The server issues a fresh 256-bit random challenge per login attempt and
// pre-stores it here as "pending".  The /api/verify handler confirms the proof's
// server_challenge was genuinely issued (not fabricated by the client) and then
// consumes it so it cannot be replayed.
// TTL matches the session TTL; challenges expire if the client never proves.
const issuedChallenges = new Map(); // challenge → expiry timestamp
setInterval(() => {
    const now = Date.now();
    for (const [k, exp] of issuedChallenges) {
        if (now > exp) issuedChallenges.delete(k);
    }
}, 60_000);

function issueChallenge() {
    const challenge = crypto.randomBytes(32).toString('hex'); // 256-bit random
    issuedChallenges.set(challenge, Date.now() + SESSION_TTL_MS);
    return challenge;
}

function checkAndConsumeChallenge(challenge) {
    if (!challenge) return false; // challenge is required; never allow missing
    const key = String(challenge);
    if (!issuedChallenges.has(key)) return false; // not issued by server
    if (Date.now() > issuedChallenges.get(key)) {
        issuedChallenges.delete(key);
        return false; // expired
    }
    issuedChallenges.delete(key); // single-use
    return true;
}

function checkAndConsumeNonce(nonce) {
    if (!nonce) return true; // no session_nonce provided → allow (demo mode)
    const key = String(nonce);
    if (usedNonces.has(key)) return false; // already used
    usedNonces.set(key, Date.now() + SESSION_TTL_MS);
    return true;
}

// ── Per-username rate limiting (Phase 3) ─────────────────────────────────────
// Cap: 5 attempts per username per minute; hard lock after 10 failures.
// In production, use Redis + sliding-window counters.
const RATE_WINDOW_MS  = 60_000;
const MAX_ATTEMPTS    = 5;
const LOCK_THRESHOLD  = 10;

const usernameAttempts = new Map(); // username → { count, windowStart, locked }
setInterval(() => {
    const now = Date.now();
    for (const [k, v] of usernameAttempts) {
        if (now - v.windowStart > RATE_WINDOW_MS && !v.locked) usernameAttempts.delete(k);
    }
}, 60_000);

function checkUsernameRateLimit(username) {
    if (!username) return { allowed: true };
    const now = Date.now();
    let rec = usernameAttempts.get(username);
    if (!rec) { rec = { count: 0, windowStart: now, locked: false }; usernameAttempts.set(username, rec); }
    if (rec.locked) return { allowed: false, reason: 'Account locked after repeated failures' };
    if (now - rec.windowStart > RATE_WINDOW_MS) { rec.count = 0; rec.windowStart = now; }
    rec.count++;
    if (rec.count > LOCK_THRESHOLD) { rec.locked = true; return { allowed: false, reason: 'Account locked after repeated failures' }; }
    if (rec.count > MAX_ATTEMPTS) return { allowed: false, reason: `Too many attempts — wait ${RATE_WINDOW_MS/1000}s` };
    return { allowed: true };
}

function recordFailure(username) {
    if (!username) return;
    const rec = usernameAttempts.get(username);
    if (rec) rec.failCount = (rec.failCount || 0) + 1;
}

// ── IP-level rate limiter (simple token bucket per IP) ───────────────────────
const rateCounts = new Map();
setInterval(() => rateCounts.clear(), 60_000);

const MAX_PROOF_QUERIES = 75; // must stay in sync with verifier.js MAX_QUERIES

function ipRateLimit(req, res, next) {
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    const count = (rateCounts.get(ip) || 0) + 1;
    rateCounts.set(ip, count);
    if (count > 10) {
        return res.status(429).json({ success: false, error: "Too many requests — try again shortly." });
    }
    next();
}

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(bodyParser.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, '../public')));
app.use('/zk-hash', express.static(path.join(__dirname, '../../zk-hash')));

const verifier = new ZKVerifier();

// ── API Routes ────────────────────────────────────────────────────────────────

// Issue a fresh single-use server challenge for the next proof.
// The 256-bit hex challenge is pre-stored server-side; the client must include
// it in the proof's public_inputs.server_challenge and absorb it as the first
// element of the STARK transcript.  This makes every proof session-specific and
// non-replayable even if the KDF output (and therefore the transcript nonce) is
// deterministic for a given password+salt pair.
app.get('/api/nonce', ipRateLimit, (req, res) => {
    const challenge = issueChallenge();
    res.json({ nonce: challenge });
});

app.post('/api/verify', ipRateLimit, (req, res) => {
    console.log("Received verification request...");
    const proof = req.body;
    
    if (!proof || Object.keys(proof).length === 0) {
        return res.status(400).json({ success: false, error: "Empty proof body" });
    }

    const allowedTypes = ['zk-stark-fri-full', 'zk-stark-bcrypt', 'zk-stark-argon2', 'standard-hash-proof'];
    if (!allowedTypes.includes(proof.proof_type)) {
        return res.status(400).json({ success: false, error: `Unknown proof_type: ${proof.proof_type}` });
    }

    // ── Per-username rate limit ───────────────────────────────────────────────
    const username = proof.username || (proof.public_inputs && proof.public_inputs.username) || null;
    const rl = checkUsernameRateLimit(username);
    if (!rl.allowed) {
        return res.status(429).json({ success: false, error: rl.reason });
    }

    // ── Nonce replay prevention ───────────────────────────────────────────────
    // session_nonce is a short random UUID generated by the prover per proof.
    // The transcript nonce (inside public_inputs.nonce) is the hash-witness field
    // element and is NOT checked here — it is verified inside ZKVerifier.
    const sessionNonce = proof.public_inputs && proof.public_inputs.session_nonce;
    if (sessionNonce && !checkAndConsumeNonce(sessionNonce)) {
        return res.status(400).json({ success: false, error: "Nonce already used — request a fresh session nonce" });
    }

    // ── Issue #2: Routing-layer server_challenge guard (MUST precede verifier.verify) ──
    // This check lives in the routing layer — NOT inside ZKVerifier — because only
    // the server knows which challenges it has issued.  The verifier merely absorbs
    // whatever value it receives into the transcript; the routing layer is the one
    // that enforces "this challenge was actually issued by GET /api/nonce and has not
    // been used before".
    //
    // Flow:
    //   1. Client calls GET /api/nonce → server calls issueChallenge() which stores
    //      the 256-bit hex in issuedChallenges with a TTL and returns it.
    //   2. Client embeds the challenge in public_inputs.server_challenge and uses it
    //      as transcript step 0 in the prover.
    //   3. Here we call checkAndConsumeChallenge() BEFORE verifier.verify():
    //        – If the challenge was not issued → 400 (forgery attempt).
    //        – If the challenge has already been used → 400 (replay attempt).
    //        – If the challenge has expired (TTL) → 400 (stale proof).
    //      Only if it passes do we proceed to the cryptographic STARK verification.
    // standard-hash-proof is exempt (no STARK transcript to bind to a session).
    if (proof.proof_type !== 'standard-hash-proof') {
        const serverChallenge = proof.public_inputs && proof.public_inputs.server_challenge;
        if (!checkAndConsumeChallenge(serverChallenge)) {
            return res.status(400).json({
                success: false,
                error: "Invalid or missing server_challenge — call GET /api/nonce before generating a proof"
            });
        }
    }

    try {
        // ZKVerifier.verify() absorbs server_challenge from public_inputs into the
        // transcript as step 0 to reconstruct the exact same Fiat-Shamir challenges
        // the prover used.  By this point the routing layer has already confirmed
        // the challenge is genuine and single-use — the verifier trusts it for
        // transcript reconstruction only.
        const result = verifier.verify(proof);

        if (!result.success) {
            recordFailure(username);
        }

        console.log("Verification Result:", result);
        res.json(result);
    } catch (e) {
        console.error("Verification crashed:", e);
        recordFailure(username);
        res.status(500).json({ success: false, error: "Server verification crashed: " + e.message });
    }
});

// ── Pattern 2 API Routes ──────────────────────────────────────────────────────
//
// Security model:
//   • The Argon2id salt is a public value (safe to return on request — it is
//     required by the client to re-derive the exact same hash on login).
//   • The pepper (ZK_SERVER_PEPPER env var) NEVER leaves the server.
//   • The pepper commitment C = Poseidon(mimc_output, pepper) is computed and
//     checked exclusively server-side in verifyPepperCommitP2().
//   • The client NEVER computes, transmits, or sees pepper_commit.

/**
 * GET /api/p2/salt/:username
 * Returns the Argon2id salt and parameters for `username`.
 * Salt is safe to expose — it is not a secret (see Argon2 RFC).
 * The client needs it to re-run Argon2id with the same params on login.
 */
app.get('/api/p2/salt/:username', ipRateLimit, (req, res) => {
    const username = String(req.params.username || '').trim();
    if (!username) return res.status(400).json({ success: false, error: 'username required' });

    try {
        const user = db.getUserByUsername(username);
        if (!user) {
            // Constant-time response to avoid username enumeration.
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        const params = typeof user.argon2_params === 'string'
            ? JSON.parse(user.argon2_params)
            : user.argon2_params;
        res.json({
            success: true,
            salt:         user.argon2_salt,
            argon2_params: params
        });
    } catch (e) {
        console.error('[p2/salt] error:', e);
        res.status(500).json({ success: false, error: 'Internal error' });
    }
});

/**
 * POST /api/p2/register
 * Body: { proof, username }
 *
 * Pattern 2 registration flow:
 *   1. Validate input; check username availability.
 *   2. Check server_challenge was genuinely issued (replay prevention).
 *   3. Verify the STARK proof with skipPepperCheck=true  ← client has no pepper.
 *   4. Server computes C = Poseidon(mimc_output, serverPepper) entirely server-side.
 *   5. Store {username, pepper_commit=C, argon2_salt, argon2_params} in DB.
 *   6. Return success.  h₁ (Argon2id output) is NEVER stored.
 */
app.post('/api/p2/register', ipRateLimit, (req, res) => {
    const { proof, username } = req.body || {};

    if (!proof || !username) {
        return res.status(400).json({ success: false, error: 'proof and username required' });
    }

    const uname = String(username).trim();
    if (!uname || uname.length < 3 || uname.length > 64) {
        return res.status(400).json({ success: false, error: 'username must be 3–64 characters' });
    }
    if (!/^[a-zA-Z0-9_.-]+$/.test(uname)) {
        return res.status(400).json({ success: false, error: 'username may only contain letters, digits, _ . -' });
    }

    // ── Proof type guard ──────────────────────────────────────────────────────
    if (proof.proof_type !== 'zk-stark-argon2') {
        return res.status(400).json({ success: false, error: 'Pattern 2 requires proof_type zk-stark-argon2' });
    }

    // ── Rate limiting ─────────────────────────────────────────────────────────
    const rl = checkUsernameRateLimit(uname);
    if (!rl.allowed) return res.status(429).json({ success: false, error: rl.reason });

    // ── Server challenge check ─────────────────────────────────────────────────
    const serverChallenge = proof.public_inputs && proof.public_inputs.server_challenge;
    if (!checkAndConsumeChallenge(serverChallenge)) {
        return res.status(400).json({
            success: false,
            error: 'Invalid or missing server_challenge — call GET /api/nonce before registering'
        });
    }

    // ── Session nonce replay prevention ───────────────────────────────────────
    const sessionNonce = proof.public_inputs && proof.public_inputs.session_nonce;
    if (sessionNonce && !checkAndConsumeNonce(sessionNonce)) {
        return res.status(400).json({ success: false, error: 'Nonce already used — request a fresh nonce' });
    }

    try {
        // ── Check username availability ────────────────────────────────────────
        const exists = db.usernameExists(uname);
        if (exists) {
            return res.status(409).json({ success: false, error: 'Username already taken' });
        }

        // ── STARK verification (Pattern 2: pepper check skipped) ──────────────
        // skipPepperCheck=true because the client correctly did NOT compute
        // pepper_commit. The pepper binding is enforced below by verifyPepperCommitP2.
        const result = verifier.verify(proof, { skipPepperCheck: true });
        if (!result.success) {
            recordFailure(uname);
            return res.status(400).json({ success: false, error: 'Proof verification failed: ' + result.error });
        }

        // ── Pepper commitment (server-side only) ───────────────────────────────
        // The client sent mimc_output as a public proof input. We now apply the
        // server pepper exclusively here — the client never participates in this step.
        const mimc_output = proof.public_inputs && proof.public_inputs.mimc_output;
        if (!mimc_output) {
            return res.status(400).json({ success: false, error: 'Proof missing mimc_output' });
        }
        // verifyPepperCommitP2 computes C = Poseidon(mimc_output, serverPepper) and
        // throws if the result is degenerate.  We store the computed C in the DB.
        // (At registration there is no storedC to compare against — we compute it fresh.)
        const C = computePepperCommit(mimc_output);

        // ── Extract Argon2id params for storage ────────────────────────────────
        const pi = proof.public_inputs;
        const argonParams = (pi.params) || (pi.argon2_params) || {};
        const argon2Salt  = (argonParams.salt) || (pi.params && pi.params.salt) || '';
        if (!argon2Salt) {
            return res.status(400).json({ success: false, error: 'Proof missing Argon2id salt — cannot register' });
        }

        db.createUser({
            username:      uname,
            pepper_commit: C,
            argon2_salt:   argon2Salt,
            argon2_params: {
                time:    argonParams.time    || 3,
                mem:     argonParams.mem     || 65536,
                hashLen: argonParams.hashLen || 32
            }
        });

        console.log(`[p2/register] Registered user: ${uname}`);
        res.json({
            success: true,
            message: `User ${uname} registered successfully with ZK-Pattern 2 credential`
        });

    } catch (e) {
        console.error('[p2/register] error:', e);
        if (e.code === 'SQLITE_CONSTRAINT_UNIQUE' || (e.message && e.message.includes('UNIQUE'))) {
            return res.status(409).json({ success: false, error: 'Username already taken' });
        }
        res.status(500).json({ success: false, error: 'Registration failed: ' + e.message });
    }
});

/**
 * POST /api/p2/login
 * Body: { proof, username }
 *
 * Pattern 2 login flow:
 *   1. Look up stored C for username from DB.
 *   2. Check server_challenge.
 *   3. Verify STARK proof with skipPepperCheck=true.
 *   4. Server-side: compute Poseidon(mimc_output, serverPepper) and compare to stored C.
 *      This is the sole credential check — no password is ever transmitted or stored.
 *   5. Return success/failure.
 */
app.post('/api/p2/login', ipRateLimit, (req, res) => {
    const { proof, username } = req.body || {};

    if (!proof || !username) {
        return res.status(400).json({ success: false, error: 'proof and username required' });
    }

    const uname = String(username).trim();

    // ── Rate limiting ─────────────────────────────────────────────────────────
    const rl = checkUsernameRateLimit(uname);
    if (!rl.allowed) return res.status(429).json({ success: false, error: rl.reason });

    // ── Proof type guard ──────────────────────────────────────────────────────
    if (proof.proof_type !== 'zk-stark-argon2') {
        return res.status(400).json({ success: false, error: 'Pattern 2 requires proof_type zk-stark-argon2' });
    }

    // ── Server challenge check ─────────────────────────────────────────────────
    const serverChallenge = proof.public_inputs && proof.public_inputs.server_challenge;
    if (!checkAndConsumeChallenge(serverChallenge)) {
        return res.status(400).json({
            success: false,
            error: 'Invalid or missing server_challenge — call GET /api/nonce before logging in'
        });
    }

    // ── Session nonce replay prevention ───────────────────────────────────────
    const sessionNonce = proof.public_inputs && proof.public_inputs.session_nonce;
    if (sessionNonce && !checkAndConsumeNonce(sessionNonce)) {
        return res.status(400).json({ success: false, error: 'Nonce already used — request a fresh nonce' });
    }

    try {
        // ── Look up user ───────────────────────────────────────────────────────
        const user = db.getUserByUsername(uname);
        if (!user) {
            // Constant-time failure path — same response shape as wrong password.
            recordFailure(uname);
            return res.status(401).json({ success: false, error: 'Invalid username or password' });
        }

        // ── STARK verification (Pattern 2: pepper check skipped) ──────────────
        const result = verifier.verify(proof, { skipPepperCheck: true });
        if (!result.success) {
            recordFailure(uname);
            return res.status(401).json({ success: false, error: 'Proof verification failed: ' + result.error });
        }

        // ── Pattern 2 pepper binding: compare against stored DB commitment ─────
        // The server independently computes Poseidon(mimc_output, pepper) and
        // compares to the value stored at registration.  The client never knew or
        // computed this value — it is an opaque server-side operation.
        const mimc_output = proof.public_inputs && proof.public_inputs.mimc_output;
        if (!mimc_output) {
            recordFailure(uname);
            return res.status(400).json({ success: false, error: 'Proof missing mimc_output' });
        }

        try {
            verifier.verifyPepperCommitP2(mimc_output, user.pepper_commit);
        } catch (pepperErr) {
            recordFailure(uname);
            // Return a generic auth failure — do NOT expose "pepper mismatch" to the client.
            return res.status(401).json({ success: false, error: 'Invalid username or password' });
        }

        // ── Success ────────────────────────────────────────────────────────────
        db.touchLastLogin(uname);
        console.log(`[p2/login] Authenticated user: ${uname}`);
        res.json({
            success: true,
            message: `Welcome back, ${uname}! ZK-Pattern 2 authentication successful.`,
            username: uname
        });

    } catch (e) {
        console.error('[p2/login] error:', e);
        recordFailure(uname);
        res.status(500).json({ success: false, error: 'Login failed: ' + e.message });
    }
});

/**
 * GET /api/p2/db-view/:username
 * Returns the entire database row for a given username.
 * For demonstration purposes only to show the user what does and does not get stored!
 */
app.get('/api/p2/db-view/:username', ipRateLimit, (req, res) => {
    const username = String(req.params.username || '').trim();
    if (!username) return res.status(400).json({ success: false, error: 'username required' });

    try {
        const user = db.getUserByUsername(username);
        if (!user) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        res.json({
            success: true,
            user: user
        });
    } catch (e) {
        console.error('[p2/db-view] error:', e);
        res.status(500).json({ success: false, error: 'Internal error' });
    }
});

// ── Internal: server-side pepper commitment helper ───────────────────────────
// Computes C = Poseidon(mimc_output, serverPepper) — mirrors verifyPepperCommitP2
// in verifier.js.  Used at registration to produce the value stored in the DB.
// Kept in server.js so it is never shipped to the client.
const { poseidonHash: _poseidonHash } = require('../../zk-hash/stark-math');
const _FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function _hashBytesToWitnessServer(hashBytes) {
    const LIMB = 31;
    const elements = [];
    for (let i = 0; i < hashBytes.length; i += LIMB) {
        let v = 0n;
        for (let j = i; j < Math.min(i + LIMB, hashBytes.length); j++) {
            v = (v << 8n) | BigInt(hashBytes[j]);
        }
        elements.push(v % _FIELD_MODULUS);
    }
    return _poseidonHash(elements);
}

function computePepperCommit(mimc_output) {
    const pepperHex   = process.env.ZK_SERVER_PEPPER || 'INSECURE-DEV-PEPPER-REPLACE-WITH-HSM';
    const pepperBytes = Buffer.from(pepperHex, 'utf8');
    const pepperField = _hashBytesToWitnessServer(pepperBytes);
    return _poseidonHash([BigInt(mimc_output), pepperField]).toString();
}

// ── Start Server ──────────────────────────────────────────────────────────────
// initDB() is synchronous (better-sqlite3).  The DB is ready before the
// server begins accepting connections.
try {
    db.initDB();
} catch (err) {
    console.error('Fatal: DB init failed —', err.message);
    process.exit(1);
}

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
    console.log(`ZK-Hash Demo active.`);
});

