const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const ZKVerifier = require('../../zk-hash/verifier');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Rate Limiter (simple in-process token bucket per IP) ─────────────────────
// Allows 10 verify requests per minute per IP before returning 429.
const rateCounts = new Map();
setInterval(() => rateCounts.clear(), 60_000); // Reset every minute

const MAX_PROOF_QUERIES = 75; // must stay in sync with verifier.js MAX_QUERIES

function rateLimit(req, res, next) {
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    const count = (rateCounts.get(ip) || 0) + 1;
    rateCounts.set(ip, count);
    if (count > 10) {
        return res.status(429).json({ success: false, error: "Too many requests — try again shortly." });
    }
    next();
}

// ── Middleware ────────────────────────────────────────────────────────────────
// Tighter body limit: a valid proof with 20 queries + Merkle paths is < 300 KB.
// 512 KB gives ample headroom while blocking oversized DoS payloads.
app.use(bodyParser.json({ limit: '512kb' }));
app.use(express.static(path.join(__dirname, '../public')));
// Expose zk-hash folder to the client so it can load the Prover code
app.use('/zk-hash', express.static(path.join(__dirname, '../../zk-hash')));

// Initialize Verifier
const verifier = new ZKVerifier();

// ── API Routes ────────────────────────────────────────────────────────────────
app.post('/api/verify', rateLimit, (req, res) => {
    console.log("Received verification request...");
    const proof = req.body;
    
    // Add validation for empty body
    if (!proof || Object.keys(proof).length === 0) {
        return res.status(400).json({ success: false, error: "Empty proof body" });
    }

    // Reject proof_type that we don't recognise to prevent future bypass exploits
    const allowedTypes = ['zk-stark-fri-full', 'zk-stark-bcrypt', 'zk-stark-argon2', 'standard-hash-proof'];
    if (!allowedTypes.includes(proof.proof_type)) {
        return res.status(400).json({ success: false, error: `Unknown proof_type: ${proof.proof_type}` });
    }

    // Verify Proof
    try {
        const result = verifier.verify(proof);
        console.log("Verification Result:", result);
        res.json(result);
    } catch (e) {
        console.error("Verification crashed:", e);
        res.status(500).json({ success: false, error: "Server verification crashed: " + e.message });
    }
});

// ── Start Server ──────────────────────────────────────────────────────────────
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
    console.log(`ZK-Hash Demo active.`);
});
