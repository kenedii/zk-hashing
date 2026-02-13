const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const ZKVerifier = require('../../zk-hash/verifier');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, '../public')));
// Expose zk-hash folder to the client so it can load the Prover code
app.use('/zk-hash', express.static(path.join(__dirname, '../zk-hash')));

// Initialize Verifier
const verifier = new ZKVerifier();

// API Routes
app.post('/api/verify', (req, res) => {
    console.log("Received verification request...");
    const proof = req.body;

    // Verify Proof
    const result = verifier.verify(proof);
    console.log("Verification Result:", result);
    res.json(result);
});

// Start Server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
    console.log(`ZK-Hash Demo active.`);
});
