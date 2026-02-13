document.addEventListener('DOMContentLoaded', async () => {
    // Note: ZKProver is loaded via script tag in index.html, calling window.ZKProver
    
    // Dependencies are loaded via CDN in index.html:
    // dcodeIO.bcrypt
    // argon2 (available as window.argon2)

    console.log("Initializing App...");
    const prover = new ZKProver(window.dcodeIO.bcrypt, window.argon2);

    const generateBtn = document.getElementById('btn-generate');
    const verifyBtn = document.getElementById('btn-verify');
    const algoSelect = document.getElementById('algo-select');
    const paramsArgon = document.getElementById('params-argon');
    const paramsBcrypt = document.getElementById('params-bcrypt');
    const paramsAuth = document.getElementById('params-zk-auth');
    const proofOutput = document.getElementById('proof-output');
    const statusBox = document.getElementById('verify-status');
    const loader = document.getElementById('loader');

    // Toggle Params UI
    algoSelect.addEventListener('change', () => {
        // Hide all first
        paramsArgon.style.display = 'none';
        paramsBcrypt.style.display = 'none';
        paramsAuth.style.display = 'none';

        if (algoSelect.value === 'argon2id') {
            paramsArgon.style.display = 'block';
        } else if (algoSelect.value === 'bcrypt') {
            paramsBcrypt.style.display = 'block';
        } else if (algoSelect.value === 'zk-auth') {
            paramsAuth.style.display = 'block';
        }
    });

    // 1. Generate Proof (Hash + Mock STARK)
    generateBtn.addEventListener('click', async () => {
        const password = document.getElementById('password-input').value;
        if (!password) {
            alert("Please enter a password.");
            return;
        }

        const algo = algoSelect.value;
        const params = {};

        generateBtn.disabled = true;
        generateBtn.innerText = "Hashing & Generating Proof...";

        try {
            if (algo === 'bcrypt') {
                const val = document.getElementById('bcrypt-cost').value;
                params.cost = parseInt(val) || 10;
            } else if (algo === 'argon2id') {
                params.time = parseInt(document.getElementById('argon-time').value) || 1;
                params.mem = parseInt(document.getElementById('argon-mem').value) || 1024;
                params.hashLen = parseInt(document.getElementById('argon-len').value) || 32;
                params.salt = "browsersalt123"; // Simplification for demo
            } else if (algo === 'zk-auth') {
                const nonce = document.getElementById('auth-nonce').value;
                console.log("Generating Zero-Knowledge Auth Proof...");
                
                // Use the high-level Auth method which hashes the password first
                const proof = await prover.generateAuthProof(password, nonce);
                
                proofOutput.value = JSON.stringify(proof, null, 4);
                statusBox.style.display = 'none';
                document.getElementById('edit-hint').style.color = '#58a6ff';
                return; // Exit early as we handled it manually
            }

            console.log(`Starting ${algo} hashing...`);
            const proof = await prover.generateProof(password, algo, params);
            
            // Format for display
            proofOutput.value = JSON.stringify(proof, null, 4);
            statusBox.style.display = 'none';
            
            // Highlight the user they can edit this
            document.getElementById('edit-hint').style.color = '#58a6ff';

        } catch (e) {
            console.error(e);
            alert("Error generating proof: " + e.message + "\nCheck console for details.");
        } finally {
            generateBtn.disabled = false;
            generateBtn.innerText = "Generate Hash & ZK Proof";
        }
    });

    // 2. Verified Proof
    verifyBtn.addEventListener('click', async () => {
        const proofText = proofOutput.value;
        if (!proofText) {
            alert("No proof to verify. Generate one first.");
            return;
        }

        let proofObj;
        try {
            proofObj = JSON.parse(proofText);
        } catch (e) {
            alert("Invalid JSON format in Proof Viewer.");
            return;
        }

        verifyBtn.disabled = true;
        loader.style.display = 'inline-block';
        statusBox.style.display = 'none';

        try {
            const response = await fetch('/api/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(proofObj)
            });
            const result = await response.json();
            
            statusBox.className = result.success ? 'status success' : 'status error';
            statusBox.innerText = result.success 
                ? "✅ SUCCESS: " + result.message 
                : "❌ FAILED: " + result.error;
            statusBox.style.display = 'block';

        } catch (e) {
            statusBox.className = 'status error';
            statusBox.innerText = "Network Error: " + e.message;
            statusBox.style.display = 'block';
        } finally {
            verifyBtn.disabled = false;
            loader.style.display = 'none';
        }
    });
});
