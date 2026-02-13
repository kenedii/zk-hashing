// zk-hash/stark-math.js
// A lightweight implementation of Finite Field (Prime Field) arithmetic and basic Polynomial logic needed for STARKs.
// We use a small prime for demonstration speed in JS, but big enough for security in this context.
// Prime = 3 * 2^30 + 1 (A "Goldilocks-like" field or similar is often used, we'll use a standard discrete field)

// Constants
// We use a prime p = 3221225473 (3 * 2^30 + 1) which allows FFTs of size 2^30.
// BUT for JS numbers (double precision safe integer is 2^53), we need to be careful with multiplication overflow.
// Let's use BigInt for safety.

const FIELD_MODULUS = 3221225473n; // 3 * 2^30 + 1
const FIELD_GENERATOR = 5n; // Generator for the multiplicative group

class FieldElement {
    constructor(val) {
        if (typeof val === 'bigint') {
            this.val = ((val % FIELD_MODULUS) + FIELD_MODULUS) % FIELD_MODULUS;
        } else {
            this.val = ((BigInt(val) % FIELD_MODULUS) + FIELD_MODULUS) % FIELD_MODULUS;
        }
    }

    add(other) { return new FieldElement(this.val + other.val); }
    sub(other) { return new FieldElement(this.val - other.val); }
    mul(other) { return new FieldElement(this.val * other.val); }
    
    // Modular exponentiation
    pow(exp) {
        let res = 1n;
        let base = this.val;
        let p = BigInt(exp);
        while (p > 0n) {
            if (p & 1n) res = (res * base) % FIELD_MODULUS;
            base = (base * base) % FIELD_MODULUS;
            p >>= 1n;
        }
        return new FieldElement(res);
    }

    inv() {
        return this.pow(FIELD_MODULUS - 2n); // Fermat's Little Theorem
    }

    div(other) { return this.mul(other.inv()); }
    
    equals(other) { return this.val === other.val; }
    toString() { return this.val.toString(); }
}

// Basic MiMC Hash implementation (ZK-Friendly Hash)
// x is input, k is key (can be 0)
const MIMC_ROUNDS = 64;
const MIMC_CONSTANTS = Array.from({length: MIMC_ROUNDS}, (_, i) => BigInt(i * 123456789)); 

function mimcHash(x, k = 0n) {
    let curr = (typeof x === 'bigint') ? x : BigInt(x);
    let key = (typeof k === 'bigint') ? k : BigInt(k);
    
    for (let i = 0; i < MIMC_ROUNDS; i++) {
        // x = (x + k + ci)^3
        let t = (curr + key + (MIMC_CONSTANTS[i] || 0n)) % FIELD_MODULUS;
        // Optimization: Use raw BigInt math instead of FieldElement for internal loop speed
        let t2 = (t * t) % FIELD_MODULUS;
        let t3 = (t2 * t) % FIELD_MODULUS;
        curr = t3;
    }
    return (curr + key) % FIELD_MODULUS;
}

// Security: Deterministic Random Bit Generator for Fiat-Shamir
function generateFiatShamirQueries(traceRoot, numQueries, domainSize) {
    // traceRoot is now strictly a Decimal String (BigInt.toString())
    // Parse directly
    let seed = 0n;
    try {
        seed = BigInt(traceRoot);
    } catch(e) {
        // Fallback if somehow old hex data persists in cache
        if (traceRoot.startsWith && traceRoot.startsWith('0x')) seed = BigInt(traceRoot);
        else seed = BigInt('0x' + traceRoot);
    }

    const indices = new Set();
    let counter = 0n;

    // Generate distinct indices
    while (indices.size < numQueries) {
        // Use MiMC as the PRNG source
        // Hash(Seed + Counter)
        const randVal = mimcHash(seed, counter);
        const idx = Number(randVal % BigInt(domainSize));
        if (idx < domainSize) { // Valid index
            indices.add(idx);
        }
        counter++;
    }
    return Array.from(indices).sort((a,b) => a-b);
}

// Merkle Tree Implementation for Commitments
class MerkleTree {
    constructor(leaves) {
        this.leaves = leaves.map(l => typeof l === 'string' ? l : l.toString());
        this.layers = [this.leaves];
        this.build();
    }

    build() {
        let currentLayer = this.leaves;
        while (currentLayer.length > 1) {
            const nextLayer = [];
            for (let i = 0; i < currentLayer.length; i += 2) {
                const left = currentLayer[i];
                const right = (i + 1 < currentLayer.length) ? currentLayer[i + 1] : "";
                // Simple string concat hash for demo speed (use SHA256 in production)
                // We use a simple hash to avoid heavy crypto libs in this pure math file
                nextLayer.push(this.hashPair(left, right));
            }
            this.layers.push(nextLayer);
            currentLayer = nextLayer;
        }
        this.root = currentLayer[0];
    }

    hashPair(a, b) {
        // Universal Hash: Input Decimal Strings -> Output Decimal String
        // This ensures consistency across layers (Initial Leaves are Dec, Nodes are Dec)
        const toBI = (val) => {
             if (typeof val === 'bigint') return val;
             val = val.toString();
             // Since we standardized on Decimal output, treat everything as decimal 
             // UNLESS it explicitly has 0x prefix (shouldn't happen with new logic but safe to keep)
             if (val.startsWith('0x')) return BigInt(val);
             return BigInt(val);
        };

        const ba = toBI(a || "0");
        const bb = toBI(b || "0");

        // Mix: a + 2*b (Simple non-symmetric algebraic mix)
        const mixed = (ba + (bb * 2n)) % FIELD_MODULUS;
        
        // Hash the mixed value
        const res = mimcHash(mixed);
        return res.toString(); // Return DECIMAL string
    }

    getRoot() {
        return this.root;
    }

    getPath(index) {
        const path = [];
        let layerIdx = 0;
        let currentIdx = index;
        
        while (layerIdx < this.layers.length - 1) {
            const isLeft = currentIdx % 2 === 0;
            const siblingIdx = isLeft ? currentIdx + 1 : currentIdx - 1;
            const layer = this.layers[layerIdx];
            
            if (siblingIdx < layer.length) {
                path.push(layer[siblingIdx]);
            } else {
                path.push(""); // Padding
            }
            
            currentIdx = Math.floor(currentIdx / 2);
            layerIdx++;
        }
        return path;
    }
    
    static verify(root, index, value, path) {
        let currentHash = value.toString();
        let currentIdx = index;
        
        // Use an instance to access the specific hash logic
        const tempTree = new MerkleTree([]); 

        for (const sibling of path) {
            const isLeft = currentIdx % 2 === 0;
            if (isLeft) {
                currentHash = tempTree.hashPair(currentHash, sibling);
            } else {
                currentHash = tempTree.hashPair(sibling, currentHash);
            }
            currentIdx = Math.floor(currentIdx / 2);
        }
        return currentHash === root;
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        FieldElement,
        FIELD_MODULUS,
        mimcHash,
        MerkleTree,
        generateFiatShamirQueries
    };
}

if (typeof window !== 'undefined') {
    window.StarkMath = {
        FieldElement,
        FIELD_MODULUS,
        mimcHash,
        MerkleTree,
        generateFiatShamirQueries
    };
}
