// Common constants and utilities for the ZK Hash demo

const ALGORITHMS = {
    BCRYPT: 'bcrypt',
    ARGON2ID: 'argon2id'
};

const ZK_PROOF_PREFIX = "zk-stark-proof-v1";

if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        ALGORITHMS,
        ZK_PROOF_PREFIX
    };
}
if (typeof window !== 'undefined') {
    window.CommonZK = {
        ALGORITHMS,
        ZK_PROOF_PREFIX
    };
}

