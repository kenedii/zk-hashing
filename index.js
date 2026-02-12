const ZKProver = require('./prover');
const ZKVerifier = require('./verifier');
const common = require('./common');

module.exports = {
    ZKProver,
    ZKVerifier,
    ...common
};
