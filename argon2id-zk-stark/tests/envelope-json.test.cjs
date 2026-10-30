const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

(async () => {
  const modulePath = path.resolve(__dirname, '..', 'web', 'envelope-json.js');
  const moduleSource = fs.readFileSync(modulePath, 'utf8');
  const moduleUrl = `data:text/javascript;base64,${Buffer.from(moduleSource).toString('base64')}`;
  const { parseEnvelope } = await import(moduleUrl);
  const parsed = parseEnvelope(`{
    "programHash": [18446744069414584320, 9007199254740991],
    "credential": [8370215289663149514, 1, 2, 3],
    "saltHex": "00000000000000000000000000000000",
    "proofBase64": "12345678901234567890",
    "escaped": "quote: \\" and 12345678901234567890"
  }`);

  assert.equal(parsed.programHash[0], 18446744069414584320n);
  assert.equal(parsed.programHash[1], 9007199254740991n);
  assert.equal(parsed.credential[0], 8370215289663149514n);
  assert.equal(parsed.saltHex, '00000000000000000000000000000000');
  assert.equal(parsed.proofBase64, '12345678901234567890');
  assert.equal(parsed.escaped, 'quote: " and 12345678901234567890');
  assert.throws(() => parseEnvelope('{"credential":[18446744069414584320,]}'));
  console.log('envelope JSON precision/string tests: PASS');
})().catch((error) => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
