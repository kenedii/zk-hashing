import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createDemoServer } from '../server/app.js';
import { derivePasswordKey, makeLoginProof, PARAMETERS, bytesToHex } from '../web/lib/live-crypto.js';

let server, base, account, key, setup;
let clock = Date.now();
const password = 'a demo password ☕ 2026';
async function request(path, body) {
  const response = await fetch(base + path, body ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) } : {});
  return { status: response.status, result: await response.json() };
}
async function challenge() { return (await request('/api/demo/challenge', { accountId: account.accountId })).result; }
function payload(challenge, signingKey = key.secretKey) {
  return { accountId: account.accountId, challengeId: challenge.challengeId, proof: makeLoginProof(signingKey, account.accountId, challenge) };
}
before(async () => {
  server = createDemoServer({ now: () => clock });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
  setup = (await request('/api/demo/setup')).result;
  key = await derivePasswordKey(password, setup.salt);
  account = (await request('/api/demo/register', { publicKey: key.publicKey, salt: setup.salt, parameters: PARAMETERS })).result;
});
after(async () => { key?.hash.fill(0); key?.secretKey.fill(0); await new Promise((resolve) => server.close(resolve)); });

test('registration stores only public data, never the password or Argon2id output', () => {
  assert.ok(account.accountId);
  assert.deepEqual(Object.keys(account.stored).sort(), ['expiresAt', 'parameters', 'publicKey', 'salt']);
  assert.deepEqual(account.receivedFields, ['publicKey', 'salt', 'parameters']);
  const data = JSON.stringify(account);
  assert.ok(!data.includes(password));
  assert.ok(!data.includes(bytesToHex(key.hash)));
  assert.ok(!data.includes(bytesToHex(key.secretKey)));
});
test('a freshly derived correct password produces a proof accepted by the server', async () => {
  const fresh = await derivePasswordKey(password, setup.salt);
  try {
    const c = await challenge();
    const sent = payload(c, fresh.secretKey);
    assert.ok(!JSON.stringify(sent).includes(bytesToHex(fresh.hash)));
    const { status, result } = await request('/api/demo/verify', sent);
    assert.equal(status, 200);
    assert.equal(result.verified, true);
    assert.equal(result.challengeConsumed, true);
    assert.deepEqual(result.receivedFields, ['accountId', 'challengeId', 'proof']);
  } finally { fresh.hash.fill(0); fresh.secretKey.fill(0); }
});
test('wrong passwords are rejected by the actual verifier and spend their challenge', async () => {
  const wrong = await derivePasswordKey('a different password', setup.salt);
  try {
    const sent = payload(await challenge(), wrong.secretKey);
    const response = await request('/api/demo/verify', sent);
    assert.equal(response.status, 401);
    assert.equal(response.result.verified, false);
    assert.equal((await request('/api/demo/verify', sent)).status, 409);
  } finally { wrong.hash.fill(0); wrong.secretKey.fill(0); }
});
test('valid proofs cannot be replayed, tampered with, or relabelled for another challenge', async () => {
  const sent = payload(await challenge());
  assert.equal((await request('/api/demo/verify', sent)).status, 200);
  assert.equal((await request('/api/demo/verify', sent)).status, 409);
  const next = await challenge();
  assert.equal((await request('/api/demo/verify', { ...sent, challengeId: next.challengeId })).status, 401);
  const mutated = payload(await challenge());
  mutated.proof = (mutated.proof[0] === 'a' ? 'b' : 'a') + mutated.proof.slice(1);
  assert.equal((await request('/api/demo/verify', mutated)).status, 401);
});
test('another account cannot use a proof from the first account', async () => {
  const other = (await request('/api/demo/register', { publicKey: key.publicKey, salt: setup.salt, parameters: PARAMETERS })).result;
  const c = (await request('/api/demo/challenge', { accountId: other.accountId })).result;
  const proof = makeLoginProof(key.secretKey, account.accountId, c);
  assert.equal((await request('/api/demo/verify', { accountId: other.accountId, challengeId: c.challengeId, proof })).status, 401);
});
test('API rejects unexpected secret fields and altered hash parameters', async () => {
  const data = { publicKey: key.publicKey, salt: setup.salt, parameters: PARAMETERS };
  assert.equal((await request('/api/demo/register', { ...data, password: 'should-be-rejected' })).status, 400);
  assert.equal((await request('/api/demo/register', { ...data, hash: 'should-be-rejected' })).status, 400);
  assert.equal((await request('/api/demo/register', { ...data, parameters: { ...PARAMETERS, memoryKiB: 8 } })).status, 400);
  const sent = payload(await challenge());
  assert.equal((await request('/api/demo/verify', { ...sent, hash: 'should-be-rejected' })).status, 400);
});
test('static pages, Wasm MIME type, security headers and traversal protection work', async () => {
  const response = await fetch(base);
  assert.equal(response.status, 200);
  assert.match(await response.text(), /class="home-links"/);
  assert.match(await (await fetch(base + '/login.html')).text(), /id="register-form"/);
  assert.match(await (await fetch(base + '/architecture.html')).text(), /id="act-verify"/);
  assert.match(response.headers.get('content-security-policy'), /wasm-unsafe-eval/);
  assert.equal((await fetch(base + '/pkg/argon2id_zk_runtime_bg.wasm', { method: 'HEAD' })).headers.get('content-type'), 'application/wasm');
  assert.equal((await fetch(base + '/%2e%2e%2fpackage.json')).status, 404);
  assert.equal((await fetch(base + '/lab/')).status, 200);
});
test('expired challenges and accounts fail closed', async () => {
  const sent = payload(await challenge());
  clock += 2 * 60_000 + 1;
  assert.equal((await request('/api/demo/verify', sent)).status, 409);
  clock += 30 * 60_000;
  assert.equal((await request('/api/demo/challenge', { accountId: account.accountId })).status, 404);
});
