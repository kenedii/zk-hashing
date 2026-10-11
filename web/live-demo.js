import { derivePasswordKey, makeLoginProof, bytesToHex } from './lib/live-crypto.js';

const $ = (id) => document.getElementById(id);
let account = null;
let working = false;
let lastProof = null;
const transcript = [];
const pretty = (value) => JSON.stringify(value, null, 2);

function status(message, state = '') {
  $('live-status').textContent = message;
  $('live-status').dataset.state = state;
}
function showHash(hash) {
  // Display only in this browser; never put it into a network request.
  $('local-hash').textContent = bytesToHex(hash);
  $('local-hash').hidden = !$('reveal-hash').checked;
  $('local-computation').textContent = 'Argon2id ran here: 32 MiB memory, 3 passes. Its 32-byte output stayed in this tab.';
}
async function request(path, payload) {
  const method = payload ? 'POST' : 'GET';
  const entry = { method, path, ...(payload ? { body: structuredClone(payload) } : {}) };
  transcript.push(entry);
  // This shows the exact object serialized for fetch, not a simulated message.
  $('network-transcript').textContent = pretty(transcript);
  const response = await fetch(path, payload ? { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) } : { cache: 'no-store' });
  const result = await response.json();
  entry.status = response.status;
  $('network-transcript').textContent = pretty(transcript);
  if (!response.ok && response.status !== 401) throw new Error(result.error || 'The server could not complete the request.');
  return result;
}
function showServer(result) {
  $('server-record').textContent = pretty(result.stored);
  $('server-fields').textContent = result.receivedFields.join(', ');
  $('privacy-receipt').hidden = false;
  $('privacy-receipt').textContent = `Server received ${result.receivedFields.length} fields: ${result.receivedFields.join(', ')}. Password and Argon2id hash: absent. This record is returned by the running server.`;
}
async function busy(task) {
  if (working) return;
  working = true;
  syncButtons();
  try { await task(); }
  catch (error) { status(error.message || String(error), 'error'); }
  finally { working = false; syncButtons(); }
}
function syncButtons() {
  $('register-password').disabled = working;
  $('login-password').disabled = working || !account;
  $('register-button').disabled = working;
  $('login-button').disabled = working || !account;
  $('replay-button').disabled = working || !lastProof;
}

$('register-form').addEventListener('submit', (event) => {
  event.preventDefault();
  busy(async () => {
    let password = $('register-password').value;
    if (!password) throw new Error('Enter a demo password first.');
    let derived;
    try {
      status('Hashing your password in this browser…');
      const setup = await request('/api/demo/setup');
      derived = await derivePasswordKey(password, setup.salt);
      password = '';
      $('register-password').value = '';
      showHash(derived.hash);
      status('Sending the public key and salt to the server…');
      const result = await request('/api/demo/register', { publicKey: derived.publicKey, salt: setup.salt, parameters: setup.parameters });
      account = { accountId: result.accountId, salt: setup.salt };
      lastProof = null;
      showServer(result);
      $('login-stage').classList.add('is-ready');
      status('Registered. Type the same password below to prove you know it.', 'ready');
    } finally { derived?.secretKey.fill(0); derived?.hash.fill(0); }
  }).then(() => { if (account) $('login-password').focus(); });
});

$('login-form').addEventListener('submit', (event) => {
  event.preventDefault();
  busy(async () => {
    let password = $('login-password').value;
    if (!password || !account) throw new Error('Register a password, then enter it here.');
    let derived;
    const started = performance.now();
    try {
      status('Requesting a fresh challenge from the server…');
      const challenge = await request('/api/demo/challenge', { accountId: account.accountId });
      $('live-challenge').textContent = challenge.challenge;
      status('Hashing locally and creating your password proof…');
      derived = await derivePasswordKey(password, challenge.salt);
      password = '';
      $('login-password').value = '';
      showHash(derived.hash);
      const proof = makeLoginProof(derived.secretKey, account.accountId, challenge);
      const payload = { accountId: account.accountId, challengeId: challenge.challengeId, proof };
      lastProof = payload;
      $('live-proof').textContent = proof;
      status('The server is verifying the 64-byte proof…');
      const result = await request('/api/demo/verify', payload);
      showServer(result);
      $('live-timing').textContent = `${(performance.now() - started).toFixed(0)} ms including hashing and the server round trip`;
      status(result.verified ? 'Verified by the server. You proved knowledge of your registered password.' : 'Rejected by the server. That password does not match your registration.', result.verified ? 'accepted' : 'rejected');
    } finally { derived?.secretKey.fill(0); derived?.hash.fill(0); }
  });
});

$('replay-button').addEventListener('click', () => busy(async () => {
  try { await request('/api/demo/verify', lastProof); status('Unexpected replay response.', 'error'); }
  catch (error) { status(`Replay rejected by the server: ${error.message}`, 'rejected'); }
}));
$('reveal-hash').addEventListener('change', () => { $('local-hash').hidden = !$('reveal-hash').checked; });
syncButtons();
