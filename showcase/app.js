// Showcase page: animates the memory chart once and runs the real Miden verifier
// (built from ../argon2id-zk-stark/runtime) against the checked-in MiMC-7 proof.
import { parseEnvelope } from '../argon2id-zk-stark/web/envelope-json.js';

const RUNTIME = '../argon2id-zk-stark/web/pkg/argon2id_zk_runtime.js';
const WASM = '../argon2id-zk-stark/web/pkg/argon2id_zk_runtime_bg.wasm';
const PROOF = '../argon2id-zk-stark/tests/fixtures/mimc-proof.json';

const SALT = '000102030405060708090a0b0c0d0e0f';
const CHALLENGE = new Uint32Array([305419896, 2596069104, 267242409, 2271560481]);
const CREDENTIAL = [
  8370215289663149514n, 8090811050392849221n, 9444347110279816554n, 1235188709954996380n,
];

const $ = (id) => document.getElementById(id);
let api = null;
let envelope = null;

// ---------- Memory chart: one entrance, markers travel to their measured position ----------
function stageWall() {
  const plot = $('wall');
  if (!plot || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  plot.querySelectorAll('.load').forEach((el, i) => el.style.setProperty('--delay', `${250 + i * 160}ms`));
  plot.classList.add('is-entering');
}

// ---------- Verifier ----------
function addResult(ok, title, detail, ms) {
  const li = document.createElement('li');
  li.className = ok ? 'accepted' : 'rejected';
  const verdict = document.createElement('span');
  verdict.className = 'verdict';
  verdict.textContent = ok ? 'Accepted' : 'Rejected';
  const body = document.createElement('span');
  body.className = 'detail';
  body.textContent = title;
  if (detail) {
    const small = document.createElement('small');
    small.textContent = detail;
    body.append(small);
  }
  const time = document.createElement('span');
  time.className = 'time';
  time.textContent = `${ms.toFixed(0)} ms`;
  li.append(verdict, body, time);
  $('results').prepend(li);
}

function reason(error) {
  const text = String(error?.message ?? error);
  return text.length > 220 ? `${text.slice(0, 220)}…` : text;
}

function run(title, makeArgs) {
  const started = performance.now();
  try {
    const { env, credential, challenge } = makeArgs();
    const receipt = api.verify_mimc7(env, credential, challenge, SALT);
    const level = receipt.securityLevel ?? receipt.security_level;
    addResult(true, title, `STARK checked at ${level}-bit security.`, performance.now() - started);
  } catch (error) {
    addResult(false, title, reason(error), performance.now() - started);
  }
}

function flipOneBit(base64) {
  const bytes = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
  // Skip the first 64 bytes of framing so the change lands in proof data, not the header.
  const index = 64 + Math.floor(Math.random() * (bytes.length - 64));
  const bit = Math.floor(Math.random() * 8);
  bytes[index] ^= 1 << bit;
  let out = '';
  for (let i = 0; i < bytes.length; i += 0x8000) out += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return { flipped: btoa(out), index, bit };
}

function freshChallenge() {
  const words = new Uint32Array(4);
  crypto.getRandomValues(words);
  return words;
}

function wire() {
  $('act-verify').addEventListener('click', () =>
    run('The original proof, as published', () => ({ env: envelope, credential: CREDENTIAL, challenge: CHALLENGE })));

  $('act-flip').addEventListener('click', () => {
    const { flipped, index, bit } = flipOneBit(envelope.proofBase64);
    run(`Proof with bit ${bit} of byte ${index.toLocaleString()} flipped`, () => ({
      env: { ...envelope, proofBase64: flipped }, credential: CREDENTIAL, challenge: CHALLENGE,
    }));
  });

  $('act-replay').addEventListener('click', () => {
    const challenge = freshChallenge();
    run(`Same proof, relabelled for challenge ${Array.from(challenge).join(', ')}`, () => ({
      env: { ...envelope, challenge: Array.from(challenge) }, credential: CREDENTIAL, challenge,
    }));
  });

  $('guess-form').addEventListener('submit', (event) => {
    event.preventDefault();
    const guess = $('guess').value;
    if (!guess) return;
    run(`Checked against the credential for “${guess}”`, () => {
      const credential = Array.from(api.credential_mimc7(guess, SALT), (v) => BigInt(v.toString()));
      return { env: envelope, credential, challenge: CHALLENGE };
    });
  });
}

async function boot() {
  stageWall();
  try {
    api = await import(RUNTIME);
    const wasm = await fetch(WASM);
    if (!wasm.ok) throw new Error(`HTTP ${wasm.status} for the verifier`);
    await api.default({ module_or_path: wasm });
    const proofResponse = await fetch(PROOF);
    if (!proofResponse.ok) throw new Error(`HTTP ${proofResponse.status} for the proof file`);
    envelope = parseEnvelope(await proofResponse.text());
    $('st-program').textContent = Array.from(api.mimc_circuit_program_hash(), String).join(', ');
    $('runtime').textContent = `Verifier ready. Proof loaded (${(envelope.proofBase64.length * 0.75 / 1024).toFixed(0)} KB).`;
    for (const id of ['act-verify', 'act-flip', 'act-replay', 'act-guess']) $(id).disabled = false;
    wire();
  } catch (error) {
    $('st-program').textContent = 'Unavailable';
    $('runtime').classList.add('error');
    $('runtime').textContent = `The verifier didn't load (${reason(error)}). Serve the zk-hash-demo folder with the local server described in showcase/README.md, then reload.`;
  }
}

boot();
