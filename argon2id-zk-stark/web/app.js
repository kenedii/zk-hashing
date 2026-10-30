import { parseEnvelope } from './envelope-json.js?v=20260814.2';

const $ = (id) => document.getElementById(id);
const bundleVersion = '20260814.2';
const fullArgonMinimumCycles = 19_593_971;
const measuredTraceBytes = 109_521_666_048;
const estimatedCycles = { argon2id: fullArgonMinimumCycles, bcrypt2b: 367_224_034, mimc7: 430_204 };
let wasmApi = null;
let programHashes = null;

function algorithm() { return $('algorithm').value; }

function values() {
  const challenge = $('challenge').value.split(',').map((part) => Number(part.trim()));
  if (challenge.length !== 4 || challenge.some((part) => !Number.isInteger(part) || part < 0 || part > 0xffffffff)) {
    throw new Error('Challenge must contain exactly four unsigned 32-bit integers.');
  }
  return {
    algorithm: algorithm(), password: $('password').value, salt: $('salt').value.trim(),
    memory: Number($('memory').value), passes: Number($('passes').value), lanes: Number($('lanes').value),
    cost: Number($('bcrypt-cost').value), challenge,
  };
}

function asStrings(value) { return Array.from(value, (item) => item.toString()); }
function writeCredential(value) { $('credential').value = asStrings(value).join(', '); }
function readCredential() {
  const parts = $('credential').value.split(/[\s,·]+/).filter(Boolean);
  if (parts.length !== 4 || parts.some((part) => !/^\d+$/.test(part))) {
    throw new Error('Expected credential must contain exactly four unsigned decimal field elements.');
  }
  return parts.map(BigInt);
}
function json(value) { return JSON.stringify(value, (_, item) => typeof item === 'bigint' ? item.toString() : item, 2); }
function log(message, error = false) {
  $('log').textContent = message;
  $('log').style.color = error ? '#ff8a8a' : '#a9b8c4';
}

function nativeCommand() {
  try {
    const v = values();
    const prefix = '.\\native-prover\\argon2id-zk-prover.exe';
    const quotedPassword = `'${v.password.replaceAll("'", "''")}'`;
    const c = v.challenge.join(' ');
    if (v.algorithm === 'argon2id') return `${prefix} prove ${quotedPassword} ${v.salt} ${v.memory} ${v.passes} ${v.lanes} ${c} --out proof.json`;
    if (v.algorithm === 'bcrypt2b') return `${prefix} prove-bcrypt ${quotedPassword} ${v.salt} ${v.cost} ${c} --out proof.json`;
    return `${prefix} prove-mimc ${quotedPassword} ${v.salt} ${c} --out proof.json`;
  } catch (_) { return 'Complete the fields to generate a command.'; }
}

function updateEstimate() {
  try {
    const v = values();
    let cycles = estimatedCycles[v.algorithm];
    if (v.algorithm === 'argon2id') cycles *= Math.max(1, (v.memory / 8) * v.passes * Math.max(1, v.lanes));
    if (v.algorithm === 'bcrypt2b') cycles *= 2 ** Math.max(0, v.cost - 4);
    const rows = 2 ** Math.ceil(Math.log2(cycles));
    const bytesPerRow = measuredTraceBytes / (2 ** 25);
    const ram = rows * bytesPerRow;
    $('cycles').textContent = Math.ceil(cycles).toLocaleString();
    $('rows').textContent = rows.toExponential(2);
    $('ram').textContent = ram >= 2 ** 50 ? `${(ram / 2 ** 50).toFixed(2)} PiB` : ram >= 2 ** 40 ? `${(ram / 2 ** 40).toFixed(2)} TiB` : ram >= 2 ** 30 ? `${(ram / 2 ** 30).toFixed(1)} GiB` : `${(ram / 2 ** 20).toFixed(0)} MiB`;
    if (v.algorithm === 'mimc7') $('ram').textContent = '≈ 4.0 GiB observed in Chromium';
    $('native-command').textContent = nativeCommand();
  } catch (_) {
    $('cycles').textContent = $('rows').textContent = $('ram').textContent = 'invalid input';
  }
}

function syncProveButton() {
  $('prove-button').disabled = true;
}

function updateAlgorithm() {
  const a = algorithm();
  $('argon-params').classList.toggle('hidden', a !== 'argon2id');
  $('bcrypt-params').classList.toggle('hidden', a !== 'bcrypt2b');
  $('mimc-params').classList.toggle('hidden', a !== 'mimc7');
  $('algorithm-summary').textContent = a === 'argon2id' ? 'Argon2id v=19' : a === 'bcrypt2b' ? 'bcrypt 2b / EksBlowfish' : 'MiMC-7 · 220 rounds';
  $('credential-button').textContent = a === 'argon2id' ? 'Run Argon2id & compute credential' : a === 'bcrypt2b' ? 'Run bcrypt & compute credential' : 'Run MiMC & compute credential';
  if (programHashes) $('program-hash').textContent = programHashes[a].join(' · ');
  if (a === 'argon2id') {
    $('notice-title').textContent = 'Argon2id proving requirement';
    $('notice-body').textContent = 'The full RFC 9106 circuit measured 19,593,971 cycles even at the 8 KiB minimum. Its 2^25-row trace made the generic Miden prover request about 102 GiB, before normal process overhead. The executable contains this exact circuit, but 128 GiB is still marginal; browser proving is disabled. Imported proofs verify quickly.';
    $('cycle-summary').textContent = 'proof RAM ≈ 102 GiB';
  } else if (a === 'bcrypt2b') {
    $('notice-title').textContent = 'Full bcrypt is much larger than Argon2id here';
    $('notice-body').textContent = 'Cost 4 executes the complete EksBlowfish schedule in 367,224,034 VM cycles (2^29 padded rows). Generic proving is estimated near 1.6 TiB of RAM, so the native executable can execute it but this 128 GiB machine cannot produce its STARK. Cost 4 is demonstration-only and unsuitable for password storage.';
    $('cycle-summary').textContent = 'proof RAM ≈ 1.6 TiB';
  } else {
    $('notice-title').textContent = 'MiMC full proof works in the native executable';
    $('notice-body').textContent = 'All 220 MiMC-7 rounds and the password/salt absorption execute inside Miden. Native proving completed in about 39 seconds. An actual Chromium attempt reached the wasm32 4 GiB memory ceiling and stalled, so browser proving is disabled; import the native proof for fast local verification. MiMC is not memory-hard.';
    $('cycle-summary').textContent = 'native proof · browser verifies';
  }
  $('browser-consent').classList.add('hidden');
  $('prove-button').textContent = 'Generate proof with Windows executable';
  $('prove-button').className = 'danger';
  $('unlock').checked = false;
  $('credential').value = '';
  syncProveButton();
  updateEstimate();
}

async function busy(button, label, work) {
  const previous = button.textContent;
  button.disabled = true;
  button.textContent = label;
  try { return await work(); }
  finally {
    button.textContent = previous;
    if (button === $('prove-button')) syncProveButton(); else button.disabled = false;
  }
}

async function computeCredential() {
  await busy($('credential-button'), 'Computing…', async () => {
    const v = values();
    const started = performance.now();
    let result;
    if (v.algorithm === 'argon2id') result = wasmApi.credential_argon2id(v.password, v.salt, v.memory, v.passes, v.lanes);
    else if (v.algorithm === 'bcrypt2b') result = wasmApi.credential_bcrypt2b(v.password, v.salt, v.cost);
    else result = wasmApi.credential_mimc7(v.password, v.salt);
    writeCredential(result);
    log(`Credential computed locally in ${(performance.now() - started).toFixed(1)} ms. The password was not serialized into the proof envelope.`);
  });
}

async function verify() {
  await busy($('verify-button'), 'Verifying STARK…', async () => {
    const v = values();
    const expectedCredential = readCredential();
    const envelope = parseEnvelope($('proof').value);
    let receipt;
    if (v.algorithm === 'argon2id') receipt = wasmApi.verify_argon2id(envelope, expectedCredential, v.challenge, v.salt, v.memory, v.passes, v.lanes);
    else if (v.algorithm === 'bcrypt2b') receipt = wasmApi.verify_bcrypt2b(envelope, expectedCredential, v.challenge, v.salt, v.cost);
    else receipt = wasmApi.verify_mimc7(envelope, expectedCredential, v.challenge, v.salt);
    log(`Proof accepted at security level ${receipt.securityLevel}.\n${json(receipt)}`);
  });
}

async function main() {
  try {
    $('program-hash').textContent = 'fetching local runtime…';
    wasmApi = await import(`./pkg/argon2id_zk_runtime.js?v=${bundleVersion}`);
    const response = await fetch(`./pkg/argon2id_zk_runtime_bg.wasm?v=${bundleVersion}`, { cache: 'no-store' });
    if (!response.ok) throw new Error(`Wasm download failed: HTTP ${response.status}`);
    await wasmApi.default({ module_or_path: response });
    programHashes = {
      argon2id: asStrings(wasmApi.circuit_program_hash()),
      bcrypt2b: asStrings(wasmApi.bcrypt_circuit_program_hash()),
      mimc7: asStrings(wasmApi.mimc_circuit_program_hash()),
    };
    $('wasm-status').textContent = 'Wasm ready';
    $('wasm-status').classList.add('ready');
  } catch (error) {
    wasmApi = null;
    $('wasm-status').textContent = 'load failed';
    $('program-hash').textContent = 'WebAssembly failed to initialize';
    log(`WebAssembly startup error: ${error instanceof Error ? error.message : String(error)}`, true);
    return;
  }

  $('algorithm').addEventListener('change', updateAlgorithm);
  $('credential-button').addEventListener('click', () => computeCredential().catch((error) => log(String(error), true)));
  $('verify-button').addEventListener('click', () => verify().catch((error) => log(String(error), true)));
  $('unlock').addEventListener('change', syncProveButton);
  $('copy-command').addEventListener('click', async () => {
    await navigator.clipboard.writeText($('native-command').textContent);
    log('Native prover command copied.');
  });
  $('proof-file').addEventListener('change', async (event) => {
    const [file] = event.target.files;
    if (!file) return;
    $('proof').value = await file.text();
    log(`Loaded ${file.name}. Compute the expected credential, then verify it against the selected fields.`);
  });
  $('preset-production').addEventListener('click', () => {
    $('memory').value = '65536'; $('passes').value = '3'; $('lanes').value = '4'; updateEstimate();
  });
  for (const id of ['password', 'salt', 'memory', 'passes', 'lanes', 'bcrypt-cost', 'challenge']) $(id).addEventListener('input', updateEstimate);
  updateAlgorithm();
}

main();
