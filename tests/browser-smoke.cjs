const { chromium } = require('playwright-core');
const path = require('path');

const root = path.resolve(__dirname, '..');
const baseUrl = process.env.ZK_DEMO_URL || 'http://127.0.0.1:4173/lab/';
const expected = {
  argon2id: {
    programHash: '7414375205037963537 · 6936894371163969737 · 5606295635567605248 · 14554023635893857426',
    credential: '14003553230994514291, 17501336355793343691, 14150596336398746883, 11817552983452184436',
  },
  bcrypt2b: {
    programHash: '5380308799974435194 · 17174608301180550111 · 15788955599884494609 · 8070629447958685485',
    credential: '7211476120096127609, 6315364460697531817, 10986676318847474483, 15165701513619436781',
  },
  mimc7: {
    programHash: '3706684623668685261 · 3213429259195923014 · 3585804632091340585 · 11041704685863744209',
    credential: '8370215289663149514, 8090811050392849221, 9444347110279816554, 1235188709954996380',
  },
};

function check(condition, message) {
  if (!condition) throw new Error(message);
}

async function selectAndCredential(page, algorithm) {
  await page.selectOption('#algorithm', algorithm);
  await page.waitForFunction(
    ({ hash }) => document.querySelector('#program-hash')?.textContent === hash,
    { hash: expected[algorithm].programHash },
  );
  await page.click('#credential-button');
  await page.waitForFunction(
    ({ credential }) => document.querySelector('#credential')?.value === credential,
    { credential: expected[algorithm].credential },
  );
}

(async () => {
  const browser = await chromium.launch({
    executablePath: process.env.BROWSER_EXE || 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
    headless: true,
  });
  const page = await browser.newPage();
  const diagnostics = [];
  page.on('console', (message) => {
    if (message.type() === 'error') diagnostics.push(`console: ${message.text()}`);
  });
  page.on('pageerror', (error) => diagnostics.push(`pageerror: ${error.message}`));

  try {
    const response = await page.goto(baseUrl, { waitUntil: 'networkidle', timeout: 120_000 });
    check(response?.ok(), `page returned HTTP ${response?.status()}`);
    await page.waitForFunction(() => document.querySelector('#wasm-status')?.textContent === 'Wasm ready', null, { timeout: 120_000 });
    check(await page.textContent('#program-hash') === expected.argon2id.programHash, 'Argon2id program hash did not render');

    await selectAndCredential(page, 'argon2id');
    check(await page.locator('#browser-consent').evaluate((node) => node.classList.contains('hidden')), 'Argon2id browser prover should be disabled');

    await selectAndCredential(page, 'bcrypt2b');
    check(await page.textContent('#cycles') === '367,224,034', 'bcrypt cycle count is not the measured value');
    check((await page.textContent('#ram')).includes('TiB'), 'bcrypt RAM warning is missing');

    await selectAndCredential(page, 'mimc7');
    check(await page.locator('#browser-consent').evaluate((node) => node.classList.contains('hidden')), 'unsafe MiMC browser prover opt-in is visible');
    check(await page.isDisabled('#prove-button'), 'browser prover should be disabled after the 4 GiB limit was measured');
    check(await page.textContent('#cycles') === '430,204', 'MiMC cycle count is not the measured value');
    check((await page.textContent('#native-command')).includes('prove-mimc'), 'native MiMC command is missing');

    const proofPath = path.join(root, 'web', 'proofs', 'mimc-proof.json');
    await page.setInputFiles('#proof-file', proofPath);
    await page.click('#verify-button');
    await page.waitForFunction(() => document.querySelector('#log')?.textContent.includes('Proof accepted at security level 96.'), null, { timeout: 120_000 });

    const tamperedPath = path.join(root, 'web', 'proofs', 'mimc-proof-tampered.json');
    await page.setInputFiles('#proof-file', tamperedPath);
    await page.click('#verify-button');
    await page.waitForFunction(() => {
      const text = document.querySelector('#log')?.textContent || '';
      return text.includes('Error') || text.includes('invalid') || text.includes('failed') || text.includes('verification');
    }, null, { timeout: 120_000 });
    check(!(await page.textContent('#log')).includes('Proof accepted'), 'tampered proof was accepted');

    if (process.env.SMOKE_SCREENSHOT) await page.screenshot({ path: process.env.SMOKE_SCREENSHOT, fullPage: true });
    check(diagnostics.length === 0, diagnostics.join('\n'));
    console.log(JSON.stringify({
      ok: true,
      wasmStatus: await page.textContent('#wasm-status'),
      algorithm: await page.inputValue('#algorithm'),
      credential: await page.inputValue('#credential'),
      tamperedResult: await page.textContent('#log'),
      diagnostics,
    }, null, 2));
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
