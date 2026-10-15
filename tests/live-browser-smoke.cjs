const assert = require('node:assert/strict');
const { chromium } = require('playwright-core');

(async () => {
  const browser = await chromium.launch({ executablePath: process.env.BROWSER_EXE || 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe', headless: true });
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  const errors = [];
  const requests = [];
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('request', (request) => { if (request.url().includes('/api/demo/')) requests.push({ url: request.url(), body: request.postData() }); });
  try {
    const base = (process.env.ZK_DEMO_URL || 'http://127.0.0.1:8080/').replace(/\/?$/, '/');
    await page.goto(`${base}password-demo.html`, { waitUntil: 'networkidle' });
    const password = 'browser demo secret ☕';
    await page.fill('#register-password', password);
    await page.click('#register-button');
    await page.locator('#live-status[data-state="ready"]').waitFor();
    assert.equal(await page.inputValue('#register-password'), '');
    await page.fill('#login-password', password);
    await page.click('#login-button');
    await page.locator('#live-status[data-state="accepted"]').waitFor();
    const hash = await page.textContent('#local-hash');
    assert.match(hash, /^[0-9a-f]{64}$/);
    const record = JSON.parse(await page.textContent('#server-record'));
    assert.deepEqual(Object.keys(record).sort(), ['expiresAt', 'parameters', 'publicKey', 'salt']);
    await page.click('#replay-button');
    await page.locator('#live-status').filter({ hasText: /^Replay rejected by the server/ }).waitFor();
    await page.fill('#login-password', 'wrong password');
    await page.click('#login-button');
    await page.locator('#live-status').filter({ hasText: /^Rejected by the server\./ }).waitFor();
    await page.fill('#login-password', password);
    await page.click('#login-button');
    await page.locator('#live-status[data-state="accepted"]').waitFor();
    for (const request of requests) {
      assert.ok(!request.body?.includes(password), 'password was sent over the network');
      assert.ok(!request.body?.includes(hash), 'Argon2id hash was sent over the network');
      if (!request.body) continue;
      const data = JSON.parse(request.body);
      if (request.url.endsWith('/register')) assert.deepEqual(Object.keys(data), ['publicKey', 'salt', 'parameters']);
      if (request.url.endsWith('/verify')) assert.deepEqual(Object.keys(data), ['accountId', 'challengeId', 'proof']);
    }
    if (process.env.SMOKE_SCREENSHOT) await page.locator('.live-section').screenshot({ path: process.env.SMOKE_SCREENSHOT });
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, 'mobile page overflows');
    if (process.env.SMOKE_MOBILE_SCREENSHOT) await page.locator('.live-section').screenshot({ path: process.env.SMOKE_MOBILE_SCREENSHOT });
    // The full STARK verifier must still accept the published proof.
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.goto(`${base}verify.html`, { waitUntil: 'networkidle' });
    await page.locator('#act-verify:not([disabled])').waitFor({ timeout: 120000 });
    await page.click('#act-verify');
    await page.locator('#results .accepted').waitFor();
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({ ok: true, verified: true, wrongPasswordRejected: true, replayRejected: true, secretAbsentFromRequests: true, starkVerifierWorking: true, apiRequests: requests.length }, null, 2));
  } finally { await browser.close(); }
})().catch((error) => { console.error(error.stack || error); process.exitCode = 1; });
