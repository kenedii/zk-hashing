import { createServer } from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve, extname, sep } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { schnorr } from '@noble/curves/secp256k1';
import { PARAMETERS, PROTOCOL, challengeMessage } from './protocol.js';

const WEB_ROOT = fileURLToPath(new URL('../web/', import.meta.url));
const ACCOUNT_TTL = 30 * 60_000;
const CHALLENGE_TTL = 2 * 60_000;
const MAX_ACCOUNTS = 1000;
const CSP = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'application/javascript', '.css': 'text/css', '.json': 'application/json', '.wasm': 'application/wasm', '.woff2': 'font/woff2', '.csv': 'text/csv; charset=utf-8', '.ttf': 'font/ttf' };

function fail(status, message) { throw Object.assign(new Error(message), { status }); }
function exactFields(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== fields.length || fields.some((field) => !Object.hasOwn(value, field))) {
    fail(400, 'Unexpected request fields. Passwords and password hashes must stay in the browser.');
  }
}
function hex(value, bytes) { return typeof value === 'string' && new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(value); }
function json(res, status, value) { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(value)); }
async function body(req) {
  if (!req.headers['content-type']?.startsWith('application/json')) fail(415, 'Use application/json.');
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 8192) fail(413, 'Request too large.');
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { fail(400, 'Invalid JSON.'); }
}

export function createDemoServer({ now = Date.now } = {}) {
  // Deliberately ephemeral, bounded demo accounts. No credential material is logged.
  const accounts = new Map();
  const attempts = new Map();
  function prune() {
    const timestamp = now();
    for (const [id, account] of accounts) if (account.expiresAt <= timestamp) accounts.delete(id);
    for (const [ip, record] of attempts) if (record.expiresAt <= timestamp) attempts.delete(ip);
  }
  function stored(account) {
    return { publicKey: account.publicKey, salt: account.salt, parameters: PARAMETERS, expiresAt: account.expiresAt };
  }
  function accountFor(id) {
    const account = typeof id === 'string' ? accounts.get(id) : null;
    if (!account) fail(404, 'This demo account expired. Register again.');
    return account;
  }
  const server = createServer(async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Security-Policy', CSP);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000');
    try {
      const url = new URL(req.url, 'http://localhost');
      if (url.pathname.startsWith('/api/')) {
        prune();
        // Origin checks supplement a strict JSON-only API. No cookies or shared accounts.
        if (req.headers.origin && new URL(req.headers.origin).host !== req.headers.host) fail(403, 'Origin does not match this demo.');
        const ip = req.socket.remoteAddress;
        const record = attempts.get(ip) || { count: 0, expiresAt: now() + 60_000 };
        if (attempts.size >= 2000 && !attempts.has(ip)) fail(429, 'Demo is busy. Try again shortly.');
        attempts.set(ip, record);
        if (++record.count > 120) fail(429, 'Too many demo requests. Wait a minute.');
        if (req.method === 'GET' && url.pathname === '/api/demo/setup') {
          return json(res, 200, { salt: randomBytes(16).toString('hex'), parameters: PARAMETERS, protocol: PROTOCOL });
        }
        if (req.method !== 'POST') fail(405, 'Method not allowed.');
        const data = await body(req);
        if (url.pathname === '/api/demo/register') {
          exactFields(data, ['publicKey', 'salt', 'parameters']);
          if (!hex(data.publicKey, 32) || !hex(data.salt, 16)) fail(400, 'Invalid public key or salt.');
          exactFields(data.parameters, Object.keys(PARAMETERS));
          if (Object.entries(PARAMETERS).some(([key, value]) => data.parameters[key] !== value)) fail(400, 'Unsupported hash settings.');
          try { schnorr.utils.lift_x(BigInt(`0x${data.publicKey}`)); }
          catch { fail(400, 'Invalid public key.'); }
          if (accounts.size >= MAX_ACCOUNTS) fail(503, 'Demo is full. Try again later.');
          const accountId = randomUUID();
          const account = { publicKey: data.publicKey, salt: data.salt, expiresAt: now() + ACCOUNT_TTL, pending: null };
          accounts.set(accountId, account);
          return json(res, 201, { accountId, stored: stored(account), receivedFields: Object.keys(data) });
        }
        if (url.pathname === '/api/demo/challenge') {
          exactFields(data, ['accountId']);
          const account = accountFor(data.accountId);
          account.pending = { challengeId: randomUUID(), challenge: randomBytes(32).toString('hex'), expiresAt: now() + CHALLENGE_TTL };
          return json(res, 200, { ...account.pending, salt: account.salt, parameters: PARAMETERS });
        }
        if (url.pathname === '/api/demo/verify') {
          exactFields(data, ['accountId', 'challengeId', 'proof']);
          if (!hex(data.proof, 64)) fail(400, 'Invalid proof encoding.');
          const account = accountFor(data.accountId);
          const challenge = account.pending;
          if (!challenge || challenge.challengeId !== data.challengeId || challenge.expiresAt <= now()) fail(409, 'Challenge expired, already used, or does not belong to this account.');
          // Consume before verification so both valid and invalid attempts are single use.
          account.pending = null;
          const verified = schnorr.verify(data.proof, challengeMessage(data.accountId, challenge.challengeId, challenge.challenge), account.publicKey);
          return json(res, verified ? 200 : 401, {
            verified, protocol: PROTOCOL, receivedFields: Object.keys(data), stored: stored(account),
            challengeConsumed: true,
            message: verified ? 'Password proof accepted by the server.' : 'Password proof rejected. Try the password you registered.',
          });
        }
        fail(404, 'Unknown API endpoint.');
      }
      if (req.method !== 'GET' && req.method !== 'HEAD') fail(405, 'Method not allowed.');
      let pathname = decodeURIComponent(url.pathname);
      if (pathname.endsWith('/')) pathname += 'index.html';
      const filename = resolve(WEB_ROOT, `.${pathname}`);
      if (!filename.startsWith(WEB_ROOT.endsWith(sep) ? WEB_ROOT : WEB_ROOT + sep)) fail(404, 'Not found.');
      let content;
      try { content = await readFile(filename); }
      catch { fail(404, 'Not found.'); }
      res.writeHead(200, { 'Content-Type': MIME[extname(filename)] || 'application/octet-stream', 'Content-Length': content.length });
      res.end(req.method === 'HEAD' ? undefined : content);
    } catch (error) {
      if (!res.headersSent) json(res, error.status || 500, { error: error.status ? error.message : 'The demo could not complete this request.' });
      else res.end();
    }
  });
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  createDemoServer().listen(Number(process.env.PORT || 8080), '0.0.0.0', () => console.log('zk-hashing demo ready'));
}
