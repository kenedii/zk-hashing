/**
 * db.js — SQLite database layer for Auth Pattern 2 (ZK-Only, no hash storage)
 *
 * Pattern 2 Security Model:
 *   - Client derives h₁ = Argon2id(password, salt) entirely in the browser.
 *   - Client generates a STARK proof over h₁ and sends {proof, mimc_output, username, salt}.
 *   - Server verifies the STARK proof, then computes C = Poseidon(mimc_output, serverPepper)
 *     SERVER-SIDE ONLY.  The client NEVER sees or computes the pepper commitment.
 *   - Server stores {username, pepper_commit=C, argon2_salt, argon2_params} — h₁ is NEVER stored.
 *
 * On login:
 *   - Client re-derives h₁ from password+salt, generates STARK proof, sends proof+mimc_output.
 *   - Server verifies STARK, looks up stored C from DB, independently recomputes
 *     Poseidon(mimc_output, serverPepper) and compares with stored C.
 *   - Authentication succeeds iff both the STARK proof is valid AND the commitment matches.
 *
 * The pepper lives exclusively on the server (env var ZK_SERVER_PEPPER, ideally HSM in
 * production).  The client has zero knowledge of the pepper — it only ever submits
 * mimc_output as a public input, and the pepper is applied server-side after STARK
 * verification.
 *
 * Storage: a single SQLite file at <frontend>/data/zkdemo.db (created on first run).
 * Uses better-sqlite3 (synchronous API) — appropriate for a demo server with low concurrency.
 */

'use strict';

const Database = require('better-sqlite3');
const path     = require('path');
const fs       = require('fs');

// ── DB file location ──────────────────────────────────────────────────────────
// Stored in <frontend>/data/zkdemo.db so it survives server restarts but is
// easy to wipe by deleting the file.  The directory is created if absent.
const DATA_DIR = path.join(__dirname, '..', 'data');
const DB_FILE  = process.env.SQLITE_DB_PATH || path.join(DATA_DIR, 'zkdemo.db');

let db = null;

/**
 * initDB() — Call once at server start (synchronous).
 *
 * Creates the data/ directory and SQLite file if they don't exist, then
 * runs the CREATE TABLE IF NOT EXISTS migration.  Every restart is safe
 * and idempotent — existing data is preserved.
 *
 * Throws on fatal error (bad path, permission denied, etc.) so the server
 * startup fails loudly rather than silently continuing with a broken DB.
 */
function initDB() {
    // Ensure the data directory exists
    if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
    }

    console.log('[db] Opening SQLite database at', DB_FILE);
    db = new Database(DB_FILE);

    // WAL mode: better concurrency for read-heavy workloads and crash safety.
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');

    // ── Schema ────────────────────────────────────────────────────────────────
    // pepper_commit is a BN254 field element as a decimal string (≤78 digits).
    // argon2_params is a JSON string: {time, mem, hashLen}.
    // argon2_salt is the hex-encoded 16-byte salt (public by design; needed by
    // the client to re-derive the same Argon2id output on login).
    db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            username        TEXT    NOT NULL UNIQUE,
            pepper_commit   TEXT    NOT NULL,
            argon2_salt     TEXT    NOT NULL,
            argon2_params   TEXT    NOT NULL,
            created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
            last_login_at   TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
    `);

    console.log('[db] Schema ready (table: users, file: ' + DB_FILE + ')');
}

// ── Query helpers (synchronous — better-sqlite3 style) ────────────────────────

/**
 * getUserByUsername(username) → row | null
 *
 * Returns the full users row for `username`, or null if no such user.
 * argon2_params is parsed from JSON before returning.
 */
function getUserByUsername(username) {
    const row = db.prepare(
        'SELECT id, username, pepper_commit, argon2_salt, argon2_params, created_at, last_login_at ' +
        'FROM users WHERE username = ? LIMIT 1'
    ).get(username);

    if (!row) return null;
    // Parse stored JSON so callers get a plain object, not a string.
    try { row.argon2_params = JSON.parse(row.argon2_params); } catch (_) {}
    return row;
}

/**
 * createUser({ username, pepper_commit, argon2_salt, argon2_params })
 *
 * Inserts a new user row.  Throws if the username is already taken.
 * argon2_params must be a plain object — JSON.stringify()'d before storage.
 */
function createUser({ username, pepper_commit, argon2_salt, argon2_params }) {
    if (!username || !pepper_commit || !argon2_salt || !argon2_params) {
        throw new Error('createUser: all fields are required');
    }
    db.prepare(
        'INSERT INTO users (username, pepper_commit, argon2_salt, argon2_params) VALUES (?, ?, ?, ?)'
    ).run(username, pepper_commit, argon2_salt, JSON.stringify(argon2_params));
}

/**
 * touchLastLogin(username) — update last_login_at timestamp on success.
 * Best-effort: failure is silently swallowed.
 */
function touchLastLogin(username) {
    try {
        db.prepare("UPDATE users SET last_login_at = datetime('now') WHERE username = ?").run(username);
    } catch (_) { /* non-fatal */ }
}

/**
 * usernameExists(username) → boolean
 * Cheap existence check without fetching the full row.
 */
function usernameExists(username) {
    const row = db.prepare('SELECT 1 FROM users WHERE username = ? LIMIT 1').get(username);
    return row !== undefined;
}

module.exports = { initDB, getUserByUsername, createUser, touchLastLogin, usernameExists };
