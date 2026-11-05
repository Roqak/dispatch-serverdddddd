-- dispatch-server on Cloudflare Workers: D1 schema.
-- Mirrors server/src/db.rs::migrate() exactly (CREATE TABLE IF NOT EXISTS;
-- idempotent, safe to re-apply with: npx wrangler d1 execute dispatch-server --remote --file schema.sql
-- or `--local` while running `wrangler dev`, both from worker/).

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    workspace_grants TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
-- Where each collection/environment uid lives, learned from every
-- per-workspace list/create/delete that the proxy sees.
CREATE TABLE IF NOT EXISTS collections_map (
    uid TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    name TEXT,
    updated_at TEXT
);
CREATE TABLE IF NOT EXISTS environments_map (
    uid TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    name TEXT,
    updated_at TEXT
);
-- Postman accounts an admin connected. key_ciphertext is AES-256-GCM under
-- SECRET_KEY; the plain key is never stored or returned.
CREATE TABLE IF NOT EXISTS postman_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL,
    region TEXT NOT NULL,
    key_ciphertext TEXT NOT NULL,
    key_hint TEXT NOT NULL,
    postman_user_id TEXT,
    postman_name TEXT,
    created_by TEXT,
    created_at TEXT NOT NULL
);
-- Which accounts reach which workspace, refreshed from Postman's own lists.
-- account_id 0 is the POSTMAN_API_KEY setting.
CREATE TABLE IF NOT EXISTS workspace_accounts (
    workspace_id TEXT NOT NULL,
    account_id INTEGER NOT NULL,
    name TEXT,
    type TEXT,
    PRIMARY KEY (workspace_id, account_id)
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    user_id INTEGER,
    email TEXT,
    action TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status INTEGER NOT NULL
);