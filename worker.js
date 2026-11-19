// StarGG license Worker + dashboard - single-file build (paste into the Cloudflare dashboard editor)

// ===== lib.js =====
// Shared helpers: responses, crypto, validation, rate limiting, audit log.
// Only Web Crypto + fetch APIs are used, so the same code runs on Workers and Node (tests).

const enc = new TextEncoder();

const TOKEN_TTL_SECONDS = 12 * 60 * 60; // 12 hours
const MAX_BODY_BYTES = 2048;

// ------------------------------------------------------------------ responses
// No CORS headers are ever set: browsers on other origins cannot call this API.
const BASE_HEADERS = {
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
};

function json(status, body, extra = {}) {
  return new Response(JSON.stringify(body), { status, headers: { ...BASE_HEADERS, ...extra } });
}

const ok = (body = {}) => json(200, { ok: true, ...body });
const fail = (status, error, extra) => json(status, { ok: false, error }, extra);

// ------------------------------------------------------------------ encoding
function b64urlEncode(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(str) {
  const pad = '='.repeat((4 - (str.length % 4)) % 4);
  const bin = atob(str.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function toHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// ------------------------------------------------------------------ crypto
async function hmacKey(secret, usages) {
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, usages);
}

async function hmacHex(secret, message) {
  const key = await hmacKey(secret, ['sign']);
  return toHex(await crypto.subtle.sign('HMAC', key, enc.encode(message)));
}

async function sha256Hex(message) {
  return toHex(await crypto.subtle.digest('SHA-256', enc.encode(message)));
}

/** Constant-time string comparison. Both inputs are hashed first, so length is not leaked either. */
async function safeEqual(a, b) {
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest('SHA-256', enc.encode(String(a))),
    crypto.subtle.digest('SHA-256', enc.encode(String(b))),
  ]);
  const x = new Uint8Array(ha);
  const y = new Uint8Array(hb);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

// ------------------------------------------------------------------ license keys
// 31 symbols, no 0/O/1/I/L. 12 symbols = ~59 bits of entropy.
const KEY_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const KEY_RE = /^STAR-[A-HJKMNP-Z2-9]{4}-[A-HJKMNP-Z2-9]{4}-[A-HJKMNP-Z2-9]{4}$/;

function randomSymbols(n) {
  const out = [];
  const limit = 256 - (256 % KEY_ALPHABET.length); // rejection sampling: no modulo bias
  while (out.length < n) {
    const bytes = crypto.getRandomValues(new Uint8Array(n * 2));
    for (const b of bytes) {
      if (b < limit && out.length < n) out.push(KEY_ALPHABET[b % KEY_ALPHABET.length]);
    }
  }
  return out.join('');
}

function generateKey() {
  const s = randomSymbols(12);
  return `STAR-${s.slice(0, 4)}-${s.slice(4, 8)}-${s.slice(8, 12)}`;
}

/** Returns the canonical key (upper case, trimmed) or null if it is not a well-formed key. */
function normalizeKey(input) {
  if (typeof input !== 'string' || input.length > 40) return null;
  const k = input.trim().toUpperCase();
  return KEY_RE.test(k) ? k : null;
}

function hashKey(env, key) {
  return hmacHex(env.KEY_SALT, 'key:' + key);
}

// ------------------------------------------------------------------ validation
const RESERVED_NAMES = new Set(['admin', 'administrator', 'owner', 'staff', 'support', 'system', 'moderator', 'stargg', 'null', 'undefined']);

/** Lower-cases and validates an account name. Returns the name or null. */
function normalizeAccountName(input) {
  if (typeof input !== 'string') return null;
  const n = input.trim().toLowerCase();
  if (!/^[a-z0-9_]{3,16}$/.test(n)) return null;
  if (RESERVED_NAMES.has(n)) return null;
  return n;
}

function validDeviceHash(h) {
  return typeof h === 'string' && /^[0-9a-f]{64}$/.test(h);
}

/** Reads a small JSON object body. Returns the object or null. */
async function readJson(request) {
  const type = request.headers.get('content-type') || '';
  if (!type.toLowerCase().includes('application/json')) return null;
  const text = await request.text();
  if (text.length > MAX_BODY_BYTES) return null;
  try {
    const v = JSON.parse(text);
    return v && typeof v === 'object' && !Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}

const nowSeconds = () => Math.floor(Date.now() / 1000);

/** Accepts unix seconds or an ISO date string; returns unix seconds or null. */
function parseTime(v) {
  if (typeof v === 'number' && Number.isFinite(v) && v > 0) return Math.floor(v);
  if (typeof v === 'string' && v.length < 40) {
    const t = Date.parse(v);
    if (!Number.isNaN(t)) return Math.floor(t / 1000);
  }
  return null;
}

/** active / disabled / expired, taking expires_at into account. */
function effectiveStatus(row, now = nowSeconds()) {
  if (row.status === 'disabled') return 'disabled';
  if (row.status === 'expired') return 'expired';
  if (row.expires_at !== null && row.expires_at !== undefined && now >= row.expires_at) return 'expired';
  return 'active';
}

// ------------------------------------------------------------------ tokens (HMAC-SHA256)
async function signToken(env, payload) {
  const body = b64urlEncode(enc.encode(JSON.stringify(payload)));
  const key = await hmacKey(env.TOKEN_SECRET, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(body)));
  return `${body}.${b64urlEncode(sig)}`;
}

/** Returns the payload, or null if the token is malformed, forged or expired. */
async function verifyToken(env, token) {
  if (typeof token !== 'string' || token.length > 600) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  try {
    const key = await hmacKey(env.TOKEN_SECRET, ['verify']);
    // subtle.verify compares in constant time
    const valid = await crypto.subtle.verify('HMAC', key, b64urlDecode(parts[1]), enc.encode(parts[0]));
    if (!valid) return null;
    const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[0])));
    if (payload.v !== 1 || typeof payload.exp !== 'number' || payload.exp <= nowSeconds()) return null;
    return payload;
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------ request helpers
function clientIp(request) {
  return request.headers.get('cf-connecting-ip') || 'unknown';
}

function ipHash(env, ip) {
  return hmacHex(env.KEY_SALT, 'ip:' + ip).then((h) => h.slice(0, 24));
}

/**
 * Fixed-window rate limit stored in D1 (free, works locally).
 * Returns { allowed, retryAfter }.
 */
async function rateLimit(env, request, route, limit, windowSeconds) {
  const now = nowSeconds();
  const windowStart = now - (now % windowSeconds);
  const bucket = `${route}:${await ipHash(env, clientIp(request))}`;
  const row = await env.DB.prepare(
    `INSERT INTO rate_limits (bucket, window_start, count) VALUES (?1, ?2, 1)
     ON CONFLICT(bucket) DO UPDATE SET
       count = CASE WHEN window_start = ?2 THEN count + 1 ELSE 1 END,
       window_start = ?2
     RETURNING count`,
  ).bind(bucket, windowStart).first();
  const count = row ? row.count : 1;
  return { allowed: count <= limit, retryAfter: windowStart + windowSeconds - now };
}

/** Writes an audit row without delaying the response. Never throws. */
function audit(env, ctx, request, event, licenseId = null, detail = null) {
  const work = (async () => {
    try {
      const now = nowSeconds();
      await env.DB.prepare('INSERT INTO audit_log (ts, event, license_id, ip_hash, detail) VALUES (?1, ?2, ?3, ?4, ?5)')
        .bind(now, event, licenseId, await ipHash(env, clientIp(request)), detail ? String(detail).slice(0, 200) : null)
        .run();
      // housekeeping, roughly once per 100 writes: drop old audit and rate-limit rows
      if (Math.random() < 0.01) {
        await env.DB.batch([
          env.DB.prepare('DELETE FROM audit_log WHERE ts < ?1').bind(now - 90 * 86400),
          env.DB.prepare('DELETE FROM rate_limits WHERE window_start < ?1').bind(now - 86400),
        ]);
      }
    } catch (e) {
      console.error('audit failed', e && e.message);
    }
  })();
  if (ctx && ctx.waitUntil) ctx.waitUntil(work);
  return work;
}

// ===== auth.js =====
// /auth/* endpoints used by the Minecraft client.

const LOGIN_LIMIT = [20, 60];   // 20 attempts / minute / IP
const REDEEM_LIMIT = [10, 600]; // 10 attempts / 10 minutes / IP
const CHECK_LIMIT = [60, 60];

async function limited(env, request, route, [limit, window]) {
  const r = await rateLimit(env, request, route, limit, window);
  return r.allowed ? null : fail(429, 'rate_limited', { 'retry-after': String(r.retryAfter) });
}

async function findByKey(env, key) {
  return env.DB.prepare('SELECT * FROM licenses WHERE key_hash = ?1').bind(await hashKey(env, key)).first();
}

/** Returns an error Response if the license may not be used right now, otherwise null. */
async function statusError(env, row) {
  const status = effectiveStatus(row);
  if (status === 'active') return null;
  if (status === 'expired' && row.status !== 'expired') {
    // remember it, so the list view shows the truth
    await env.DB.prepare("UPDATE licenses SET status = 'expired' WHERE id = ?1 AND status = 'active'").bind(row.id).run();
  }
  return fail(403, status);
}

/**
 * Binds the device atomically: an existing device is refreshed, a new one is only inserted
 * while the license still has a free slot (single SQL statement, so no race can exceed the limit).
 */
async function bindDevice(env, licenseId, deviceHash) {
  const now = nowSeconds();
  const existing = await env.DB.prepare('UPDATE devices SET last_seen = ?3 WHERE license_id = ?1 AND device_hash = ?2')
    .bind(licenseId, deviceHash, now).run();
  if (existing.meta.changes > 0) return true;
  const inserted = await env.DB.prepare(
    `INSERT INTO devices (license_id, device_hash, first_seen, last_seen)
     SELECT ?1, ?2, ?3, ?3
     WHERE (SELECT COUNT(*) FROM devices WHERE license_id = ?1) < (SELECT max_devices FROM licenses WHERE id = ?1)`,
  ).bind(licenseId, deviceHash, now).run();
  return inserted.meta.changes > 0;
}

async function issueSession(env, row, deviceHash) {
  const now = nowSeconds();
  const exp = now + TOKEN_TTL_SECONDS;
  const token = await signToken(env, { v: 1, lid: row.id, dev: deviceHash, acc: row.account_name, iat: now, exp });
  await env.DB.prepare('UPDATE licenses SET last_login = ?2, last_seen = ?2 WHERE id = ?1').bind(row.id, now).run();
  return ok({ token, account: row.account_name, exp, expires_at: row.expires_at ?? null });
}

// ------------------------------------------------------------------ POST /auth/redeem
async function redeem(request, env, ctx) {
  const blocked = await limited(env, request, 'redeem', REDEEM_LIMIT);
  if (blocked) return blocked;

  const body = await readJson(request);
  if (!body) return fail(400, 'bad_request');
  const key = normalizeKey(body.key);
  const name = normalizeAccountName(body.account_name);
  if (!validDeviceHash(body.device_hash)) return fail(400, 'bad_request');
  if (!key) return fail(401, 'invalid_key');
  if (!name) return fail(400, 'invalid_name');

  const row = await findByKey(env, key);
  if (!row) return fail(401, 'invalid_key');
  const bad = await statusError(env, row);
  if (bad) return bad;
  if (row.account_name !== null) return fail(409, 'already_redeemed');

  try {
    const res = await env.DB.prepare('UPDATE licenses SET account_name = ?2 WHERE id = ?1 AND account_name IS NULL')
      .bind(row.id, name).run();
    if (res.meta.changes === 0) return fail(409, 'already_redeemed');
  } catch (e) {
    if (String(e && e.message).includes('UNIQUE')) return fail(409, 'name_taken');
    throw e;
  }

  if (!(await bindDevice(env, row.id, body.device_hash))) return fail(403, 'device_limit');
  audit(env, ctx, request, 'redeem', row.id, name);
  return issueSession(env, { ...row, account_name: name }, body.device_hash);
}

// ------------------------------------------------------------------ POST /auth/login
async function login(request, env, ctx) {
  const blocked = await limited(env, request, 'login', LOGIN_LIMIT);
  if (blocked) return blocked;

  const body = await readJson(request);
  if (!body) return fail(400, 'bad_request');
  const key = normalizeKey(body.key);
  if (!validDeviceHash(body.device_hash)) return fail(400, 'bad_request');
  if (!key) return fail(401, 'invalid_key');

  const row = await findByKey(env, key);
  if (!row) return fail(401, 'invalid_key');
  const bad = await statusError(env, row);
  if (bad) return bad;
  if (row.account_name === null) return fail(409, 'needs_redeem');

  if (!(await bindDevice(env, row.id, body.device_hash))) {
    audit(env, ctx, request, 'device_limit', row.id);
    return fail(403, 'device_limit');
  }
  audit(env, ctx, request, 'login', row.id);
  return issueSession(env, row, body.device_hash);
}

// ------------------------------------------------------------------ GET /auth/check
async function check(request, env) {
  const blocked = await limited(env, request, 'check', CHECK_LIMIT);
  if (blocked) return blocked;

  const header = request.headers.get('authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7).trim() : '';
  const payload = await verifyToken(env, token);
  if (!payload) return fail(401, 'bad_token');

  // Re-check the live state, so disabling / expiring / resetting devices takes effect right away.
  const row = await env.DB.prepare('SELECT * FROM licenses WHERE id = ?1').bind(payload.lid).first();
  if (!row || row.account_name === null || row.account_name !== payload.acc) return fail(401, 'bad_token');
  const bad = await statusError(env, row);
  if (bad) return bad;
  const device = await env.DB.prepare('SELECT 1 AS x FROM devices WHERE license_id = ?1 AND device_hash = ?2')
    .bind(row.id, payload.dev).first();
  if (!device) return fail(403, 'device_removed');

  await env.DB.prepare('UPDATE licenses SET last_seen = ?2 WHERE id = ?1').bind(row.id, nowSeconds()).run();
  return ok({ account: row.account_name, exp: payload.exp, expires_at: row.expires_at ?? null });
}

// ===== admin.js =====
// /admin/* endpoints. Protected by `Authorization: Bearer <ADMIN_SECRET>`.

const DAY = 86400;
/** A client counts as online if it checked in within this many seconds (it checks every ~10 minutes). */
const ONLINE_WINDOW = 15 * 60;

async function authorize(request, env) {
  // brute-force protection for the admin secret: 30 requests / minute / IP
  const rl = await rateLimit(env, request, 'admin', 30, 60);
  if (!rl.allowed) return fail(429, 'rate_limited', { 'retry-after': String(rl.retryAfter) });
  const header = request.headers.get('authorization') || '';
  const given = header.startsWith('Bearer ') ? header.slice(7).trim() : '';
  if (!env.ADMIN_SECRET || !(await safeEqual(given, env.ADMIN_SECRET))) return fail(401, 'unauthorized');
  return null;
}

function publicRow(row, deviceCount) {
  return {
    id: row.id,
    account_name: row.account_name,
    status: effectiveStatus(row),
    stored_status: row.status,
    expires_at: row.expires_at,
    max_devices: row.max_devices,
    devices: deviceCount ?? undefined,
    note: row.note,
    created_at: row.created_at,
    last_login: row.last_login,
    last_seen: row.last_seen ?? null,
    online: row.last_seen != null && nowSeconds() - row.last_seen < ONLINE_WINDOW,
  };
}

async function handleAdmin(request, env, ctx, url, path) {
  const denied = await authorize(request, env);
  if (denied) return denied;

  const method = request.method;

  // GET /admin/keys
  if (method === 'GET' && path === '/admin/keys') {
    const limit = Math.min(Math.max(parseInt(url.searchParams.get('limit') || '100', 10) || 100, 1), 500);
    const offset = Math.max(parseInt(url.searchParams.get('offset') || '0', 10) || 0, 0);
    const { results } = await env.DB.prepare(
      `SELECT l.*, (SELECT COUNT(*) FROM devices d WHERE d.license_id = l.id) AS device_count
       FROM licenses l ORDER BY l.id DESC LIMIT ?1 OFFSET ?2`,
    ).bind(limit, offset).all();
    return ok({ keys: results.map((r) => publicRow(r, r.device_count)) });
  }

  // POST /admin/keys
  if (method === 'POST' && path === '/admin/keys') {
    const body = (await readJson(request)) ?? {};
    const now = nowSeconds();

    let expiresAt = null;
    if (body.expires_at !== undefined && body.expires_at !== null) {
      expiresAt = parseTime(body.expires_at);
      if (expiresAt === null || expiresAt <= now) return fail(400, 'bad_expires_at');
    } else if (body.days !== undefined) {
      if (!Number.isInteger(body.days) || body.days < 1 || body.days > 3650) return fail(400, 'bad_days');
      expiresAt = now + body.days * DAY;
    }
    let maxDevices = 1;
    if (body.max_devices !== undefined) {
      if (!Number.isInteger(body.max_devices) || body.max_devices < 1 || body.max_devices > 20) return fail(400, 'bad_max_devices');
      maxDevices = body.max_devices;
    }
    const note = typeof body.note === 'string' ? body.note.slice(0, 100) : null;

    for (let attempt = 0; attempt < 3; attempt++) {
      const key = generateKey();
      try {
        const res = await env.DB.prepare(
          'INSERT INTO licenses (key_hash, status, expires_at, max_devices, note, created_at) VALUES (?1, \'active\', ?2, ?3, ?4, ?5)',
        ).bind(await hashKey(env, key), expiresAt, maxDevices, note, now).run();
        const id = res.meta.last_row_id;
        audit(env, ctx, request, 'admin_create', id);
        // The plain key is shown exactly once and is not recoverable afterwards.
        return ok({ id, key, expires_at: expiresAt, max_devices: maxDevices, note });
      } catch (e) {
        if (!String(e && e.message).includes('UNIQUE')) throw e; // astronomically unlikely collision: retry
      }
    }
    return fail(500, 'server_error');
  }

  // POST /admin/keys/:id/<action>
  const m = path.match(/^\/admin\/keys\/(\d{1,12})\/(disable|enable|reset-devices|extend|rename|delete)$/);
  if (method === 'POST' && m) {
    const id = parseInt(m[1], 10);
    const action = m[2];
    const row = await env.DB.prepare('SELECT * FROM licenses WHERE id = ?1').bind(id).first();
    if (!row) return fail(404, 'not_found');
    const now = nowSeconds();

    if (action === 'delete') {
      await env.DB.prepare('DELETE FROM devices WHERE license_id = ?1').bind(id).run();
      await env.DB.prepare('DELETE FROM licenses WHERE id = ?1').bind(id).run();
      audit(env, ctx, request, 'admin_delete', null, 'id ' + id);
      return ok({ deleted: id });
    }

    if (action === 'rename') {
      const body = (await readJson(request)) ?? {};
      if (typeof body.note !== 'string') return fail(400, 'bad_request');
      const note = body.note.trim().slice(0, 100);
      await env.DB.prepare('UPDATE licenses SET note = ?2 WHERE id = ?1').bind(id, note === '' ? null : note).run();
    } else if (action === 'disable') {
      await env.DB.prepare("UPDATE licenses SET status = 'disabled' WHERE id = ?1").bind(id).run();
    } else if (action === 'enable') {
      // back to active; if expires_at is in the past the key is still reported as expired until extended
      await env.DB.prepare("UPDATE licenses SET status = 'active' WHERE id = ?1").bind(id).run();
    } else if (action === 'reset-devices') {
      await env.DB.prepare('DELETE FROM devices WHERE license_id = ?1').bind(id).run();
    } else {
      const body = (await readJson(request)) ?? {};
      let next = null;
      if (body.expires_at !== undefined) {
        next = parseTime(body.expires_at);
        if (next === null || next <= now) return fail(400, 'bad_expires_at');
      } else if (Number.isInteger(body.days) && body.days >= 1 && body.days <= 3650) {
        if (row.expires_at === null) return fail(400, 'lifetime_key'); // nothing to extend; pass expires_at to set one
        next = Math.max(row.expires_at, now) + body.days * DAY;
      } else {
        return fail(400, 'bad_request');
      }
      // an expired key comes back to life; a disabled key stays disabled on purpose
      await env.DB.prepare(
        "UPDATE licenses SET expires_at = ?2, status = CASE WHEN status = 'expired' THEN 'active' ELSE status END WHERE id = ?1",
      ).bind(id, next).run();
    }

    audit(env, ctx, request, 'admin_' + action.replace('-', '_'), id);
    const fresh = await env.DB.prepare(
      'SELECT l.*, (SELECT COUNT(*) FROM devices d WHERE d.license_id = l.id) AS device_count FROM licenses l WHERE l.id = ?1',
    ).bind(id).first();
    return ok({ key: publicRow(fresh, fresh.device_count) });
  }

  return fail(404, 'not_found');
}

// ===== dashboard.js =====
// GENERATED by scripts/build.py from dashboard.html - edit the .html file, not this one.
// One array entry per line, so no single line is huge (easier to copy on a phone).
const DASHBOARD_HTML = [
  "<!doctype html>",
  "<html lang=\"en\">",
  "<head>",
  "<meta charset=\"utf-8\">",
  "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1, viewport-fit=cover\">",
  "<meta name=\"robots\" content=\"noindex,nofollow\">",
  "<meta name=\"theme-color\" content=\"#0f0e10\">",
  "<title>StarGG Licenses</title>",
  "<style>",
  ":root{--bg:#0f0e10;--panel:#19181b;--panel2:#252428;--line:#2c2b30;--text:#ececf1;--dim:#9a99a5;--accent:#8b6cff;--good:#3fb950;--bad:#e05a5a;--warn:#e0a030}",
  "*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}",
  "html,body{margin:0;background:var(--bg);color:var(--text);font:15px/1.4 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}",
  "body{padding:env(safe-area-inset-top) 0 env(safe-area-inset-bottom)}",
  ".wrap{max-width:720px;margin:0 auto;padding:14px}",
  "h1{font-size:20px;margin:0}",
  "h1 span{color:var(--accent)}",
  ".bar{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:12px}",
  "button,input,select{font:inherit;color:inherit}",
  "button{background:var(--panel2);border:0;border-radius:10px;padding:11px 14px;cursor:pointer;min-height:44px}",
  "button:active{filter:brightness(1.2)}",
  "button.primary{background:var(--accent);color:#fff;font-weight:600}",
  "button.danger{background:#3a1d1f;color:#ff8d8d}",
  "button.small{padding:8px 12px;min-height:38px;font-size:14px}",
  "button:disabled{opacity:.5}",
  "input,select{width:100%;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px;min-height:44px;outline:none}",
  "input:focus,select:focus{border-color:var(--accent)}",
  "label{display:block;color:var(--dim);font-size:13px;margin:12px 0 5px}",
  ".card{background:var(--panel);border-radius:14px;padding:13px;margin-bottom:10px}",
  ".top{display:flex;align-items:center;gap:10px;cursor:pointer}",
  ".dot{width:12px;height:12px;border-radius:50%;background:#55545c;flex:none}",
  ".dot.on{background:var(--good);box-shadow:0 0 0 4px #3fb95033}",
  ".names{flex:1;min-width:0}",
  ".names b{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}",
  ".names small{color:var(--dim)}",
  ".badge{font-size:12px;padding:3px 9px;border-radius:99px;background:var(--panel2);color:var(--dim);flex:none}",
  ".badge.active{background:#1c3524;color:#6fe08a}",
  ".badge.disabled{background:#3a1d1f;color:#ff8d8d}",
  ".badge.expired{background:#3a2e17;color:#f0c060}",
  ".meta{display:flex;flex-wrap:wrap;gap:4px 14px;color:var(--dim);font-size:13px;margin-top:9px}",
  ".actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px;padding-top:12px;border-top:1px solid var(--line)}",
  ".stats{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:12px}",
  ".stat{background:var(--panel);border-radius:12px;padding:10px;text-align:center}",
  ".stat b{display:block;font-size:22px}",
  ".stat span{color:var(--dim);font-size:12px}",
  ".chips{display:flex;gap:6px;overflow-x:auto;padding-bottom:4px;margin:10px 0}",
  ".chip{white-space:nowrap;padding:8px 13px;min-height:36px;border-radius:99px;background:var(--panel)}",
  ".chip.sel{background:var(--accent);color:#fff}",
  ".empty{color:var(--dim);text-align:center;padding:30px 10px}",
  ".msg{padding:10px 12px;border-radius:10px;margin:10px 0;background:#3a1d1f;color:#ff9d9d;font-size:14px}",
  ".shade{position:fixed;inset:0;background:#000b;display:flex;align-items:flex-end;justify-content:center;z-index:10}",
  ".sheet{background:var(--bg);border:1px solid var(--line);width:100%;max-width:520px;border-radius:18px 18px 0 0;padding:16px 16px calc(16px + env(safe-area-inset-bottom));max-height:92vh;overflow:auto}",
  "@media(min-width:600px){.shade{align-items:center}.sheet{border-radius:18px}}",
  ".sheet h2{margin:0 0 4px;font-size:18px}",
  ".row{display:flex;gap:8px}.row>*{flex:1}",
  ".keybox{background:var(--panel);border:1px dashed var(--accent);border-radius:12px;padding:16px;text-align:center;font:600 19px ui-monospace,Menlo,Consolas,monospace;letter-spacing:1px;word-break:break-all;margin:12px 0;user-select:all}",
  ".hint{color:var(--dim);font-size:13px}",
  ".login{margin-top:12vh}",
  "</style>",
  "</head>",
  "<body>",
  "<div class=\"wrap\" id=\"app\"></div>",
  "<script>",
  "(function () {",
  "  var app = document.getElementById('app');",
  "  var secret = sessionStorage.getItem('sg_admin') || '';",
  "  var keys = [], filter = 'all', query = '', openId = null, timer = null, modalOpen = false;",
  "",
  "  // ---------- tiny helpers (all text goes in with textContent, never innerHTML)",
  "  function el(tag, attrs, kids) {",
  "    var n = document.createElement(tag);",
  "    for (var k in (attrs || {})) {",
  "      if (k === 'class') n.className = attrs[k];",
  "      else if (k === 'text') n.textContent = attrs[k];",
  "      else if (k.slice(0, 2) === 'on') n.addEventListener(k.slice(2), attrs[k]);",
  "      else n.setAttribute(k, attrs[k]);",
  "    }",
  "    (kids || []).forEach(function (c) { if (c) n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); });",
  "    return n;",
  "  }",
  "  function ago(sec) {",
  "    if (!sec) return 'never';",
  "    var d = Math.max(0, Math.floor(Date.now() / 1000 - sec));",
  "    if (d < 60) return 'just now';",
  "    if (d < 3600) return Math.floor(d / 60) + ' min ago';",
  "    if (d < 86400) return Math.floor(d / 3600) + ' h ago';",
  "    return Math.floor(d / 86400) + ' d ago';",
  "  }",
  "  function dateStr(sec) { return new Date(sec * 1000).toISOString().slice(0, 10); }",
  "  function expiry(k) {",
  "    if (!k.expires_at) return 'Lifetime';",
  "    var left = k.expires_at - Date.now() / 1000;",
  "    if (left <= 0) return 'Expired ' + dateStr(k.expires_at);",
  "    return 'Ends ' + dateStr(k.expires_at) + ' (' + Math.ceil(left / 86400) + ' d left)';",
  "  }",
  "  var ERRORS = {",
  "    rate_limited: 'Too many tries. Wait a minute.', lifetime_key: 'This license has no end date. Pick a date instead.',",
  "    bad_days: 'Days must be a whole number from 1 to 3650.', bad_max_devices: 'Devices must be 1 to 20.',",
  "    bad_expires_at: 'That date is not valid (it must be in the future).', not_found: 'That license no longer exists.',",
  "    server_error: 'Server error. Check that DB and the 3 secrets are set.'",
  "  };",
  "",
  "  async function api(method, path, body) {",
  "    var headers = { Authorization: 'Bearer ' + secret };",
  "    if (body !== undefined) headers['Content-Type'] = 'application/json';",
  "    var res = await fetch(path, { method: method, headers: headers, body: body === undefined ? undefined : JSON.stringify(body) });",
  "    var data = null;",
  "    try { data = await res.json(); } catch (e) { }",
  "    if (res.status === 401) { logout(); throw new Error('Wrong admin password.'); }",
  "    if (!res.ok || !data || !data.ok) throw new Error(ERRORS[data && data.error] || ('Error ' + res.status));",
  "    return data;",
  "  }",
  "",
  "  // ---------- login",
  "  function showLogin(err) {",
  "    clearInterval(timer);",
  "    app.textContent = '';",
  "    var pw = el('input', { type: 'password', placeholder: 'Admin password', autocomplete: 'current-password' });",
  "    var msg = el('div', { class: 'msg', text: err || '', style: err ? '' : 'display:none' });",
  "    var go = el('button', { class: 'primary', text: 'Open dashboard', style: 'width:100%;margin-top:12px' });",
  "    async function submit() {",
  "      secret = pw.value.trim();",
  "      if (!secret) return;",
  "      go.disabled = true;",
  "      try { await load(); sessionStorage.setItem('sg_admin', secret); showMain(); }",
  "      catch (e) { secret = ''; showLogin(e.message); }",
  "    }",
  "    go.addEventListener('click', submit);",
  "    pw.addEventListener('keydown', function (e) { if (e.key === 'Enter') submit(); });",
  "    app.appendChild(el('div', { class: 'login' }, [",
  "      el('h1', {}, ['STAR', el('span', { text: '.GG' }), ' Licenses']),",
  "      el('p', { class: 'hint', text: 'Enter the ADMIN_SECRET you saved in Cloudflare.' }), pw, msg, go]));",
  "  }",
  "  function logout() { secret = ''; sessionStorage.removeItem('sg_admin'); keys = []; showLogin(); }",
  "",
  "  // ---------- data",
  "  async function load() { keys = (await api('GET', '/admin/keys?limit=500')).keys; }",
  "  async function refresh() { if (modalOpen) return; try { await load(); render(); } catch (e) { } }",
  "",
  "  // ---------- main screen",
  "  var listBox, statsBox, chipsBox;",
  "  function showMain() {",
  "    app.textContent = '';",
  "    var search = el('input', { type: 'search', placeholder: 'Search name or account\u2026' });",
  "    search.addEventListener('input', function () { query = search.value.trim().toLowerCase(); renderList(); });",
  "    statsBox = el('div', { class: 'stats' });",
  "    chipsBox = el('div', { class: 'chips' });",
  "    listBox = el('div');",
  "    app.appendChild(el('div', { class: 'bar' }, [",
  "      el('h1', {}, ['STAR', el('span', { text: '.GG' })]),",
  "      el('div', { class: 'row', style: 'flex:none' }, [",
  "        el('button', { class: 'small', text: 'Refresh', onclick: refresh }),",
  "        el('button', { class: 'small', text: 'Log out', onclick: logout })])]));",
  "    app.appendChild(statsBox);",
  "    app.appendChild(el('button', { class: 'primary', text: '+ Create license', style: 'width:100%', onclick: createDialog }));",
  "    app.appendChild(chipsBox);",
  "    app.appendChild(search);",
  "    app.appendChild(el('div', { style: 'height:10px' }));",
  "    app.appendChild(listBox);",
  "    render();",
  "    clearInterval(timer);",
  "    timer = setInterval(refresh, 30000);",
  "  }",
  "  function render() { renderStats(); renderChips(); renderList(); }",
  "",
  "  function counts() {",
  "    var c = { all: keys.length, online: 0, active: 0, disabled: 0, expired: 0, unused: 0 };",
  "    keys.forEach(function (k) {",
  "      if (k.online) c.online++;",
  "      c[k.status]++;",
  "      if (!k.account_name) c.unused++;",
  "    });",
  "    return c;",
  "  }",
  "  function renderStats() {",
  "    var c = counts();",
  "    statsBox.textContent = '';",
  "    [['Online now', c.online], ['Active', c.active], ['Total', c.all]].forEach(function (s) {",
  "      statsBox.appendChild(el('div', { class: 'stat' }, [el('b', { text: String(s[1]) }), el('span', { text: s[0] })]));",
  "    });",
  "  }",
  "  function renderChips() {",
  "    var c = counts();",
  "    chipsBox.textContent = '';",
  "    [['all', 'All'], ['online', 'Online'], ['active', 'Active'], ['unused', 'Not activated'], ['disabled', 'Disabled'], ['expired', 'Expired']].forEach(function (f) {",
  "      chipsBox.appendChild(el('button', { class: 'chip' + (filter === f[0] ? ' sel' : ''), text: f[1] + ' ' + c[f[0]],",
  "        onclick: function () { filter = f[0]; renderChips(); renderList(); } }));",
  "    });",
  "  }",
  "  function matches(k) {",
  "    if (filter === 'online' && !k.online) return false;",
  "    if (filter === 'unused' && k.account_name) return false;",
  "    if ((filter === 'active' || filter === 'disabled' || filter === 'expired') && k.status !== filter) return false;",
  "    if (query) {",
  "      var hay = ((k.note || '') + ' ' + (k.account_name || '')).toLowerCase();",
  "      if (hay.indexOf(query) < 0) return false;",
  "    }",
  "    return true;",
  "  }",
  "  function renderList() {",
  "    listBox.textContent = '';",
  "    var shown = keys.filter(matches);",
  "    if (!shown.length) {",
  "      listBox.appendChild(el('div', { class: 'empty', text: keys.length ? 'Nothing matches.' : 'No licenses yet. Tap \"+ Create license\".' }));",
  "      return;",
  "    }",
  "    shown.forEach(function (k) { listBox.appendChild(card(k)); });",
  "  }",
  "",
  "  function card(k) {",
  "    var title = k.note || 'Unnamed license';",
  "    var who = k.account_name ? '@' + k.account_name : 'Not activated yet';",
  "    var top = el('div', { class: 'top', onclick: function () { openId = openId === k.id ? null : k.id; renderList(); } }, [",
  "      el('span', { class: 'dot' + (k.online ? ' on' : '') }),",
  "      el('div', { class: 'names' }, [el('b', { text: title }), el('small', { text: who + '  \u00b7  #' + k.id })]),",
  "      el('span', { class: 'badge ' + k.status, text: k.status })]);",
  "    var meta = el('div', { class: 'meta' }, [",
  "      el('span', { text: k.online ? 'Online now' : 'Seen ' + ago(k.last_seen) }),",
  "      el('span', { text: 'Devices ' + (k.devices || 0) + '/' + k.max_devices }),",
  "      el('span', { text: expiry(k) })]);",
  "    var c = el('div', { class: 'card' }, [top, meta]);",
  "    if (openId === k.id) {",
  "      c.appendChild(el('div', { class: 'actions' }, [",
  "        el('button', { class: 'small', text: 'Rename', onclick: function () { rename(k); } }),",
  "        el('button', { class: 'small', text: 'Extend', onclick: function () { extendDialog(k); } }),",
  "        el('button', { class: 'small', text: 'Reset devices', onclick: function () {",
  "          if (confirm('Free all device slots of this license?')) act(k, 'reset-devices'); } }),",
  "        k.status === 'disabled'",
  "          ? el('button', { class: 'small primary', text: 'Enable', onclick: function () { act(k, 'enable'); } })",
  "          : el('button', { class: 'small danger', text: 'Disable', onclick: function () {",
  "              if (confirm('Disable this license? The user is locked out within ~10 minutes.')) act(k, 'disable'); } }),",
  "        el('button', { class: 'small danger', text: 'Delete', onclick: function () {",
  "          if (confirm('Delete this license forever? The key stops working and the account name is freed.')) act(k, 'delete'); } })]));",
  "    }",
  "    return c;",
  "  }",
  "",
  "  async function act(k, action, body) {",
  "    try { await api('POST', '/admin/keys/' + k.id + '/' + action, body || {}); if (action === 'delete') openId = null; await load(); render(); }",
  "    catch (e) { alert(e.message); }",
  "  }",
  "  function rename(k) {",
  "    var v = prompt('Name for this license (for example the buyer):', k.note || '');",
  "    if (v !== null) act(k, 'rename', { note: v });",
  "  }",
  "",
  "  // ---------- dialogs",
  "  function modal(nodes) {",
  "    modalOpen = true;",
  "    var shade = el('div', { class: 'shade' });",
  "    function close() { modalOpen = false; shade.remove(); }",
  "    shade.addEventListener('click', function (e) { if (e.target === shade) close(); });",
  "    shade.appendChild(el('div', { class: 'sheet' }, nodes));",
  "    document.body.appendChild(shade);",
  "    return close;",
  "  }",
  "",
  "  function createDialog() {",
  "    var name = el('input', { type: 'text', maxlength: '100', placeholder: 'e.g. John (Discord)' });",
  "    var dur = el('select', {}, [['30', '30 days'], ['7', '7 days'], ['90', '90 days'], ['365', '1 year'], ['0', 'Lifetime'], ['custom', 'Custom days\u2026']]",
  "      .map(function (o) { return el('option', { value: o[0], text: o[1] }); }));",
  "    var custom = el('input', { type: 'number', min: '1', max: '3650', placeholder: 'Number of days', style: 'display:none;margin-top:8px' });",
  "    dur.addEventListener('change', function () { custom.style.display = dur.value === 'custom' ? '' : 'none'; });",
  "    var dev = el('input', { type: 'number', min: '1', max: '20', value: '1' });",
  "    var err = el('div', { class: 'msg', style: 'display:none' });",
  "    var close;",
  "    var go = el('button', { class: 'primary', text: 'Create', onclick: async function () {",
  "      var body = { max_devices: parseInt(dev.value, 10) || 1 };",
  "      if (name.value.trim()) body.note = name.value.trim();",
  "      var d = dur.value === 'custom' ? parseInt(custom.value, 10) : parseInt(dur.value, 10);",
  "      if (dur.value === 'custom' && !(d >= 1)) { err.textContent = 'Enter the number of days.'; err.style.display = ''; return; }",
  "      if (d > 0) body.days = d;",
  "      go.disabled = true;",
  "      try { var res = await api('POST', '/admin/keys', body); close(); keyDialog(res.key, name.value.trim()); await load(); render(); }",
  "      catch (e) { go.disabled = false; err.textContent = e.message; err.style.display = ''; }",
  "    } });",
  "    close = modal([el('h2', { text: 'New license' }),",
  "      el('label', { text: 'Name (just for you)' }), name,",
  "      el('label', { text: 'How long' }), dur, custom,",
  "      el('label', { text: 'Devices allowed (computers / phones)' }), dev, err,",
  "      el('div', { class: 'row', style: 'margin-top:16px' }, [el('button', { text: 'Cancel', onclick: function () { close(); } }), go])]);",
  "  }",
  "",
  "  function keyDialog(key, name) {",
  "    var close;",
  "    var copy = el('button', { class: 'primary', text: 'Copy key', onclick: async function () {",
  "      try { await navigator.clipboard.writeText(key); copy.textContent = 'Copied \u2713'; }",
  "      catch (e) { copy.textContent = 'Press and hold the key to copy'; }",
  "    } });",
  "    close = modal([el('h2', { text: 'License created' }),",
  "      el('p', { class: 'hint', text: (name ? name + ': ' : '') + 'send this key to the buyer. It is shown only once and cannot be shown again.' }),",
  "      el('div', { class: 'keybox', text: key }),",
  "      el('div', { class: 'row' }, [copy, el('button', { text: 'Done', onclick: function () { close(); } })])]);",
  "  }",
  "",
  "  function extendDialog(k) {",
  "    var close;",
  "    var date = el('input', { type: 'date' });",
  "    function quick(days) {",
  "      return el('button', { text: '+' + days + ' days', onclick: async function () { close(); await act(k, 'extend', { days: days }); } });",
  "    }",
  "    var buttons = k.expires_at ? [el('div', { class: 'row', style: 'margin-top:12px' }, [quick(7), quick(30)]),",
  "      el('div', { class: 'row', style: 'margin-top:8px' }, [quick(90), quick(365)])] : [",
  "      el('p', { class: 'hint', text: 'This license is lifetime. You can give it an end date below.' })];",
  "    close = modal([el('h2', { text: 'Extend: ' + (k.note || '#' + k.id) }),",
  "      el('p', { class: 'hint', text: expiry(k) })].concat(buttons, [",
  "      el('label', { text: 'Or set an exact end date' }), date,",
  "      el('div', { class: 'row', style: 'margin-top:16px' }, [el('button', { text: 'Cancel', onclick: function () { close(); } }),",
  "        el('button', { class: 'primary', text: 'Set date', onclick: async function () {",
  "          if (!date.value) return;",
  "          close(); await act(k, 'extend', { expires_at: date.value + 'T23:59:59Z' }); } })])]));",
  "  }",
  "",
  "  // ---------- start",
  "  if (secret) { load().then(showMain).catch(function () { showLogin(); }); } else { showLogin(); }",
  "})();",
  "</script>",
  "</body>",
  "</html>",
  ""
].join("\n");

// ===== index.js =====
// StarGG license backend: Cloudflare Worker + D1.

function configured(env) {
  return env.DB && env.ADMIN_SECRET && env.TOKEN_SECRET && env.KEY_SALT;
}

const worker = {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const path = url.pathname.replace(/\/+$/, '') || '/';

      if (!configured(env)) {
        console.error('Missing binding or secret: need DB, ADMIN_SECRET, TOKEN_SECRET, KEY_SALT');
        return fail(500, 'server_error');
      }

      // The dashboard page is public HTML with no data in it; every action needs the admin password.
      if (path === '/' && request.method === 'GET') {
        return new Response(DASHBOARD_HTML, {
          headers: {
            'content-type': 'text/html; charset=utf-8',
            'cache-control': 'no-store',
            'content-security-policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
            'x-frame-options': 'DENY',
            'x-content-type-options': 'nosniff',
            'referrer-policy': 'no-referrer',
            'x-robots-tag': 'noindex, nofollow',
          },
        });
      }

      if (path === '/auth/login' && request.method === 'POST') return await login(request, env, ctx);
      if (path === '/auth/redeem' && request.method === 'POST') return await redeem(request, env, ctx);
      if (path === '/auth/check' && request.method === 'GET') return await check(request, env);
      if (path.startsWith('/admin/')) return await handleAdmin(request, env, ctx, url, path);
      if (path === '/health') return new Response('ok', { headers: { 'cache-control': 'no-store' } });

      // CORS is intentionally off: OPTIONS and unknown routes get no special treatment.
      return fail(404, 'not_found');
    } catch (e) {
      // Never leak internals; the message is only visible in `wrangler tail`.
      console.error('unhandled', e && e.message, nowSeconds());
      return fail(500, 'server_error');
    }
  },
};

export default worker;
