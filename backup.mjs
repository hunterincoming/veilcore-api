// Off-site backups of the registry database.
//
// Why: the database lives on one Railway volume. Railway's own volume backups are deleted
// with the volume ("Wiping a volume deletes all backups", docs.railway.com/volumes/backups),
// so they do not protect against the failure that matters most. This sends a copy somewhere
// else, every day.
//
// What leaves the server is useless without a key the server never holds:
//   1. a consistent snapshot of the whole database, made with SQLite's online backup into a
//      temporary file next to the live one (same disk, same exposure as the live file; it is
//      deleted as soon as the run ends, success or not). Page by page, so the registry keeps
//      answering, and no size limit from memory: the first version held the whole database in
//      memory and refused past 128 MB, which a busy month would have reached (ops review,
//      5 Nov 2026);
//   2. checked before it goes anywhere: it must open, pass SQLite's integrity check, and
//      hold a records table;
//   3. streamed through gzip, then encrypted with age (age-encryption.org) to a public key,
//      into a second temporary file. Only the matching private key, kept offline by the
//      operator, can open it. Someone who takes over this server, or the storage account,
//      gets ciphertext;
//   4. uploaded to an S3-compatible bucket (Backblaze B2 in production) under a new name
//      every time, so an upload never replaces an earlier backup; the body is read from the
//      file, not memory.
// Lab-result files (lineage/lab-results.mjs) are copied too, each once, under
// lab-results/<id>: they are already locked to the breeder's key, so they go as they are.
// Which ones have gone is kept in the backup_lab_files table, so each run sends only new
// ones. restore.mjs puts a backup back, and the lab files with it.
// The bucket is meant to have Object Lock on (docs/backups in the README): even a stolen
// upload key then cannot delete or overwrite a backup until its lock runs out.
//
// Each backup's name says which key it is sealed to: `<time>.key-<id>.sqlite.gz.age`, where
// <id> is the first 12 hex characters of SHA-256 of the public key (recipientId). So after
// the key is rotated (docs/rotate-backup-key.md) anyone can tell from the bucket listing,
// and from GET /admin/backup and the deploy log, which backups the new key opens and which
// only the old one did. Only the public key goes into it; it says nothing about the private.
//
// Settings (all or none; a partial set is refused, loudly, and nothing is sent):
//   BACKUP_AGE_RECIPIENT   age1… public key
//   BACKUP_S3_ENDPOINT     https://s3.<region>.backblazeb2.com
//   BACKUP_S3_BUCKET       bucket name
//   BACKUP_S3_KEY_ID       application key id
//   BACKUP_S3_SECRET       application key
// Optional: BACKUP_S3_REGION (read from a B2 endpoint otherwise), BACKUP_EVERY_HOURS
// (24; 1 to 168), BACKUP_PREFIX (veilcore-registry), BACKUP_PING_URL (an https address
// called after every successful backup, e.g. a healthchecks.io check, so a day with no
// backup sends an alert instead of passing unnoticed).
//
// SPDX-License-Identifier: Apache-2.0

import { createHash, randomBytes } from 'node:crypto';
import { createReadStream, createWriteStream, existsSync, openAsBlob, readdirSync, rmSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { Readable, Writable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { createRequire } from 'node:module';
import { Encrypter } from 'age-encryption';
import { AwsClient } from 'aws4fetch';

const require = createRequire(import.meta.url);
const Database = require('better-sqlite3');

const REQUIRED = ['BACKUP_AGE_RECIPIENT', 'BACKUP_S3_ENDPOINT', 'BACKUP_S3_BUCKET', 'BACKUP_S3_KEY_ID', 'BACKUP_S3_SECRET'];
const FIRST_RUN_MS = 10 * 60_000; // not at boot: a deploy that crash-loops would send one per crash
const RETRY_MS = 60 * 60_000;
// Nothing is held in memory now; the limit is the disk, which needs room for the snapshot
// and its encrypted copy next to the live file. Past this, refuse and say so (a single PUT
// to the store also stops at 5 GB).
const MAX_BYTES = 4 * 1024 * 1024 * 1024;
// GET /admin/backup says `large: true` past this: time to plan for the volume, not urgent.
export const LARGE_BYTES = 1024 * 1024 * 1024;
const UPLOAD_TIMEOUT_MS = 30 * 60_000; // a hung upload must not stop every later backup
const PING_TIMEOUT_MS = 30_000;
const LAB_ID = /^[A-Za-z0-9_-]{8,64}$/;

const isLoopback = (host) => host === '127.0.0.1' || host === 'localhost' || host === '[::1]';
const BUCKET_RE = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/i;
const PREFIX_RE = /^[a-z0-9][a-z0-9._-]{0,62}$/i;

/** A short, public name for an age public key: the first 12 hex of its SHA-256. */
export const recipientId = (recipient) => createHash('sha256').update(String(recipient).trim(), 'utf8').digest('hex').slice(0, 12);

/**
 * Read the settings. Returns { on: false, reason } when backups are not configured (or
 * badly configured; `problem` is set then), or { on: true, ... }. Never echoes a secret.
 */
export const backupConfig = (env) => {
  const set = REQUIRED.filter((k) => typeof env[k] === 'string' && env[k].trim() !== '');
  if (set.length === 0) return { on: false, reason: 'not configured' };
  const missing = REQUIRED.filter((k) => !set.includes(k));
  if (missing.length) return { on: false, problem: `backups are half set up: missing ${missing.join(', ')}` };

  const recipient = env.BACKUP_AGE_RECIPIENT.trim();
  // A secret key pasted where the public one goes would sit in the service's settings:
  // refuse it, and say so without repeating it.
  if (/^AGE-SECRET-KEY-/i.test(recipient)) {
    return { on: false, problem: 'BACKUP_AGE_RECIPIENT holds a PRIVATE key. Remove it from the settings now, and set the public key (age1…) instead' };
  }
  if (!/^age1[0-9a-z]{20,}$/.test(recipient)) return { on: false, problem: 'BACKUP_AGE_RECIPIENT is not an age public key (age1…)' };
  // The checksum too: a one-letter typo would otherwise pass here and fail every hour.
  try { new Encrypter().addRecipient(recipient); } catch {
    return { on: false, problem: 'BACKUP_AGE_RECIPIENT is not a valid age public key (check it was copied exactly)' };
  }

  let url;
  try { url = new URL(env.BACKUP_S3_ENDPOINT.trim()); } catch { return { on: false, problem: 'BACKUP_S3_ENDPOINT is not a URL' }; }
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopback(url.hostname))) {
    return { on: false, problem: 'BACKUP_S3_ENDPOINT must be https' };
  }
  if (url.username || url.password || url.search || (url.pathname !== '/' && url.pathname !== '')) {
    return { on: false, problem: 'BACKUP_S3_ENDPOINT must be just the endpoint, e.g. https://s3.us-west-004.backblazeb2.com' };
  }
  const bucket = env.BACKUP_S3_BUCKET.trim();
  if (!BUCKET_RE.test(bucket)) return { on: false, problem: 'BACKUP_S3_BUCKET is not a valid bucket name' };

  const region = (env.BACKUP_S3_REGION || '').trim() || (/^s3\.([a-z0-9-]+)\.backblazeb2\.com$/.exec(url.hostname)?.[1] ?? '');
  if (!region) return { on: false, problem: 'set BACKUP_S3_REGION (it can only be read from a Backblaze endpoint)' };

  const hours = env.BACKUP_EVERY_HOURS === undefined || env.BACKUP_EVERY_HOURS === '' ? 24 : Number(env.BACKUP_EVERY_HOURS);
  if (!Number.isFinite(hours) || hours < 1 || hours > 168) return { on: false, problem: 'BACKUP_EVERY_HOURS must be between 1 and 168' };

  const prefix = (env.BACKUP_PREFIX || 'veilcore-registry').trim();
  if (!PREFIX_RE.test(prefix)) return { on: false, problem: 'BACKUP_PREFIX may hold letters, digits, dot, dash and underscore only' };

  let ping = null;
  if ((env.BACKUP_PING_URL || '').trim()) {
    try { ping = new URL(env.BACKUP_PING_URL.trim()); } catch { return { on: false, problem: 'BACKUP_PING_URL is not a URL' }; }
    if (ping.protocol !== 'https:' && !(ping.protocol === 'http:' && isLoopback(ping.hostname))) return { on: false, problem: 'BACKUP_PING_URL must be https' };
  }

  return {
    on: true,
    recipient,
    recipientId: recipientId(recipient),
    endpoint: `${url.protocol}//${url.host}`,
    bucket,
    region,
    keyId: env.BACKUP_S3_KEY_ID.trim(),
    secret: env.BACKUP_S3_SECRET.trim(),
    everyMs: Math.round(hours * 3600_000),
    prefix,
    ping: ping ? ping.href : null,
    network: /^[a-z0-9-]{1,32}$/.test(env.VEILCORE_ANCHOR_NETWORK || '') ? env.VEILCORE_ANCHOR_NETWORK : 'unset',
  };
};

/** The values that must never appear in a log line. */
export const backupSecrets = (env) => [env.BACKUP_S3_SECRET, env.BACKUP_S3_KEY_ID, env.BACKUP_PING_URL].filter((s) => typeof s === 'string' && s.trim().length >= 8).map((s) => s.trim());

const scrub = (text, secrets) => secrets.reduce((t, s) => t.split(s).join('[hidden]'), String(text));

/** The database's size in bytes, from its pages. */
export const dbBytes = (db) => db.pragma('page_count', { simple: true }) * db.pragma('page_size', { simple: true });

/** A temporary file next to the database (or in the system's temp folder for one in memory). */
const tempPath = (db, what) => {
  const dir = db.memory || db.name === ':memory:' || !db.name ? tmpdir() : dirname(db.name);
  return join(dir, `.veilcore-backup-${randomBytes(6).toString('hex')}.${what}`);
};

/**
 * One snapshot, into a file, checked. Throws with a short reason if the copy is not a sound
 * database. Returns its path (the caller deletes it) and the record count, for the log.
 */
export const snapshot = async (db, maxBytes = MAX_BYTES) => {
  const size = dbBytes(db);
  if (size > maxBytes) throw Object.assign(new Error(`database is ${size} bytes, over the ${maxBytes}-byte limit for this backup`), { code: 'too-big' });
  const path = tempPath(db, 'sqlite');
  try {
    await db.backup(path);
    const copy = new Database(path, { readonly: true, fileMustExist: true });
    try {
      const check = copy.pragma('integrity_check', { simple: true });
      if (check !== 'ok') throw Object.assign(new Error('the snapshot failed SQLite\'s integrity check'), { code: 'integrity' });
      const records = copy.prepare('SELECT count(*) AS n FROM records').get().n;
      return { path, records };
    } finally {
      copy.close();
    }
  } catch (e) {
    rmSync(path, { force: true });
    throw e;
  }
};

/**
 * gzip, then age-encrypt to the operator's public key, file to file, streaming. Returns the
 * encrypted file's path, size and digests (the store checks both).
 */
export const sealFile = async (from, recipient, to) => {
  const e = new Encrypter();
  e.addRecipient(recipient);
  const gz = Readable.toWeb(createReadStream(from)).pipeThrough(new CompressionStream('gzip'));
  const sealed = await e.encrypt(gz);
  const md5 = createHash('md5');
  const sha = createHash('sha256');
  let bytes = 0;
  const out = createWriteStream(to, { mode: 0o600 });
  await pipeline(
    Readable.fromWeb(sealed),
    async function* (src) {
      for await (const chunk of src) {
        md5.update(chunk);
        sha.update(chunk);
        bytes += chunk.length;
        yield chunk;
      }
    },
    out,
  );
  return { path: to, bytes, md5: md5.digest('base64'), sha256: sha.digest('hex') };
};

const stamp = (d) => d.toISOString().replace(/[:.]/g, '-'); // 2026-10-10T11-40-00-000Z

/**
 * Upload one object: bytes in memory, or a file ({ path, md5, sha256 }) read as it goes.
 * Throws on anything but a 2xx, with the status only.
 */
const upload = async (cfg, key, body, fetchImpl) => {
  const client = new AwsClient({ accessKeyId: cfg.keyId, secretAccessKey: cfg.secret, service: 's3', region: cfg.region });
  const url = `${cfg.endpoint}/${encodeURIComponent(cfg.bucket)}/${key.split('/').map(encodeURIComponent).join('/')}`;
  const isFile = !(body instanceof Uint8Array);
  const md5 = isFile ? body.md5 : createHash('md5').update(body).digest('base64');
  const sha = isFile ? body.sha256 : createHash('sha256').update(body).digest('hex');
  const req = await client.sign(url, {
    method: 'PUT',
    body: isFile ? await openAsBlob(body.path) : body,
    headers: {
      'content-type': 'application/octet-stream',
      // A bucket with Object Lock requires an integrity header on every write; it also lets
      // the store refuse a body damaged on the way.
      'content-md5': md5,
      // Sign the body itself (the client would otherwise send UNSIGNED-PAYLOAD), so a
      // changed body fails the signature, not just the checksum.
      'x-amz-content-sha256': sha,
    },
  });
  const res = await fetchImpl(req, { signal: AbortSignal.timeout(UPLOAD_TIMEOUT_MS) });
  if (!res.ok) {
    // The store's own error code (SignatureDoesNotMatch, AccessDenied, InvalidAccessKeyId…)
    // is what tells the operator which setting is wrong. Only that element is kept.
    const text = await res.text().catch(() => '');
    const code = /<Code>([A-Za-z]{1,64})<\/Code>/.exec(text)?.[1];
    throw Object.assign(new Error(`storage answered ${res.status}${code ? ` ${code}` : ''}`), { code: `upload-${res.status}` });
  }
  await res.body?.cancel?.();
};

/**
 * Send the lab-result files not sent yet, each once, as they are (already locked to the
 * breeder). Returns how many went. A file that fails stays unsent and is tried next run.
 */
const sendLabFiles = async (db, cfg, labDir, fetchImpl) => {
  if (!labDir || !existsSync(labDir)) return { sent: 0, failed: 0 };
  db.exec('CREATE TABLE IF NOT EXISTS backup_lab_files (id TEXT PRIMARY KEY, sent_at INTEGER NOT NULL)');
  const sentAlready = new Set(db.prepare('SELECT id FROM backup_lab_files').pluck().all());
  const mark = db.prepare('INSERT OR REPLACE INTO backup_lab_files (id, sent_at) VALUES (?, ?)');
  let sent = 0;
  let failed = 0;
  for (const id of readdirSync(labDir)) {
    if (!LAB_ID.test(id) || sentAlready.has(id)) continue;
    const path = join(labDir, id);
    try {
      if (!statSync(path).isFile()) continue;
      const md5 = createHash('md5');
      const sha = createHash('sha256');
      for await (const chunk of createReadStream(path)) {
        md5.update(chunk);
        sha.update(chunk);
      }
      await upload(cfg, `${cfg.prefix}/${cfg.network}/lab-results/${id}`, { path, md5: md5.digest('base64'), sha256: sha.digest('hex') }, fetchImpl);
      mark.run(id, Date.now());
      sent += 1;
    } catch (e) {
      if (e?.code === 'ENOENT') continue; // removed meanwhile (expired or withdrawn)
      failed += 1;
    }
  }
  return { sent, failed };
};

/** Tell an outside monitor a backup landed. Its failure never fails the backup. */
const pingMonitor = async (url, fetchImpl) => {
  const res = await fetchImpl(url, { method: 'GET', signal: AbortSignal.timeout(PING_TIMEOUT_MS) });
  await res.body?.cancel?.();
  if (!res.ok) throw new Error(`monitor answered ${res.status}`);
};

/** Why a request failed, in a few words: a status, or the network error's code. */
const reason = (e) => {
  if (e?.name === 'TimeoutError') return 'timed out';
  const cause = typeof e?.cause?.code === 'string' ? ` (${e.cause.code})` : '';
  return `${e?.message ?? e}${cause}`;
};

/**
 * Start the schedule. Returns { status(), runNow() }. With backups off it does nothing
 * except say so once (louder on Railway, where an unbacked database is the real risk).
 */
export const startBackups = ({ db, labDir = null, env = process.env, log = console.log, error = console.error, fetchImpl = fetch, firstRunMs = FIRST_RUN_MS, maxBytes = MAX_BYTES } = {}) => {
  const cfg = backupConfig(env);
  const secrets = backupSecrets(env);
  const state = {
    on: cfg.on,
    lastSuccessAt: null,
    lastAttemptAt: null,
    lastError: null, // a short code, never text from outside
    lastObject: null,
    lastRecords: null,
    lastBytes: null,
    // The live database's size, and whether it is past LARGE_BYTES (plan for the volume).
    dbBytes: null,
    large: false,
    lastLabFilesSent: null,
    labFilesFailed: 0,
    // Which public key backups are sealed to now, by recipientId (never the key itself).
    recipientId: cfg.on ? cfg.recipientId : null,
    consecutiveFailures: 0,
    nextAt: null,
  };

  if (!cfg.on) {
    if (cfg.problem) error(`BACKUP: ${cfg.problem}. No backups are being made.`);
    else if (Object.keys(env).some((k) => k.startsWith('RAILWAY_'))) {
      error('WARNING: no off-site backups are set up (BACKUP_* settings). If this volume is lost, every record is lost with it.');
    }
    return { status: () => ({ on: false, ...(cfg.problem ? { problem: 'misconfigured' } : {}) }), runNow: async () => ({ ok: false, error: cfg.problem ? 'misconfigured' : 'off' }) };
  }

  let running = null;
  let timer = null;
  const schedule = (ms) => {
    clearTimeout(timer);
    state.nextAt = new Date(Date.now() + ms).toISOString();
    timer = setTimeout(() => { void run(); }, ms);
    timer.unref?.();
  };

  const once = async () => {
    const at = new Date();
    state.lastAttemptAt = at.toISOString();
    state.dbBytes = dbBytes(db);
    state.large = state.dbBytes > LARGE_BYTES;
    const snap = await snapshot(db, maxBytes);
    let sealed;
    try {
      sealed = await sealFile(snap.path, cfg.recipient, `${snap.path}.gz.age`);
      const key = `${cfg.prefix}/${cfg.network}/${stamp(at)}.key-${cfg.recipientId}.sqlite.gz.age`;
      await upload(cfg, key, sealed, fetchImpl);
      Object.assign(state, {
        lastSuccessAt: new Date().toISOString(), lastError: null, lastObject: key,
        lastRecords: snap.records, lastBytes: sealed.bytes, consecutiveFailures: 0,
      });
      log(`backup: sent ${key} (${snap.records} records, ${sealed.bytes} bytes encrypted)`);
    } finally {
      rmSync(snap.path, { force: true });
      rmSync(`${snap.path}.gz.age`, { force: true });
    }
    // Lab files after the database: a database without its newest files restores fine
    // (those answer "ask the lab to send it again"), files without their database don't.
    const lab = await sendLabFiles(db, cfg, labDir, fetchImpl);
    state.lastLabFilesSent = lab.sent;
    state.labFilesFailed = lab.failed;
    if (lab.sent || lab.failed) log(`backup: lab files: ${lab.sent} sent${lab.failed ? `, ${lab.failed} to try again next run` : ''}`);
    if (cfg.ping && !lab.failed) {
      try { await pingMonitor(cfg.ping, fetchImpl); } catch (e) { error(`backup: sent, but the monitor was not told: ${scrub(reason(e), secrets)}`); }
    }
    return { ok: true, object: state.lastObject, records: snap.records, bytes: sealed.bytes, labFilesSent: lab.sent };
  };

  const run = async () => {
    if (running) return running; // one at a time; a second call gets the same result
    running = (async () => {
      try {
        const out = await once();
        schedule(cfg.everyMs);
        return out;
      } catch (e) {
        state.consecutiveFailures += 1;
        state.lastError = typeof e?.code === 'string' && /^[a-z0-9-]{1,32}$/.test(e.code) ? e.code : 'failed';
        error(`backup FAILED (${state.consecutiveFailures} in a row): ${scrub(reason(e), secrets)}. Trying again in an hour.`);
        schedule(Math.min(RETRY_MS, cfg.everyMs));
        return { ok: false, error: state.lastError };
      } finally {
        running = null;
      }
    })();
    return running;
  };

  const startedAt = Date.now();
  log(`backup: on, to ${cfg.endpoint}/${cfg.bucket}/${cfg.prefix}/${cfg.network}/, sealed to key ${cfg.recipientId}, every ${cfg.everyMs / 3600_000} h; first in ${Math.round(firstRunMs / 60_000)} min`);
  schedule(firstRunMs);
  return {
    // overdue: no success for two whole periods since the later of the start and the last
    // success. What a monitor (or a person checking) should alarm on.
    status: () => ({
      ...state,
      overdue: Date.now() - (state.lastSuccessAt ? Date.parse(state.lastSuccessAt) : startedAt + firstRunMs) > 2 * cfg.everyMs,
    }),
    runNow: () => run(),
    stop: () => clearTimeout(timer),
  };
};
