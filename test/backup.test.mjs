// Off-site backups (backup.mjs): what is sent can be opened with the private key and holds
// the whole database; settings are all-or-nothing; secrets never reach a log; the operator
// routes are operator-only. A local HTTP server stands in for the bucket. No network.
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { gunzipSync } from 'node:zlib';
import { createRequire } from 'node:module';
import { Decrypter, generateX25519Identity, identityToRecipient } from 'age-encryption';
import { backupConfig, startBackups, snapshot, recipientId } from '../backup.mjs';
import { waitFor } from './helpers.mjs';

const require = createRequire(import.meta.url);
const Database = require('better-sqlite3');

const SECRET = 'K005-very-secret-application-key-value';
const KEY_ID = '005a1b2c3d4e5f60000000042';

let identity;
let recipient;
let bucket; // { server, base, requests, answer }
before(async () => {
  identity = await generateX25519Identity();
  recipient = await identityToRecipient(identity);
  const requests = [];
  const box = { requests, answer: 200, body: '' };
  box.server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      requests.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks) });
      res.statusCode = req.url.startsWith('/ping') ? 200 : box.answer;
      res.end(req.url.startsWith('/ping') ? '' : box.body);
    });
  });
  await new Promise((r) => box.server.listen(0, '127.0.0.1', r));
  box.base = `http://127.0.0.1:${box.server.address().port}`;
  bucket = box;
});
after(() => bucket.server.close());

const envFor = (over = {}) => ({
  BACKUP_AGE_RECIPIENT: recipient,
  BACKUP_S3_ENDPOINT: bucket.base,
  BACKUP_S3_BUCKET: 'veilcore-backups-test',
  BACKUP_S3_KEY_ID: KEY_ID,
  BACKUP_S3_SECRET: SECRET,
  BACKUP_S3_REGION: 'us-west-004',
  VEILCORE_ANCHOR_NETWORK: 'mainnet',
  ...over,
});

const sampleDb = (n = 3) => {
  const db = new Database(':memory:');
  db.exec('CREATE TABLE records (id TEXT PRIMARY KEY, holder_key TEXT NOT NULL, body TEXT NOT NULL, updated_at INTEGER NOT NULL)');
  const ins = db.prepare('INSERT INTO records VALUES (?, ?, ?, ?)');
  for (let i = 0; i < n; i++) ins.run(`rec-${i}`, 'h1:' + 'ab'.repeat(32), JSON.stringify({ strainName: `Line ${i}` }), Date.now());
  return db;
};

const quiet = () => {
  const lines = [];
  return { lines, log: (...a) => lines.push(a.join(' ')), error: (...a) => lines.push(a.join(' ')) };
};

test('settings: none set is off and silent off Railway; a partial set is refused and names what is missing', () => {
  assert.deepEqual(backupConfig({}), { on: false, reason: 'not configured' });
  const half = backupConfig({ BACKUP_AGE_RECIPIENT: recipient, BACKUP_S3_BUCKET: 'b-ok' });
  assert.equal(half.on, false);
  assert.match(half.problem, /BACKUP_S3_ENDPOINT, BACKUP_S3_KEY_ID, BACKUP_S3_SECRET/);
});

test('settings: a private key pasted as the recipient is refused, and not repeated', () => {
  const sk = 'AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ';
  const c = backupConfig(envFor({ BACKUP_AGE_RECIPIENT: sk }));
  assert.equal(c.on, false);
  assert.match(c.problem, /PRIVATE key/);
  assert.ok(!c.problem.includes(sk));
});

test('settings: plain http only to this machine; a bare endpoint only; region read from a Backblaze endpoint', () => {
  assert.match(backupConfig(envFor({ BACKUP_S3_ENDPOINT: 'http://s3.us-west-004.backblazeb2.com' })).problem, /https/);
  assert.match(backupConfig(envFor({ BACKUP_S3_ENDPOINT: 'https://s3.us-west-004.backblazeb2.com/bucket' })).problem, /just the endpoint/);
  const c = backupConfig(envFor({ BACKUP_S3_ENDPOINT: 'https://s3.eu-central-003.backblazeb2.com', BACKUP_S3_REGION: '' }));
  assert.equal(c.on, true);
  assert.equal(c.region, 'eu-central-003');
  assert.match(backupConfig(envFor({ BACKUP_S3_ENDPOINT: 'https://example.com', BACKUP_S3_REGION: '' })).problem, /BACKUP_S3_REGION/);
  assert.match(backupConfig(envFor({ BACKUP_EVERY_HOURS: '0.5' })).problem, /between 1 and 168/);
});

test('settings: a public key with a typo is refused at start, not every hour later', () => {
  const typo = recipient.slice(0, -1) + (recipient.endsWith('q') ? 'p' : 'q');
  assert.match(backupConfig(envFor({ BACKUP_AGE_RECIPIENT: typo })).problem, /not a valid age public key/);
  assert.match(backupConfig(envFor({ BACKUP_PING_URL: 'http://hc-ping.com/x' })).problem, /BACKUP_PING_URL must be https/);
});

test('a database in WAL mode is backed up and the copy opens', async () => {
  const { mkdtempSync, rmSync } = await import('node:fs');
  const { join } = await import('node:path');
  const { tmpdir } = await import('node:os');
  const dir = mkdtempSync(join(tmpdir(), 'bk-'));
  try {
    const db = new Database(join(dir, 'w.db'));
    db.pragma('journal_mode = WAL');
    db.exec('CREATE TABLE records (id TEXT PRIMARY KEY)');
    db.prepare('INSERT INTO records VALUES (?)').run('rec-w');
    const { path, records } = await snapshot(db);
    assert.equal(records, 1);
    // A file next to the live one, deleted by the caller.
    assert.ok(path.startsWith(dir));
    const copy = new Database(path, { readonly: true });
    assert.equal(copy.prepare('SELECT id FROM records').get().id, 'rec-w');
    copy.close();
    db.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a database over the size limit is refused before it is copied', async () => {
  const db = sampleDb(50);
  await assert.rejects(() => snapshot(db, 1024), /over the 1024-byte limit/);
});

test('the store\'s own error code is logged, and a monitor is told about each success', async () => {
  bucket.requests.length = 0;
  bucket.answer = 403;
  bucket.body = '<?xml version="1.0"?><Error><Code>SignatureDoesNotMatch</Code><Message>x</Message></Error>';
  const out = quiet();
  const b = startBackups({ db: sampleDb(1), env: envFor({ BACKUP_PING_URL: `${bucket.base}/ping/abc` }), fetchImpl: fetch, firstRunMs: 3_600_000, ...out });
  try {
    assert.deepEqual(await b.runNow(), { ok: false, error: 'upload-403' });
    assert.match(out.lines.join('\n'), /storage answered 403 SignatureDoesNotMatch/);
    assert.ok(!bucket.requests.some((r) => r.url.startsWith('/ping')), 'no ping after a failure');
    bucket.answer = 200;
    bucket.body = '';
    assert.equal((await b.runNow()).ok, true);
    assert.ok(bucket.requests.some((r) => r.url === '/ping/abc'), 'pinged after the success');
    assert.equal(b.status().overdue, false);
  } finally {
    b.stop();
    bucket.answer = 200;
    bucket.body = '';
  }
});

test('a backup opens with the private key and is the whole database', async () => {
  bucket.requests.length = 0;
  bucket.answer = 200;
  const db = sampleDb(5);
  const out = quiet();
  const b = startBackups({ db, env: envFor(), fetchImpl: fetch, firstRunMs: 3_600_000, ...out });
  try {
    const r = await b.runNow();
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(r.records, 5);
    assert.equal(bucket.requests.length, 1);
    const req = bucket.requests[0];
    assert.equal(req.method, 'PUT');
    // The name says which public key it is sealed to (recipientId), so a rotation can be checked.
    assert.match(req.url, new RegExp(`^/veilcore-backups-test/veilcore-registry/mainnet/\\d{4}-\\d{2}-\\d{2}T[\\d-]+Z\\.key-${recipientId(recipient)}\\.sqlite\\.gz\\.age$`));
    assert.match(recipientId(recipient), /^[0-9a-f]{12}$/);
    // Signed for S3 with the key id, the region and the body's hash; the secret is not sent.
    assert.match(req.headers.authorization, new RegExp(`^AWS4-HMAC-SHA256 Credential=${KEY_ID}/\\d{8}/us-west-004/s3/aws4_request`));
    assert.equal(req.headers['x-amz-content-sha256'], createHash('sha256').update(req.body).digest('hex'));
    assert.equal(req.headers['content-md5'], createHash('md5').update(req.body).digest('base64'));
    assert.ok(!JSON.stringify(req.headers).includes(SECRET));
    // Ciphertext: no table name or record text in the clear.
    assert.ok(!req.body.includes('records') && !req.body.includes('Line 1'));
    // Opened with the private key: the same rows.
    const d = new Decrypter();
    d.addIdentity(identity);
    const restored = new Database(gunzipSync(await d.decrypt(new Uint8Array(req.body))));
    assert.equal(restored.pragma('integrity_check', { simple: true }), 'ok');
    assert.deepEqual(restored.prepare('SELECT id FROM records ORDER BY id').all().map((x) => x.id), ['rec-0', 'rec-1', 'rec-2', 'rec-3', 'rec-4']);
    const s = b.status();
    assert.equal(s.lastError, null);
    assert.equal(s.recipientId, recipientId(recipient));
    assert.match(out.lines.join('\n'), new RegExp(`sealed to key ${recipientId(recipient)}`));
    assert.equal(s.lastRecords, 5);
    assert.ok(s.lastSuccessAt);
  } finally {
    b.stop();
  }
});

test('each backup has a new name, so none replaces an earlier one', async () => {
  bucket.requests.length = 0;
  bucket.answer = 200;
  const b = startBackups({ db: sampleDb(1), env: envFor(), fetchImpl: fetch, firstRunMs: 3_600_000, ...quiet() });
  try {
    await b.runNow();
    await new Promise((r) => setTimeout(r, 5));
    await b.runNow();
    assert.equal(bucket.requests.length, 2);
    assert.notEqual(bucket.requests[0].url, bucket.requests[1].url);
  } finally {
    b.stop();
  }
});

test('a refused upload is reported as a short code, retried later, and no secret reaches the log', async () => {
  bucket.requests.length = 0;
  bucket.answer = 403;
  const out = quiet();
  const b = startBackups({ db: sampleDb(2), env: envFor(), fetchImpl: fetch, firstRunMs: 3_600_000, ...out });
  try {
    const r = await b.runNow();
    assert.deepEqual(r, { ok: false, error: 'upload-403' });
    const s = b.status();
    assert.equal(s.consecutiveFailures, 1);
    assert.equal(s.lastSuccessAt, null);
    assert.ok(Date.parse(s.nextAt) - Date.now() <= 60 * 60_000 + 1000, 'retry within the hour');
    const all = out.lines.join('\n');
    assert.match(all, /backup FAILED/);
    assert.ok(!all.includes(SECRET) && !all.includes(KEY_ID));
  } finally {
    b.stop();
    bucket.answer = 200;
  }
});

test('half-set settings: nothing is sent, and the log says why', async () => {
  bucket.requests.length = 0;
  const out = quiet();
  const env = envFor();
  delete env.BACKUP_S3_SECRET;
  const b = startBackups({ db: sampleDb(1), env, fetchImpl: fetch, firstRunMs: 1, ...out });
  await new Promise((r) => setTimeout(r, 30));
  assert.equal(bucket.requests.length, 0);
  assert.deepEqual(await b.runNow(), { ok: false, error: 'misconfigured' });
  assert.match(out.lines.join('\n'), /half set up: missing BACKUP_S3_SECRET/);
});

test('on Railway with no backups set up, the log warns', () => {
  const out = quiet();
  startBackups({ db: sampleDb(1), env: { RAILWAY_ENVIRONMENT: 'production' }, ...out });
  assert.match(out.lines.join('\n'), /no off-site backups/);
});

test('a damaged database is not sent, and its temporary copy is not left behind', async () => {
  // A table that claims rows it does not have cannot be produced through SQLite itself;
  // a missing records table is the case that can happen (a wrong DB_PATH).
  const { readdirSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const before = readdirSync(tmpdir()).filter((n) => n.startsWith('.veilcore-backup-')).length;
  const db = new Database(':memory:');
  db.exec('CREATE TABLE other (x)');
  await assert.rejects(() => snapshot(db), /no such table: records/);
  assert.equal(readdirSync(tmpdir()).filter((n) => n.startsWith('.veilcore-backup-')).length, before);
});

test('the operator routes need the operator token', async () => {
  process.env.DB_PATH = ':memory:';
  process.env.VEILCORE_OPERATOR_TOKEN = 'test-operator-token-at-least-32-chars';
  process.env.VEILCORE_OTS = 'off';
  for (const k of Object.keys(process.env)) if (k.startsWith('BACKUP_')) delete process.env[k];
  const { app } = require('../server.js');
  const server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    // The backup module loads asynchronously: wait until the route says it has.
    await waitFor('the backup module to load', async () => {
      const r = await fetch(`${base}/admin/backup`, { headers: { 'x-operator-token': process.env.VEILCORE_OPERATOR_TOKEN } });
      return (await r.json()).problem !== 'not loaded';
    });
    assert.equal((await fetch(`${base}/admin/backup`)).status, 401);
    assert.equal((await fetch(`${base}/admin/backup`, { method: 'POST' })).status, 401);
    const ok = await fetch(`${base}/admin/backup`, { headers: { 'x-operator-token': process.env.VEILCORE_OPERATOR_TOKEN } });
    assert.equal(ok.status, 200);
    assert.deepEqual(await ok.json(), { on: false });
    const run = await fetch(`${base}/admin/backup`, { method: 'POST', headers: { 'x-operator-token': process.env.VEILCORE_OPERATOR_TOKEN } });
    assert.equal(run.status, 503);
    assert.deepEqual(await run.json(), { ok: false, error: 'off' });
  } finally {
    server.close();
  }
});

// Rotating the backup key (docs/rotate-backup-key.md, sealed records round 2, P4): once
// BACKUP_AGE_RECIPIENT names a new key, every new backup is sealed to it, says so in its
// name, and does not open with the old private key; the old key opens only the old ones.
test('after the key is rotated, new backups name the new key and the old private key cannot open them', async () => {
  const newIdentity = await generateX25519Identity();
  const newRecipient = await identityToRecipient(newIdentity);
  bucket.requests.length = 0;
  bucket.answer = 200;
  const db = sampleDb(3);
  const before = startBackups({ db, env: envFor(), fetchImpl: fetch, firstRunMs: 3_600_000, ...quiet() });
  const after = startBackups({ db, env: envFor({ BACKUP_AGE_RECIPIENT: newRecipient }), fetchImpl: fetch, firstRunMs: 3_600_000, ...quiet() });
  try {
    assert.equal((await before.runNow()).ok, true);
    assert.equal((await after.runNow()).ok, true);
    const [oldReq, newReq] = bucket.requests;
    assert.ok(oldReq.url.includes(`.key-${recipientId(recipient)}.`));
    assert.ok(newReq.url.includes(`.key-${recipientId(newRecipient)}.`));
    assert.notEqual(recipientId(recipient), recipientId(newRecipient));
    assert.equal(after.status().recipientId, recipientId(newRecipient));
    const open = async (id, body) => { const d = new Decrypter(); d.addIdentity(id); return gunzipSync(await d.decrypt(new Uint8Array(body))); };
    // The new key opens the new backup; the old key does not.
    assert.equal(new Database(await open(newIdentity, newReq.body)).prepare('SELECT count(*) AS n FROM records').get().n, 3);
    await assert.rejects(open(identity, newReq.body));
    // And the old backup needs the old key, which is what destroying it takes away.
    await assert.rejects(open(newIdentity, oldReq.body));
    assert.ok((await open(identity, oldReq.body)).length > 0);
  } finally {
    before.stop();
    after.stop();
  }
});
