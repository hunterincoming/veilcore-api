// The whole loop, on a stand-in bucket: a backup made, lab files sent once each, then put
// back with restore.mjs, from a downloaded file and from the bucket, checked, and the file it
// replaces kept. A wrong key, a damaged file and an existing target are refused. No network.
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { existsSync, mkdtempSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createRequire } from 'node:module';
import { generateX25519Identity, identityToRecipient } from 'age-encryption';
import { startBackups } from '../backup.mjs';
import { restore, identityFrom } from '../restore.mjs';

const require = createRequire(import.meta.url);
const Database = require('better-sqlite3');

let identity;
let bucket; // { base, objects: Map, puts }
let dir;
before(async () => {
  identity = await generateX25519Identity();
  const objects = new Map();
  const box = { objects, puts: [] };
  box.server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const u = new URL(req.url, 'http://x');
      const key = decodeURIComponent(u.pathname.split('/').slice(2).join('/'));
      if (req.method === 'PUT') {
        objects.set(key, Buffer.concat(chunks));
        box.puts.push(key);
        res.end('');
      } else if (u.searchParams.get('list-type') === '2') {
        const prefix = u.searchParams.get('prefix') ?? '';
        const keys = [...objects.keys()].filter((k) => k.startsWith(prefix));
        res.end(`<ListBucketResult>${keys.map((k) => `<Contents><Key>${k}</Key></Contents>`).join('')}<IsTruncated>false</IsTruncated></ListBucketResult>`);
      } else if (objects.has(key)) res.end(objects.get(key));
      else {
        res.statusCode = 404;
        res.end('<Error><Code>NoSuchKey</Code></Error>');
      }
    });
  });
  await new Promise((r) => box.server.listen(0, '127.0.0.1', r));
  box.base = `http://127.0.0.1:${box.server.address().port}`;
  bucket = box;
  dir = mkdtempSync(join(tmpdir(), 'restore-'));
});
after(() => {
  bucket.server.close();
  rmSync(dir, { recursive: true, force: true });
});

const env = async (over = {}) => ({
  BACKUP_AGE_RECIPIENT: await identityToRecipient(identity),
  BACKUP_S3_ENDPOINT: bucket.base,
  BACKUP_S3_BUCKET: 'veilcore-backups-test',
  BACKUP_S3_KEY_ID: '005a1b2c3d4e5f60000000042',
  BACKUP_S3_SECRET: 'K005-very-secret-application-key-value',
  BACKUP_S3_REGION: 'us-west-004',
  VEILCORE_ANCHOR_NETWORK: 'mainnet',
  AGE_IDENTITY: `my key: ${identity}  `,
  ...over,
});

const quiet = () => ({ log: () => {}, error: () => {} });

test('a backup and its lab files go up, and come back whole', async () => {
  const live = join(dir, 'live.db');
  const db = new Database(live);
  db.exec('CREATE TABLE records (id TEXT PRIMARY KEY, body TEXT)');
  const ins = db.prepare('INSERT INTO records VALUES (?, ?)');
  for (let i = 0; i < 500; i++) ins.run(`rec-${i}`, 'x'.repeat(500));
  const labDir = join(dir, 'lab-results');
  mkdirSync(labDir);
  writeFileSync(join(labDir, 'RESULT0000000001'), 'locked-bytes-1');
  writeFileSync(join(labDir, 'RESULT0000000002'), 'locked-bytes-2');
  writeFileSync(join(labDir, '.veilcore-store-id'), 'not a result');

  const b = startBackups({ db, labDir, env: await env(), fetchImpl: fetch, firstRunMs: 3_600_000, ...quiet() });
  try {
    const out = await b.runNow();
    assert.equal(out.ok, true);
    assert.equal(out.records, 500);
    assert.equal(out.labFilesSent, 2);
    // No temporary copy left beside the live file.
    assert.deepEqual(readdirSync(dir).filter((n) => n.startsWith('.veilcore-backup-')), []);
    // A second run sends the database again, and only new lab files.
    writeFileSync(join(labDir, 'RESULT0000000003'), 'locked-bytes-3');
    const again = await b.runNow();
    assert.equal(again.labFilesSent, 1);
    assert.equal(b.status().large, false);
  } finally {
    b.stop();
  }
  const object = [...bucket.objects.keys()].find((k) => k.endsWith('.sqlite.gz.age'));
  assert.ok(object);

  // The drill: a downloaded file, opened and checked, nothing live touched.
  const downloaded = join(dir, 'downloaded.sqlite.gz.age');
  writeFileSync(downloaded, bucket.objects.get(object));
  const drill = await restore({ from: { file: downloaded }, to: join(dir, 'restored.db'), env: await env(), ...quiet() });
  assert.equal(drill.records, 500);

  // A real restore, from the bucket, over a damaged live file, with the lab files.
  db.close();
  writeFileSync(live, 'this is not a database any more');
  writeFileSync(`${live}-journal`, 'stale journal');
  rmSync(labDir, { recursive: true, force: true });
  const r = await restore({ from: { object }, to: live, replace: true, labDir, env: await env(), fetchImpl: fetch, ...quiet() });
  assert.equal(r.records, 500);
  assert.equal(r.labFiles, 3);
  assert.equal(readFileSync(join(labDir, 'RESULT0000000002'), 'utf8'), 'locked-bytes-2');
  assert.ok(r.keptAs && existsSync(r.keptAs), 'the file it replaced is kept');
  assert.equal(existsSync(`${live}-journal`), false, 'the stale journal is moved aside');
  const back = new Database(live, { readonly: true });
  assert.equal(back.prepare('SELECT count(*) n FROM records').get().n, 500);
  back.close();
});

test('refusals: no key, a wrong key, a damaged file, an existing target', async () => {
  const object = [...bucket.objects.keys()].find((k) => k.endsWith('.sqlite.gz.age'));
  const file = join(dir, 'b.age');
  writeFileSync(file, bucket.objects.get(object));
  assert.throws(() => identityFrom('nothing here'), /no age private key/);
  const other = await generateX25519Identity();
  await assert.rejects(
    restore({ from: { file }, to: join(dir, 'x1.db'), env: await env({ AGE_IDENTITY: other }), ...quiet() }),
    /does not open that backup/,
  );
  const damaged = join(dir, 'damaged.age');
  const bytes = Buffer.from(bucket.objects.get(object));
  bytes[bytes.length - 20] ^= 0xff;
  writeFileSync(damaged, bytes);
  await assert.rejects(restore({ from: { file: damaged }, to: join(dir, 'x2.db'), env: await env(), ...quiet() }));
  assert.equal(existsSync(join(dir, 'x2.db')), false, 'nothing half-written is left under the target name');
  writeFileSync(join(dir, 'taken.db'), 'x');
  await assert.rejects(restore({ from: { file }, to: join(dir, 'taken.db'), env: await env(), ...quiet() }), /exists/);
});

test('GET /alerts: 200 when fine, 503 with short codes when not', async () => {
  process.env.DB_PATH = ':memory:';
  process.env.VEILCORE_OTS = 'off';
  for (const k of Object.keys(process.env)) if (k.startsWith('BACKUP_') || k.startsWith('RAILWAY_')) delete process.env[k];
  const { app } = require('../server.js');
  const server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  try {
    const r = await fetch(`http://127.0.0.1:${server.address().port}/alerts`);
    assert.equal(r.status, 200);
    const body = await r.json();
    assert.deepEqual(Object.keys(body).sort(), ['ok', 'problems']);
    // In memory, off Railway, no backups set up: nothing to alarm on.
    assert.deepEqual(body, { ok: true, problems: [] });
    // On Railway with no backups set up: 503, so a plain HTTP monitor alarms.
    process.env.RAILWAY_ENVIRONMENT = 'production';
    const bad = await fetch(`http://127.0.0.1:${server.address().port}/alerts`);
    assert.equal(bad.status, 503);
    assert.deepEqual(await bad.json(), { ok: false, problems: ['backup-off'] });
  } finally {
    delete process.env.RAILWAY_ENVIRONMENT;
    server.close();
  }
});
