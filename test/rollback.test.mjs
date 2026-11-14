// Round 2 (8 Oct 2026, MEDIUM 4): this version, then a rollback to the code before it, then
// this version again. And the deploy overlap, when the old container still answers
// requests after the new one has converted the database. Rows the old code writes there
// carry holder keys in plain text and transfers without the new columns: every one must
// still work. No network.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { canonicalise, sha256Hex, newNonce } from 'veilcore-records';
import { untilReady, testBody } from './helpers.mjs';

const require = createRequire(import.meta.url);
const { storedHolderKey, STORED_PREFIX, HOLDER_KEY_COLUMNS } = require('../holder-key.js');
const dir = mkdtempSync(join(tmpdir(), 'veilcore-rollback-'));
const file = join(dir, 'registry.db');
const SENDER = randomBytes(32).toString('hex'), LAB = randomBytes(32).toString('hex'), LATE = randomBytes(32).toString('hex');
const committedOf = (r) => ({ breedingMethod: r.breedingMethod ?? '', bredBy: r.bredBy, dateCreated: r.dateCreated,
  loggedAt: r.loggedAt, nonce: r.nonce, notes: r.notes, parents: r.parents ?? [],
  photoFingerprints: r.photoFingerprints ?? [], refId: r.refId ?? '', strainName: r.strainName });
const makeRecord = async (id) => {
  const r = { id, strainName: 'S' + id, bredBy: 'B', dateCreated: '2026-01-01', loggedAt: '2026-01-01T00:00:00Z',
    nonce: newNonce(), notes: 'n', parents: [], photoFingerprints: [], breedingMethod: 'm', refId: '' };
  r.recordFingerprint = await sha256Hex(canonicalise(committedOf(r)));
  return r;
};
const rb = await makeRecord('RB-SRC');
const late = await makeRecord('LATE-REC');
{
  const d = new Database(file);
  d.exec(readFileSync(new URL('./fixtures/registry-before-8oct.sql', import.meta.url), 'utf8'));
  // 1. This version starts: keys converted, transfers get their new columns.
  const { createLineage } = await import('../lineage/routes.mjs');
  const { createTransfers } = await import('../lineage/transfer.mjs');
  createTransfers(d, createLineage(d), {});
  // 2. Rolled back: the old code stores a record and makes an offer, with plain-text keys
  //    and none of the new columns filled.
  d.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?,?,?,?,?)').run(rb.id, SENDER, JSON.stringify(rb), Date.now(), Date.now());
  d.prepare(`INSERT INTO transfers (id, source_record, from_holder, to_handle, claim_code, created_at) VALUES ('TR-RB000001', ?, ?, 'lab@x', 'c0de', ?)`).run(rb.id, SENDER, Date.now());
  d.close();
}
// 3. This version again.
process.env.DB_PATH = file;
process.env.VEILCORE_OTS = 'off';
const { app, db } = require('../server.js');
let base, server;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  await untilReady(base);
});
after(() => { server.close(); db.close(); rmSync(dir, { recursive: true, force: true }); });

const call = async (method, path, holder, body) => {
  const res = await fetch(`${base}${path}`, {
    method, headers: { 'content-type': 'application/json', ...(holder ? { 'x-holder-key': holder } : {}) },
    body: body === undefined ? undefined : JSON.stringify(testBody(method, path, holder, body)),
  });
  return { status: res.status, json: await res.json() };
};

test('MEDIUM 4: an offer made by the old code during a rollback is claimable after redeploying', async () => {
  const t = db.prepare("SELECT from_holder, source_fingerprint FROM transfers WHERE id = 'TR-RB000001'").get();
  assert.equal(t.from_holder, storedHolderKey(SENDER), 'its key converted at start');
  assert.equal(t.source_fingerprint, rb.recordFingerprint, 'its fingerprint filled in at start, as it is now');
  const c = await call('POST', '/transfers/TR-RB000001/claim', LAB, { claimCode: 'c0de' });
  assert.equal(c.status, 200, JSON.stringify(c.json));
  assert.equal(db.prepare("SELECT received_record FROM transfers WHERE id = 'TR-RB000001'").get().received_record, c.json.recordId);
});

test('MEDIUM 4: rows the old code writes while this version runs (deploy overlap) are found with the key as sent', async () => {
  // The old container, still answering, writes in plain text after this one converted.
  db.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?,?,?,?,?)').run(late.id, LATE, JSON.stringify(late), Date.now(), Date.now());
  db.prepare('INSERT INTO licenses (id, holder_key, record_id, body, updated_at) VALUES (?,?,?,?,?)').run('LATE-LIC', LATE, late.id, JSON.stringify({ id: 'LATE-LIC' }), Date.now());
  db.prepare('INSERT INTO disclosure_grants (record_id, holder_key, show, updated_at) VALUES (?,?,?,?)').run(late.id, LATE, '["existence"]', Date.now());
  db.prepare(`INSERT INTO transfers (id, source_record, from_holder, to_handle, claim_code, created_at) VALUES ('TR-LATE0001', ?, ?, 'lab@x', 'c0de2', ?)`).run(late.id, LATE, Date.now());

  assert.deepEqual((await call('GET', '/api/records', LATE)).json.map((r) => r.id), [late.id]);
  assert.deepEqual((await call('GET', '/api/licenses', LATE)).json.map((l) => l.id), ['LATE-LIC']);
  assert.deepEqual((await call('GET', `/api/records/${late.id}/disclosure`, LATE)).json.show, ['existence']);
  assert.equal((await call('GET', '/transfers/sent', LATE)).json.total, 1);
  // Converted as they were found: nothing of LATE's is left in plain text.
  for (const [t, c] of HOLDER_KEY_COLUMNS) {
    assert.equal(db.prepare(`SELECT COUNT(*) AS n FROM ${t} WHERE ${c} = ?`).get(LATE).n, 0, `${t}.${c}`);
  }
  // The overlap offer has no fingerprint recorded; it is claimable, and records one.
  const c = await call('POST', '/transfers/TR-LATE0001/claim', LAB, { claimCode: 'c0de2' });
  assert.equal(c.status, 200, JSON.stringify(c.json));
  assert.equal(db.prepare("SELECT source_fingerprint FROM transfers WHERE id = 'TR-LATE0001'").get().source_fingerprint, late.recordFingerprint);
});

test('MEDIUM 4: an offer with a recorded fingerprint whose source changed says exactly that', async () => {
  const src = await makeRecord('CHG-SRC');
  await call('PUT', '/api/records', SENDER, [src]);
  const o = (await call('POST', '/transfers', SENDER, { sourceRecord: src.id, toHandle: 'chg@x' })).json;
  await call('PUT', '/api/records', SENDER, [{ ...(await makeRecord('CHG-SRC')) }]);
  const c = await call('POST', `/transfers/${o.transferId}/claim`, LAB, { claimCode: o.claimCode });
  assert.equal(c.status, 400);
  assert.match(c.json.error, /fingerprint has changed since this offer was made/);
});

test('MEDIUM 4: the periodic pass converts plain-text rows of holders who make no request', async () => {
  const QUIET = randomBytes(32).toString('hex');
  db.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?,?,?,?,?)').run('QUIET-1', QUIET, '{}', 1, 1);
  const { convertPlaintextNow } = require('../server.js');
  convertPlaintextNow();
  assert.equal(db.prepare("SELECT holder_key FROM records WHERE id = 'QUIET-1'").get().holder_key, storedHolderKey(QUIET));
  assert.ok(db.prepare('SELECT holder_key FROM records').all().every((r) => r.holder_key.startsWith(STORED_PREFIX)));
});
