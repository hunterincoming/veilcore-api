// OpenTimestamps files written by lineage/ots.mjs, checked against the OpenTimestamps
// project's own parser (Python). Skipped where that library is not installed.
// SPDX-License-Identifier: Apache-2.0

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { stampRoot, otsFile, childrenOf, rootFile } from '../lineage/ots.mjs';

const py = fileURLToPath(new URL('./fixtures/ots_reference.py', import.meta.url));
let hasReference = true;
try { execFileSync('python3', ['-c', 'import opentimestamps'], { stdio: 'ignore' }); } catch { hasReference = false; }
const ref = (...args) => execFileSync('python3', [py, ...args], { encoding: 'utf8' }).trim();

const ROOT = 'ab'.repeat(32);
const digest = createHash('sha256').update(Buffer.from(ROOT, 'hex')).digest();

test('the stamped file is the batch root as 32 raw bytes', () => {
  assert.equal(rootFile(ROOT).toString('hex'), ROOT);
  assert.throws(() => rootFile('AB'.repeat(32)));
  assert.throws(() => rootFile('ab'));
});

test('a .ots built from calendar answers parses with the reference implementation', { skip: !hasReference }, () => {
  const answers = ref('answers', digest.toString('hex')).split('\n').map((h) => Buffer.from(h, 'hex'));
  const ots = otsFile(digest, answers);
  const parsed = JSON.parse(ref('parse', ots.toString('hex')));
  assert.equal(parsed.digest, digest.toString('hex'));
  assert.match(parsed.op, /sha256/i);
  // Both calendars' pending attestations and the block-header attestation survive the merge.
  assert.deepEqual(parsed.attestations, [
    'BitcoinBlockHeaderAttestation:800000',
    'PendingAttestation:https://a.pool.opentimestamps.org',
    'PendingAttestation:https://b.pool.opentimestamps.org',
  ]);
});

test('stampRoot posts the digest to every calendar and keeps the ones that answer', { skip: !hasReference }, async () => {
  // Answers shaped like a real calendar's: a pending attestation naming the calendar asked.
  // (Before the 4 Oct attack, this used answers naming other calendars and carrying a
  // Bitcoin attestation, both of which are now refused in a fresh answer.)
  const [a, b] = ref('fresh', digest.toString('hex'), 'https://a.pool.opentimestamps.org', 'https://b.pool.opentimestamps.org').split('\n');
  const seen = [];
  const fakeFetch = async (url, init) => {
    seen.push({ url, body: Buffer.from(init.body).toString('hex') });
    if (url.startsWith('https://down.example')) throw new Error('connection refused');
    if (url.startsWith('https://garbage.example')) return new Response(Buffer.from([0x99, 0x01]));
    return new Response(Buffer.from(url.includes('a.pool') ? a : b, 'hex'));
  };
  const out = await stampRoot(ROOT, {
    calendars: ['https://a.pool.opentimestamps.org', 'https://b.pool.opentimestamps.org', 'https://down.example', 'https://garbage.example'],
    fetchImpl: fakeFetch,
  });
  assert.equal(seen.length, 4);
  for (const s of seen) assert.equal(s.body, digest.toString('hex'), 'each calendar receives SHA-256(root.bin)');
  assert.deepEqual(out.calendars.sort(), ['https://a.pool.opentimestamps.org', 'https://b.pool.opentimestamps.org']);
  assert.equal(out.failures.length, 2, 'a calendar that is down, or answers garbage, is reported and not stored');
  const parsed = JSON.parse(ref('parse', out.ots.toString('hex')));
  assert.equal(parsed.attestations.length, 2);
});

test('no calendar answering is an error, not an empty proof', async () => {
  await assert.rejects(stampRoot(ROOT, { calendars: ['https://down.example'], fetchImpl: async () => { throw new Error('down'); } }), /no OpenTimestamps calendar answered/);
});

test('malformed answers are refused', () => {
  assert.throws(() => childrenOf(Buffer.from([0x99])), /unknown timestamp tag/);
  assert.throws(() => childrenOf(Buffer.from([0xf0, 0x05, 0x01])), /truncated/);
  assert.throws(() => childrenOf(Buffer.from([0x08])), /truncated/);
  assert.throws(() => otsFile(digest, []), /no calendar answered/);
});

test('a sealed batch is stamped, served and named in every inclusion proof', { skip: !hasReference }, async () => {
  const { default: Database } = await import('better-sqlite3');
  const { createBatches } = await import('../lineage/batches.mjs');
  process.env.VEILCORE_OTS = 'off'; // stamped explicitly below, with fake calendars
  const db = new Database(':memory:');
  db.exec('CREATE TABLE records (id TEXT PRIMARY KEY, body TEXT)');
  const c1 = 'c1'.repeat(32);
  const c2 = 'c2'.repeat(32);
  db.prepare('INSERT INTO records VALUES (?, ?)').run('r1', JSON.stringify({ recordFingerprint: c1 }));
  db.prepare('INSERT INTO records VALUES (?, ?)').run('r2', JSON.stringify({ recordFingerprint: c2 }));
  const batches = createBatches(db);
  const sealed = await batches.seal();
  assert.equal(sealed.opentimestamps, 'off');
  assert.equal(batches.otsFor(sealed.batchId).ots, null);

  const d = createHash('sha256').update(Buffer.from(sealed.root, 'hex')).digest();
  const answer = ref('fresh', d.toString('hex'), 'https://b.pool.opentimestamps.org');
  const out = await batches.stamp(sealed.batchId, {
    calendars: ['https://b.pool.opentimestamps.org'],
    fetchImpl: async () => new Response(Buffer.from(answer, 'hex')),
  });
  assert.deepEqual(out.calendars, ['https://b.pool.opentimestamps.org']);
  const stored = batches.otsFor(sealed.batchId);
  const parsed = JSON.parse(ref('parse', stored.ots.toString('hex')));
  assert.equal(parsed.digest, d.toString('hex'), 'the .ots commits to SHA-256 of the batch root bytes');

  const proof = batches.proofFor(c1);
  const ots = proof.anchors.find((a) => a.kind === 'opentimestamps');
  assert.equal(ots.ots, `/batches/${sealed.batchId}/root.bin.ots`);
  assert.equal(proof.root, sealed.root);
});
