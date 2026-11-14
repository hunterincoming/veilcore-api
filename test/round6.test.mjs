// Round 6 (17 Oct 2026, the site's CONTRACT.md #33, #34, #37): the fixes for the fifth
// review's findings, each with the test that fails before and passes after.
//   #33  a record may carry `nameCode`, the salted code of its name: 64 lowercase hex or
//        absent, stored and served publicly (feature name-code-v1);
//   #34  a lab report signature made before round 6 signs the report's plain SHA-256: served
//        whole only to the delivery's sender and lab (holder key); one made since has an id
//        ending _ld1 (feature lab-doc-binding-v1). Finding 3: a stranger with only the record
//        id got the report's exact SHA-256. Since 8 Nov 2026 neither form is shown to anyone
//        else at all, not even as "a lab signed a report" (hide-lab-reports.test.mjs);
//   #37  the purge deletes dnaFileSha256 and dnaFingerprint from every grant's values
//        (finding 7), and the guarded run reports, never strips, a clear name a sealed row's
//        box doesn't hold (finding 8; round5-names.test.mjs has the counts).
// No network.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createCipheriv, createHash, randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';
import { canonicalise, sha256Hex, newNonce, generateKeypair, signAttestation, verifyAttestation } from 'veilcore-records';
import { untilReady, testBody, sealForTest, vaultKeyFor, kidOf, rememberSigner, labKeyProofHeader } from './helpers.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
const require = createRequire(import.meta.url);
const { app, db } = require('../server.js');

const key = () => randomBytes(32).toString('hex');
let base, server;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  await untilReady(base);
});
after(() => server.close());

const call = async (method, path, holder, body) => {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { 'content-type': 'application/json', 'x-forwarded-for': `10.${randomBytes(3).join('.')}`, ...(holder ? { 'x-holder-key': holder } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(testBody(method, path, holder, body)) }),
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, json };
};
const sha = (v) => createHash('sha256').update(v).digest('hex');

test('/health lists name-code-v1 and lab-doc-binding-v1, for the site’s deploy preflights', async () => {
  const h = (await call('GET', '/health')).json;
  assert.ok(h.features.includes('name-code-v1'), JSON.stringify(h));
  assert.ok(h.features.includes('lab-doc-binding-v1'), JSON.stringify(h));
});

test('#33 (finding 2): nameCode is stored and served publicly; anything but 64 lowercase hex is refused', async () => {
  const holder = key();
  const committed = { breedingMethod: '', bredBy: 'B', dateCreated: '2026-01-01', loggedAt: 1760000000000,
    nonce: newNonce(), notes: '', parents: [], photoFingerprints: [], refId: '', strainName: 'Name Code Plant' };
  const fp = await sha256Hex(canonicalise(committed));
  const salt = randomBytes(32).toString('hex');
  const nameCode = sha(Buffer.concat([Buffer.from('veilcore:name:v1\0'), Buffer.from(committed.strainName), Buffer.from(`\0${fp}\0${salt}`)]));
  const id = `NC-${randomBytes(4).toString('hex')}`;
  const row = (over = {}) => ({ ...sealForTest({ id, ...committed, recordFingerprint: fp, nameSalt: salt }, vaultKeyFor(holder)), nameCode, ...over });
  for (const bad of ['A'.repeat(64), 'ab', 7, 'x'.repeat(64)]) {
    const r = await call('PUT', '/api/records', holder, [row({ nameCode: bad })]);
    assert.ok(r.status === 400 || (r.json.rejected ?? []).length === 1, `${String(bad)}: ${JSON.stringify(r.json)}`);
    assert.match(JSON.stringify(r.json), /nameCode must be 64 lowercase hexadecimal characters/);
  }
  const ok = await call('PUT', '/api/records', holder, [row()]);
  assert.equal(ok.json.count, 1, JSON.stringify(ok.json));
  const v = (await call('GET', `/verify/${id}`)).json;
  assert.equal(v.nameCode, nameCode);
  assert.equal(v.cultivar, undefined, 'the name itself is never served');
  assert.ok(!JSON.stringify(v).includes(committed.strainName));
  assert.equal(JSON.parse(db.prepare('SELECT body FROM records WHERE id = ?').get(id).body).nameCode, nameCode);
});

/** A sender with a sealed record, an offer, and a lab that claimed it (as lab-results.test.mjs). */
const delivery = async () => {
  const committed = { breedingMethod: '', bredBy: 'B', dateCreated: '2026-01-01', loggedAt: '2026-01-01T00:00:00Z',
    nonce: newNonce(), notes: '', parents: [], photoFingerprints: [], refId: '', strainName: 'S' };
  const src = { id: `r6-${randomBytes(4).toString('hex')}`, ...committed, recordFingerprint: await sha256Hex(canonicalise(committed)) };
  const sender = key(), lab = key();
  assert.equal((await call('PUT', '/api/records', sender, [src])).status, 200);
  const o = await call('POST', '/transfers', sender, { sourceRecord: src.id, toHandle: 'lab@x' });
  assert.equal(o.status, 200, JSON.stringify(o.json));
  assert.equal((await call('POST', `/transfers/${o.json.transferId}/claim`, lab, { claimCode: o.json.claimCode })).status, 200);
  return { sender, lab, transferId: o.json.transferId, fingerprint: src.recordFingerprint, recordId: src.id };
};
const labSigns = async (kp, subjectCommitment, documentHash, suffix = '') => {
  const signed = await signAttestation({
    attestationId: `att_${randomBytes(8).toString('hex')}${suffix}`, type: 'laboratory-report', subjectCommitment, documentHash,
    hashAlgorithm: 'sha256', issuedAt: '2026-10-17T09:00:00Z', attester: { publicKey: kp.publicKey, displayName: 'Round Six Lab' },
  }, kp.privateKey);
  const r = await call('POST', '/attestations', null, signed);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  rememberSigner(signed.attestationId, kp);
  return signed;
};
const sendsBack = async (d, attestationId) => {
  const res = await fetch(`${base}/transfers/${d.transferId}/results?attestationId=${attestationId}`, {
    method: 'POST',
    headers: { 'content-type': 'application/octet-stream', 'x-holder-key': d.lab, ...(await labKeyProofHeader(d.transferId, attestationId)) },
    body: Buffer.concat([Buffer.from('age-encryption.org/v1\n-> X25519 abc\n'), randomBytes(64)]),
  });
  assert.equal(res.status, 200, await res.text());
};
const listed = async (fp, holder) => (await call('GET', `/attestations/subject/${fp}`, holder)).json.attestations;

test('#34 (finding 3): a lab report signed over the plain SHA-256 is never shown to strangers, whole for its sender and lab', async () => {
  const d = await delivery();
  const kp = await generateKeypair();
  const report = Buffer.from(`%PDF-1.7 round 6 genotype report ${randomBytes(4).toString('hex')}`);
  const old = await labSigns(kp, d.fingerprint, sha(report));
  await sendsBack(d, old.attestationId);

  // The attack (attack5.spec.ts finding1): only the record's proof code, no key, no file from
  // the holder. Before round 6, documentHash was the report's SHA-256; until 8 Nov 2026 a stub
  // still said a lab signed, and when. Now nothing, and no count.
  for (const who of [null, key()]) {
    const r = (await call('GET', `/attestations/subject/${d.fingerprint}`, who)).json;
    assert.deepEqual([r.attestations, r.total], [[], 0]);
  }
  // The embed and /verify say nothing of the hash either.
  const embed = await (await fetch(`${base}/embed/${encodeURIComponent(d.recordId)}`)).text();
  assert.match(embed, /vc-/, 'the embed answered');
  assert.ok(!embed.includes(sha(report)));
  assert.ok(!JSON.stringify((await call('GET', `/verify/${d.recordId}`)).json).includes(sha(report)));

  // The delivery's sender and lab, by holder key: whole, and it verifies.
  for (const who of [d.sender, d.lab]) {
    const [a] = await listed(d.fingerprint, who);
    assert.equal(a.documentHash, sha(report));
    const { strength, vettedAttester, registeredAs, retraction, ...asSigned } = a;
    void strength; void vettedAttester; void registeredAs; void retraction;
    assert.equal(await verifyAttestation(asSigned), true);
  }
  // The sender keeps it after deleting the report's file (it is their record's delivery).
  const results = (await call('GET', `/transfers/${d.transferId}/results`, d.sender)).json.results;
  assert.equal((await call('DELETE', `/transfers/${d.transferId}/results/${results[0].id}`, d.sender)).status, 200);
  assert.equal((await listed(d.fingerprint, d.sender))[0].documentHash, sha(report));
  assert.deepEqual(await listed(d.fingerprint, key()), []);
});

test('#34: a lab report signed since round 6 (bound, id ending _ld1) verifies for its sender and lab, and strangers get nothing', async () => {
  const d = await delivery();
  const kp = await generateKeypair();
  const bound = sha(randomBytes(32));
  const signed = await labSigns(kp, d.fingerprint, bound, '_ld1');
  await sendsBack(d, signed.attestationId);
  assert.deepEqual(await listed(d.fingerprint, null), []);
  for (const who of [d.sender, d.lab]) {
    const [a] = await listed(d.fingerprint, who);
    assert.equal(a.attestationId, signed.attestationId);
    assert.equal(a.documentHash, bound);
    assert.equal(a.documentWithheld, undefined);
    const { strength, vettedAttester, registeredAs, retraction, ...asSigned } = a;
    void strength; void vettedAttester; void registeredAs; void retraction;
    assert.equal(await verifyAttestation(asSigned), true);
  }
});

test('#37 (finding 7, old-grant-purge.py): the purge deletes plain DNA values from every grant, guarded or not', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'veilcore-r6-'));
  try {
    const file = join(dir, 'g.db');
    const f = new Database(file);
    for (const { sql } of db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name IN ('records', 'licenses', 'transfers', 'disclosure_grants')").all()) f.exec(sql);
    const box = { v: 1, alg: 'A256GCM', kid: '0'.repeat(16), iv: 'A'.repeat(16), ct: 'A'.repeat(24) };
    const SHA = 'ab'.repeat(32), PFP = 'cd'.repeat(32), BIND = 'ef'.repeat(32);
    const ins = f.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?,?,?,?,?)');
    ins.run('G-1', 'h1:converted', JSON.stringify({ id: 'G-1', recordFingerprint: '11'.repeat(32), sealed: box }), 1, 1);
    // A holder who never came back: no sealed row at all.
    ins.run('G-2', 'h1:away', JSON.stringify({ id: 'G-2', strainName: 'x', notes: 'n', recordFingerprint: '22'.repeat(32) }), 1, 1);
    const g = f.prepare('INSERT INTO disclosure_grants (record_id, holder_key, show, updated_at, grant_values, for_fingerprint) VALUES (?,?,?,?,?,?)');
    g.run('G-1', 'h1:converted', '["existence","attestation-status"]', 1, JSON.stringify({ dnaFingerprint: PFP, dnaFileSha256: SHA, dnaPairBinding: BIND }), '11'.repeat(32));
    g.run('G-2', 'h1:away', '["existence","attestation-status"]', 1, JSON.stringify({ dnaFingerprint: PFP, dnaFileSha256: SHA }), '22'.repeat(32));
    f.close();
    const purge = fileURLToPath(new URL('../scripts/purge-plaintext.mjs', import.meta.url));
    const run = (...flags) => execFileSync(process.execPath, [purge, '--db', file, ...flags], { encoding: 'utf8' });
    assert.match(run(), /DNA values grants published before round 5 [^:]*: 2 grants to clear of them \(for every holder, converted or not\)/);
    assert.match(run('--apply', '--vacuum'), /2 grants cleared of them/);
    const raw = new Database(file, { readonly: true });
    const values = (id) => JSON.parse(raw.prepare('SELECT grant_values FROM disclosure_grants WHERE record_id = ?').get(id).grant_values);
    assert.deepEqual(values('G-1'), { dnaPairBinding: BIND }, 'the bound value stays');
    assert.deepEqual(values('G-2'), {});
    raw.close();
    const bytes = readFileSync(file).toString('latin1');
    assert.ok(!bytes.includes(SHA) && !bytes.includes(PFP), 'the plain SHA-256 and pairing code are not in the file');
    assert.match(run(), /: 0 grants to clear of them/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('#37 (finding 8, purge-name-loss.mjs): the guarded purge keeps the only copy of a name; the two-flag run says it is gone for good', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'veilcore-r6n-'));
  try {
    const file = join(dir, 'n.db');
    const f = new Database(file);
    for (const { sql } of db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name IN ('records', 'licenses', 'transfers', 'disclosure_grants')").all()) f.exec(sql);
    const vault = randomBytes(32);
    const kid = kidOf(vault);
    const seal = (id, obj) => {
      const iv = randomBytes(12);
      const c = createCipheriv('aes-256-gcm', vault, iv);
      c.setAAD(Buffer.from(`veilcore:sealed:v1\0records\0${id}\0${kid}`));
      const ct = Buffer.concat([c.update(JSON.stringify(obj)), c.final(), c.getAuthTag()]);
      return { v: 1, alg: 'A256GCM', kid, iv: iv.toString('base64url'), ct: ct.toString('base64url') };
    };
    const A = 'VEIL-' + 'A'.repeat(32), B = 'VEIL-' + 'B'.repeat(32);
    const ins = f.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?,?,?,?,?)');
    ins.run(A, 'h1:x', JSON.stringify({ id: A, rev: 2, recordFingerprint: '11'.repeat(32), sealed: seal(A, { strainName: 'Name A', rev: 2 }) }), 1, 1);
    ins.run(B, 'h1:x', JSON.stringify({ id: B, strainName: 'Only copy of name B', rev: 1, recordFingerprint: '22'.repeat(32), sealed: seal(B, { bredBy: 'y', rev: 1 }) }), 1, 1);
    f.close();
    const purge = fileURLToPath(new URL('../scripts/purge-plaintext.mjs', import.meta.url));
    const out = execFileSync(process.execPath, [purge, '--db', file, '--apply'], { encoding: 'utf8' });
    assert.match(out, /record names in the clear: 1 on sealed rows locked before names went inside the lock \(reported, not removed/);
    assert.doesNotMatch(out, /or backup/);
    const body = () => JSON.parse(new Database(file, { readonly: true }).prepare('SELECT body FROM records WHERE id = ?').get(B).body);
    assert.equal(body().strainName, 'Only copy of name B');
    const all = execFileSync(process.execPath, [purge, '--db', file, '--apply', '--include-unconverted', '--i-understand-this-deletes-text'], { encoding: 'utf8' });
    assert.match(all, /record names in the clear: 1 removed \(--include-unconverted\)\. A sealed row's name removed this way is gone for good/);
    assert.doesNotMatch(all, /or backup/);
    assert.equal(body().strainName, undefined);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
