// RFC 3161 timestamps on batch roots (lineage/tsa.mjs): a request openssl reads, a token
// from a real (local, openssl) TSA verified before it is stored, refused when it stamps
// something else or answers another nonce, and served in proofs, evidence and as root.tst
// that `openssl ts -verify` accepts. No network beyond 127.0.0.1.
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createRequire } from 'node:module';
import { timestampTokenBytes, verifyTimestampToken } from 'veilcore-records';
import { X509Certificate } from 'node:crypto';
import { requestTimestamp, timeStampRequest, tokenCertificates, tsaConfig } from '../lineage/tsa.mjs';
import { createBatches } from '../lineage/batches.mjs';

const require = createRequire(import.meta.url);
const Database = require('better-sqlite3');

let dir;

// DER surgery for the third check's attack (5 Nov 2026): a token signed by another key whose
// certificate claims the pinned certificate's issuer and serial with a leading zero added.
const tlv = (b, at) => { let len = b[at + 1], h = 2; if (len & 0x80) { const n = len & 0x7f; len = 0; for (let i = 0; i < n; i++) len = len * 256 + b[at + 2 + i]; h = 2 + n; } return { tag: b[at], s: at + h, e: at + h + len, w: b.subarray(at, at + h + len) }; };
const kidsOf = (b, n) => { const o = []; for (let a = n.s; a < n.e; ) { const k = tlv(b, a); o.push(k); a = k.e; } return o; };
const enc = (tag, ...parts) => { const body = Buffer.concat(parts); const n = body.length; const l = n < 0x80 ? Buffer.from([n]) : n < 0x100 ? Buffer.from([0x81, n]) : n < 0x10000 ? Buffer.from([0x82, n >> 8, n & 255]) : Buffer.from([0x83, n >> 16, (n >> 8) & 255, n & 255]); return Buffer.concat([Buffer.from([tag]), l, body]); };
const forgeAs = (tok, pinnedDer) => {
  const pb = Buffer.from(pinnedDer);
  const pf = kidsOf(pb, kidsOf(pb, tlv(pb, 0))[0]);
  const pk = pf[0].tag === 0xa0 ? 1 : 0;
  const pad = Buffer.concat([Buffer.from([0]), pb.subarray(pf[pk].s, pf[pk].e)]);
  const pIssuer = Buffer.from(pf[pk + 2].w);
  const b = Buffer.from(tok); const [ct, ex] = kidsOf(b, tlv(b, 0)); const sd = kidsOf(b, kidsOf(b, ex)[0]);
  const ci = sd.findIndex((k) => k.tag === 0xa0);
  const other = kidsOf(b, sd[ci]).find((c) => !Buffer.from(c.w).equals(pb));
  const cc = kidsOf(b, other); const tbs = kidsOf(b, cc[0]); const k = tbs[0].tag === 0xa0 ? 1 : 0;
  const forgedCert = enc(0x30, enc(0x30, ...tbs.map((x, i) => (i === k ? enc(0x02, pad) : i === k + 2 ? pIssuer : Buffer.from(x.w)))), Buffer.from(cc[1].w), Buffer.from(cc[2].w));
  const [si] = kidsOf(b, sd[sd.length - 1]);
  const nsi = enc(0x30, ...kidsOf(b, si).map((x, i) => (i === 1 ? enc(0x30, pIssuer, enc(0x02, pad)) : Buffer.from(x.w))));
  const nsd = sd.map((x, i) => (i === ci ? enc(0xa0, pb, forgedCert) : i === sd.length - 1 ? enc(0x31, nsi) : Buffer.from(x.w)));
  return enc(0x30, Buffer.from(ct.w), enc(0xa0, enc(0x30, ...nsd)));
};
// The security re-check's attack (20 Nov 2026): the forger's own certificate given a second
// extensions block naming the pinned certificate's key identifier, and the signer named by that
// identifier. veilcore-records keeps the last identifier, so checks the forger's signature with
// the forger's key; a reader that keeps the first finds the pinned certificate instead.
const skiOf = (der) => {
  const tbs = kidsOf(der, kidsOf(der, tlv(der, 0))[0]);
  const [list] = kidsOf(der, tbs.find((x) => x.tag === 0xa3));
  for (const e of kidsOf(der, list)) {
    const parts = kidsOf(der, e);
    if (Buffer.from(parts[0].w).equals(Buffer.from('0603551d0e', 'hex'))) {
      const inner = tlv(der, parts[parts.length - 1].s);
      return Buffer.from(der.subarray(inner.s, inner.e));
    }
  }
  throw new Error('no subject key identifier');
};
const twoBlockForgery = (tok, pinnedDer) => {
  const pinned = Buffer.from(pinnedDer);
  const pinnedSki = skiOf(pinned);
  const b = Buffer.from(tok); const [ct, ex] = kidsOf(b, tlv(b, 0)); const sd = kidsOf(b, kidsOf(b, ex)[0]);
  const ci = sd.findIndex((k) => k.tag === 0xa0);
  const cc = kidsOf(b, kidsOf(b, sd[ci]).find((c) => !Buffer.from(c.w).equals(pinned)));
  const second = enc(0xa3, enc(0x30, enc(0x30, Buffer.from('0603551d0e', 'hex'), enc(0x04, enc(0x04, pinnedSki)))));
  const certA = enc(0x30, enc(0x30, ...kidsOf(b, cc[0]).map((x) => Buffer.from(x.w)), second), Buffer.from(cc[1].w), Buffer.from(cc[2].w));
  const [si] = kidsOf(b, sd[sd.length - 1]);
  const nsi = enc(0x30, ...kidsOf(b, si).map((x, i) => (i === 0 ? enc(0x02, Buffer.from([3])) : i === 1 ? enc(0x80, pinnedSki) : Buffer.from(x.w))));
  const nsd = sd.map((x, i) => (i === ci ? enc(0xa0, certA, pinned) : i === sd.length - 1 ? enc(0x31, nsi) : Buffer.from(x.w)));
  return enc(0x30, Buffer.from(ct.w), enc(0xa0, enc(0x30, ...nsd)));
};
let tsa; // { url, server, mode }
const ssl = (...args) => execFileSync('openssl', args, { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] });

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'tsa-'));
  writeFileSync(join(dir, 'ext.cnf'), 'extendedKeyUsage = critical,timeStamping\nbasicConstraints = CA:FALSE\n');
  ssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '2', '-subj', '/CN=Test TSA Root');
  ssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'tsa.key', '-out', 'tsa.csr', '-subj', '/CN=Test TSA');
  ssl('x509', '-req', '-in', 'tsa.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'tsa.pem', '-days', '2', '-extfile', 'ext.cnf');
  // Another key with the same name, self-issued: it must never pass as the pinned TSA.
  ssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'evil.key', '-out', 'evil.pem', '-days', '2', '-subj', '/CN=Test TSA', '-addext', 'extendedKeyUsage=critical,timeStamping');
  writeFileSync(join(dir, 'tsa.cnf'), `[ tsa ]\ndefault_tsa = t\n[ t ]\ndir = ${dir}\nserial = ${dir}/serial\nsigner_cert = ${dir}/tsa.pem\nsigner_key = ${dir}/tsa.key\nsigner_digest = sha256\ndefault_policy = 1.2.3.4.1\ndigests = sha256\ness_cert_id_alg = sha256\naccuracy = secs:1\nordering = no\ntsa_name = no\ness_cert_id_chain = no\ncerts = ${dir}/tsa.pem\n`);
  writeFileSync(join(dir, 'serial'), '01\n');
  tsa = { mode: 'ok' };
  tsa.server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      let q = Buffer.concat(chunks);
      if (tsa.mode === 'other') q = timeStampRequest(Buffer.alloc(32, 7)).der; // stamps something else
      writeFileSync(join(dir, 'q.tsq'), q);
      if (tsa.mode === 'evil') ssl('ts', '-reply', '-config', 'tsa.cnf', '-queryfile', 'q.tsq', '-signer', 'evil.pem', '-inkey', 'evil.key', '-chain', 'tsa.pem', '-out', 'r.tsr');
      else ssl('ts', '-reply', '-config', 'tsa.cnf', '-queryfile', 'q.tsq', '-out', 'r.tsr');
      res.setHeader('content-type', 'application/timestamp-reply');
      const reply = readFileSync(join(dir, 'r.tsr'));
      const pinnedDer = new X509Certificate(readFileSync(join(dir, 'tsa.pem'))).raw;
      res.end(tsa.forge === 'two-blocks' ? twoBlockForgery(timestampTokenBytes(reply), pinnedDer) : tsa.forge ? forgeAs(timestampTokenBytes(reply), pinnedDer) : reply);
    });
  });
  await new Promise((r) => tsa.server.listen(0, '127.0.0.1', r));
  tsa.url = `http://127.0.0.1:${tsa.server.address().port}/`;
});
after(() => {
  tsa.server.close();
  rmSync(dir, { recursive: true, force: true });
});

const ROOT = 'c3'.repeat(32);

test('the request is a TimeStampReq openssl reads: SHA-256 of the 32 root bytes, a nonce, certReq', () => {
  const { der } = timeStampRequest(Buffer.from(ROOT, 'hex'));
  writeFileSync(join(dir, 'mine.tsq'), der);
  const text = ssl('ts', '-query', '-in', 'mine.tsq', '-text').toString();
  assert.match(text, /Hash Algorithm: sha256/);
  assert.match(text, /Nonce: 0x/);
  assert.match(text, /Certificate required: yes/);
  const want = execFileSync('openssl', ['dgst', '-sha256', '-r'], { input: Buffer.from(ROOT, 'hex') }).toString().slice(0, 64);
  const imprint = [...text.matchAll(/^\s+[0-9a-f]{4} - (.{47})/gm)].map((m) => m[1].replace(/[\s-]/g, '')).join('');
  assert.equal(imprint, want, 'the imprint is SHA-256 of the raw root');
});

test('settings: off unless set; https, or http with a pin; no secret in the address; qualified only as stated', () => {
  assert.equal(tsaConfig({}), null);
  assert.ok(tsaConfig({ VEILCORE_TSA_URL: 'https://u:p@tsa.example/' }).error);
  assert.ok(tsaConfig({ VEILCORE_TSA_URL: 'https://tsa.example/?apikey=x' }).error, 'the URL is published');
  assert.ok(tsaConfig({ VEILCORE_TSA_URL: 'ftp://tsa.example/' }).error);
  assert.ok(tsaConfig({ VEILCORE_TSA_URL: 'http://tsa.example/' }).error, 'http needs a pin');
  const pin = 'ab'.repeat(32);
  assert.deepEqual(tsaConfig({ VEILCORE_TSA_URL: 'http://tsa.example/', VEILCORE_TSA_SIGNER_SHA256: pin }).pins, [pin]);
  assert.ok(tsaConfig({ VEILCORE_TSA_URL: 'http://tsa.example/', VEILCORE_TSA_SIGNER_SHA256: pin, VEILCORE_TSA_AUTHORIZATION: 'Basic x' }).error);
  assert.equal(tsaConfig({ VEILCORE_TSA_URL: 'https://tsa.example/' }).qualified, null);
  assert.deepEqual(tsaConfig({ VEILCORE_TSA_URL: 'https://tsa.example/', VEILCORE_TSA_QUALIFIED_SCHEME: 'eIDAS', VEILCORE_TSA_TRUSTED_LIST: 'https://eidas.ec.europa.eu/efda/tl-browser/' }).qualified,
    { scheme: 'eIDAS', trustedList: 'https://eidas.ec.europa.eu/efda/tl-browser/' });
  assert.ok(tsaConfig({ VEILCORE_TSA_URL: 'https://tsa.example/', VEILCORE_TSA_QUALIFIED_SCHEME: 'yes' }).error);
});

const fingerprint = () => new X509Certificate(readFileSync(join(dir, 'tsa.pem'))).fingerprint256.replace(/:/g, '').toLowerCase();

test('a pinned TSA: only a token signed by that certificate is kept; the time must be now', async () => {
  tsa.mode = 'ok';
  const pinned = await requestTimestamp(ROOT, { url: tsa.url, pins: [fingerprint()] });
  assert.ok(pinned.token, pinned.error);
  assert.ok(tokenCertificates(Buffer.from(pinned.token, 'base64')).length >= 1);
  const other = await requestTimestamp(ROOT, { url: tsa.url, pins: ['cd'.repeat(32)] });
  assert.equal(other.error, 'TSA token is not signed by the pinned certificate');
  // Signed by another key of the same name, carrying the pinned certificate beside it.
  tsa.mode = 'evil';
  const evil = await requestTimestamp(ROOT, { url: tsa.url, pins: [fingerprint()] });
  assert.equal(evil.error, 'TSA token is not signed by the pinned certificate');
  assert.ok((await requestTimestamp(ROOT, { url: tsa.url })).token, 'unpinned, the same token verifies: the pin is what refuses it');
  // The same, with its certificate claiming the pinned one's issuer and a zero-padded serial.
  tsa.forge = true;
  assert.ok((await requestTimestamp(ROOT, { url: tsa.url })).token, 'the forged token still verifies unpinned');
  assert.equal((await requestTimestamp(ROOT, { url: tsa.url, pins: [fingerprint()] })).error, 'TSA token is not signed by the pinned certificate');
  // And with a second extensions block naming the pinned certificate's key identifier.
  tsa.forge = 'two-blocks';
  assert.ok((await requestTimestamp(ROOT, { url: tsa.url })).token, 'the two-block forgery verifies unpinned: the attack is real');
  assert.equal((await requestTimestamp(ROOT, { url: tsa.url, pins: [fingerprint()] })).error, 'TSA token is not signed by the pinned certificate');
  tsa.forge = false;
  tsa.mode = 'ok';
  const late = await requestTimestamp(ROOT, { url: tsa.url }, { now: () => Date.now() + 3_600_000 });
  assert.equal(late.error, 'TSA token time is not now');
});

test('a reply too large, or too slow, ends as an error', async () => {
  const big = await requestTimestamp(ROOT, { url: 'http://x/' }, { fetchImpl: async () => new Response(new Uint8Array(70_000)) });
  assert.equal(big.error, 'TSA reply too large');
  const slow = await requestTimestamp(ROOT, { url: 'http://x/' }, { fetchImpl: async () => { throw new DOMException('timeout', 'TimeoutError'); } });
  assert.match(slow.error, /too slow/);
});

test('a token is kept only when it verifies against this root', async () => {
  tsa.mode = 'ok';
  const good = await requestTimestamp(ROOT, { url: tsa.url });
  assert.ok(good.token, good.error);
  assert.match(good.genTime, /^\d{4}-\d{2}-\d{2}T/);
  assert.equal((await verifyTimestampToken(good.token, Buffer.from(ROOT, 'hex'))).ok, true);
  tsa.mode = 'other';
  const bad = await requestTimestamp(ROOT, { url: tsa.url });
  assert.match(bad.error, /did not verify|nonce/);
  tsa.mode = 'ok';
  assert.match((await requestTimestamp(ROOT, { url: 'http://127.0.0.1:1/' })).error, /could not reach the TSA/);
});

test('every batch gets one, as root.tst that openssl verifies, with the stated scheme and a note', async () => {
  const db = new Database(':memory:');
  const batches = createBatches(db);
  db.prepare(`INSERT INTO batches (batch_id, root, sealed_at, record_count) VALUES ('B-1', ?, ?, 1)`).run(ROOT, Date.now());
  const cfg = { url: tsa.url, pins: [], qualified: { scheme: 'eIDAS' } };
  const out = await batches.tsaMaintenance(cfg, { request: requestTimestamp });
  assert.equal(out.length, 1);
  assert.ok(out[0].genTime, out[0].error);
  assert.deepEqual(await batches.tsaMaintenance(cfg, { request: requestTimestamp }), [], 'a batch is stamped once');

  const { token } = batches.tsaFor('B-1');
  writeFileSync(join(dir, 'root.bin'), Buffer.from(ROOT, 'hex'));
  writeFileSync(join(dir, 'root.tst'), token);
  const ok = ssl('ts', '-verify', '-data', 'root.bin', '-in', 'root.tst', '-token_in', '-CAfile', 'ca.pem', '-untrusted', 'tsa.pem').toString();
  assert.match(ok, /Verification: OK/);
  const entry = db.prepare('SELECT tsa_qualified FROM batches').get();
  assert.deepEqual(JSON.parse(entry.tsa_qualified), { scheme: 'eIDAS' });
  db.close();
});
