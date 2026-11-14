// A lab's key published on the lab's own domain (lineage/lab-domain.mjs): the file and the
// TXT record are read strictly, private addresses are never fetched, a look is recorded as
// seen, and a key the lab removes stops showing at the next look.
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { generateKeypair } from 'veilcore-records';
import { registrationPayload } from '../lineage/attesters.mjs';
import { checkLabDomain, cleanDomain, domainClaimPayload, fetchLabFile, isPublicAddress, readLabFile, readLabTxt } from '../lineage/lab-domain.mjs';
import { createServer as createHttpsServer } from 'node:https';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { untilReady } from './helpers.mjs';

process.env.DB_PATH = ':memory:';
const require = createRequire(import.meta.url);
const { app, setLabDomainOptions, relookLabDomains } = require('../server.js');

const K = 'ab'.repeat(32);
const file = (keys, extra = {}) => JSON.stringify({ format: 'veilcore-lab/v1', name: 'Acme Labs', keys: keys.map((publicKey) => ({ publicKey })), ...extra });

test('the file: only the v1 format, only well-formed keys, the name without hidden characters', () => {
  assert.deepEqual(readLabFile(file([K]), K), { ok: true, listed: true, name: 'Acme Labs' });
  assert.equal(readLabFile(file([K.toUpperCase()]), K).listed, true);
  assert.equal(readLabFile(file(['cd'.repeat(32)]), K).listed, false);
  assert.equal(readLabFile(file([K], { format: 'veilcore-lab/v2' }), K).ok, false);
  assert.equal(readLabFile('not json', K).ok, false);
  assert.equal(readLabFile(file(Array(65).fill(K)), K).ok, false);
  assert.equal(readLabFile(file([K], { name: 'Acme‮Labs' }), K).name, undefined);
});

test('the TXT record: exactly "veilcore-lab=v1 key=<hex>", split chunks joined', () => {
  assert.equal(readLabTxt([[`veilcore-lab=v1 key=${K}`]], K), true);
  assert.equal(readLabTxt([['veilcore-lab=v1 key=', K]], K), true);
  assert.equal(readLabTxt([[`veilcore-lab=v1 key=${K} extra`]], K), false);
  assert.equal(readLabTxt([[`key=${K}`]], K), false);
  assert.equal(readLabTxt([], K), false);
});

test('domains and addresses: public names only; private, loopback and link-local refused', () => {
  assert.equal(cleanDomain('Acme-Labs.com.'), 'acme-labs.com');
  for (const bad of ['localhost', '127.0.0.1', 'acme.com:8443', 'https://acme.com', 'acme.com/x', '', 7]) assert.equal(cleanDomain(bad), undefined, String(bad));
  for (const ip of ['127.0.0.1', '10.1.2.3', '172.20.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '192.0.0.8', '192.0.2.1',
    '::1', '::', 'fd00::1', 'fe80::1', 'fec0::1', '::ffff:127.0.0.1', '::127.0.0.1', '2002:7f00:1::1', '2001:0:1::1', '2001:db8::1', '64:ff9b::7f00:1', 'ff02::1'])
    assert.equal(isPublicAddress(ip), false, ip);
  for (const ip of ['8.8.8.8', '1.1.1.1', '192.0.78.24', '2606:4700:4700::1111', '2a00:1450:4001::1', '::ffff:8.8.8.8']) assert.equal(isPublicAddress(ip), true, ip);
});

test('a host that resolves to a private address is never connected to', async () => {
  const out = await fetchLabFile('localhost');
  assert.deepEqual(out, { ok: false, why: 'not a public address' });
});

test('one deadline for the whole look: an https server that trickles its body is cut off', async () => {
  // A real TLS server for "trickle.test" that sends headers, then one byte every 100 ms.
  const dir = mkdtempSync(join(tmpdir(), 'trickle-'));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(dir, 'k.pem'), '-out', join(dir, 'c.pem'), '-days', '1', '-subj', '/CN=trickle.test', '-addext', 'subjectAltName=DNS:trickle.test'], { stdio: 'ignore' });
  const cert = readFileSync(join(dir, 'c.pem'));
  const srv = createHttpsServer({ key: readFileSync(join(dir, 'k.pem')), cert }, (req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    const t = setInterval(() => res.write(' '), 100);
    req.on('close', () => clearInterval(t));
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const t0 = Date.now();
  const out = await fetchLabFile('trickle.test', {
    port: srv.address().port,
    ca: cert,
    deadlineMs: 800,
    lookup: (h, o, cb) => (o?.all ? cb(null, [{ address: '127.0.0.1', family: 4 }]) : cb(null, '127.0.0.1', 4)),
  });
  srv.closeAllConnections?.();
  srv.close();
  rmSync(dir, { recursive: true, force: true });
  assert.deepEqual(out, { ok: false, why: 'timed out' });
  assert.ok(Date.now() - t0 < 3000, 'ended by the deadline, not the body');
});

test('a look: the file first, then DNS, and what was seen', async () => {
  const body = Buffer.from(file([K]));
  const seen = await checkLabDomain('acme-labs.com', K, { fetchFile: async () => ({ ok: true, body }), resolveTxt: async () => [] });
  assert.equal(seen.listed, true);
  assert.equal(seen.method, 'file');
  assert.equal(seen.listedName, 'Acme Labs');
  assert.match(seen.fileSha256, /^[0-9a-f]{64}$/);
  const dns = await checkLabDomain('acme-labs.com', K, { fetchFile: async () => ({ ok: false, why: 'HTTP 404' }), resolveTxt: async () => [[`veilcore-lab=v1 key=${K}`]] });
  assert.equal(dns.method, 'dns');
  const none = await checkLabDomain('acme-labs.com', K, { fetchFile: async () => ({ ok: false, why: 'HTTP 404' }), resolveTxt: async () => { throw new Error('ENOTFOUND'); } });
  assert.equal(none.listed, false);
  assert.match(none.why, /HTTP 404.*no TXT record/);
  assert.ok((await checkLabDomain('127.0.0.1', K)).error);
});

let base;
let server;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  await untilReady(base);
});
after(() => server.close());

const post = (path, body) => fetch(`${base}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

const signClaim = async (kp, domain, issuedAt) => {
  const priv = await crypto.subtle.importKey('pkcs8', Buffer.from(kp.privateKey, 'hex'), { name: 'Ed25519' }, false, ['sign']);
  const sig = await crypto.subtle.sign('Ed25519', priv, new TextEncoder().encode(domainClaimPayload({ publicKey: kp.publicKey, domain, issuedAt })));
  return { domain, issuedAt, signature: Buffer.from(sig).toString('hex') };
};

test('the route: only the key names its domain; the look is shown, and dropped when the lab removes the key', async () => {
  const kp = await generateKeypair();
  const other = await generateKeypair();
  const reg = { publicKey: kp.publicKey, issuedAt: Date.now(), displayName: 'Acme Labs', role: 'laboratory' };
  const priv = await crypto.subtle.importKey('pkcs8', Buffer.from(kp.privateKey, 'hex'), { name: 'Ed25519' }, false, ['sign']);
  reg.signature = Buffer.from(await crypto.subtle.sign('Ed25519', priv, new TextEncoder().encode(registrationPayload(reg)))).toString('hex');
  assert.equal((await post('/attesters', reg)).status, 200);

  let listed = [kp.publicKey];
  setLabDomainOptions({ fetchFile: async () => ({ ok: true, body: Buffer.from(file(listed)) }), resolveTxt: async () => [] });

  // A stranger can't name a domain for the lab's key: unsigned, or signed by another key.
  assert.equal((await post(`/attesters/${kp.publicKey}/domain`, { domain: 'acme-labs-official.co' })).status, 400);
  const forged = await signClaim(other, 'acme-labs-official.co', Date.now());
  assert.equal((await post(`/attesters/${kp.publicKey}/domain`, forged)).status, 400);
  // A signed claim for a different domain than the body names fails too.
  assert.equal((await post(`/attesters/${kp.publicKey}/domain`, { ...(await signClaim(kp, 'acme-labs.com', Date.now())), domain: 'evil.example' })).status, 400);

  const t1 = Date.now();
  const r = await post(`/attesters/${kp.publicKey}/domain`, await signClaim(kp, 'acme-labs.com', t1));
  assert.equal(r.status, 200);
  assert.equal((await r.json()).listed, true);
  assert.equal((await post(`/attesters/${kp.publicKey}/domain`, await signClaim(kp, 'acme-labs.com', t1 + 1))).status, 429, 'one look per ten minutes');
  assert.equal((await post(`/attesters/${kp.publicKey}/domain`, await signClaim(kp, 'old-domain.com', t1 - 1000))).status, 400, 'an older claim is refused');

  const a = await (await fetch(`${base}/attesters/${kp.publicKey}`)).json();
  assert.equal(a.domainCheck.domain, 'acme-labs.com');
  assert.equal(a.domainCheck.method, 'file');
  assert.equal(a.vetted, false, 'a domain listing is not the operator name check');

  assert.equal(typeof a.domainCheck.claim.signature, 'string', 'the signed claim is served, so anyone can check it');
  assert.equal(a.domainCheck.claim.issuedAt, t1);

  listed = [];
  await relookLabDomains(0);
  const after = await (await fetch(`${base}/attesters/${kp.publicKey}`)).json();
  assert.equal(after.domainCheck, null, 'removed from the lab file: no longer shown');
  setLabDomainOptions({});
});
