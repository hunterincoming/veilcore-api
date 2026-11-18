// A lab's key published on the lab's own domain (lineage/lab-domain.mjs): the file and the
// TXT record are read strictly, private addresses are never fetched, a look is recorded as
// seen, and a key the lab removes stops showing at the next look.
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { generateKeypair } from 'veilcore-records';
import { registrationPayload } from '../lineage/attesters.mjs';
import { base58btc, checkLabDomain, ed25519FromMultibase, cleanDomain, domainClaimPayload, ed25519Multibase, fetchLabFile, isPublicAddress, readDidDoc, readLabFile, readLabTxt } from '../lineage/lab-domain.mjs';
import { createServer as createHttpsServer } from 'node:https';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { untilReady } from './helpers.mjs';

process.env.DB_PATH = ':memory:';
const require = createRequire(import.meta.url);
const { app, setLabDomainOptions, relookLabDomains, lastDomainLookReset } = require('../server.js');

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
  const gone = async () => ({ ok: false, why: 'HTTP 404', status: 404 });
  const noTxt = async () => { throw Object.assign(new Error('queryTxt ENOTFOUND'), { code: 'ENOTFOUND' }); };
  const none = await checkLabDomain('acme-labs.com', K, { fetchFile: gone, resolveTxt: noTxt });
  assert.equal(none.listed, false);
  assert.equal(none.answered, true, 'a 404 and no TXT record are real answers');
  assert.match(none.why, /HTTP 404.*no TXT record/);
  assert.ok((await checkLabDomain('127.0.0.1', K)).error);
});

const DID = 'did:web:acme-labs.com';
const didDoc = (vm, assertion = [vm.id], extra = {}) => JSON.stringify({ '@context': ['https://www.w3.org/ns/did/v1'], id: DID, verificationMethod: [vm], assertionMethod: assertion, ...extra });

test('the multibase form of an Ed25519 key is did:key\'s (z6Mk…), both ways', () => {
  // The first example key in the did:key spec.
  const vector = 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
  const hex = ed25519FromMultibase(vector);
  assert.match(hex, /^[0-9a-f]{64}$/);
  assert.equal(ed25519Multibase(hex), vector);
  assert.match(ed25519Multibase(K), /^z6Mk/);
  assert.equal(ed25519FromMultibase(ed25519Multibase(K)), K);
  assert.equal(ed25519FromMultibase('z' + base58btc(Uint8Array.from([0xe7, 0x01, ...Buffer.from(K, 'hex')]))), undefined, 'a secp256k1 prefix is not Ed25519');
  assert.equal(base58btc(Uint8Array.from([0, 0, 1])), '112');
});

test('did:web: the key as an assertionMethod of did:web:<domain>, Multikey or JWK; nothing borrowed', () => {
  const mb = { id: `${DID}#lab-1`, type: 'Multikey', controller: DID, publicKeyMultibase: ed25519Multibase(K) };
  assert.deepEqual(readDidDoc(didDoc(mb), K, 'acme-labs.com'), { ok: true, listed: true, did: DID, keyId: `${DID}#lab-1` });
  assert.equal(readDidDoc(didDoc({ ...mb, type: 'Ed25519VerificationKey2020' }), K, 'acme-labs.com').listed, true);
  const jwk = { id: `${DID}#key-0`, type: 'JsonWebKey2020', controller: DID, publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(K, 'hex').toString('base64url') } };
  assert.equal(readDidDoc(didDoc(jwk), K, 'acme-labs.com').listed, true);
  // Embedded in assertionMethod rather than referenced.
  assert.equal(readDidDoc(JSON.stringify({ id: DID, assertionMethod: [mb] }), K, 'acme-labs.com').listed, true);
  // Only for signing statements: a key listed for authentication alone doesn't count.
  assert.equal(readDidDoc(didDoc(mb, [], { authentication: [mb.id] }), K, 'acme-labs.com').listed, false);
  // Another DID's document, another DID's method, or another controller: not this website's word.
  assert.equal(readDidDoc(didDoc(mb), K, 'acme-lab.com').ok, false);
  assert.equal(readDidDoc(didDoc({ ...mb, id: 'did:web:evil.example#k' }), K, 'acme-labs.com').listed, false);
  assert.equal(readDidDoc(didDoc({ ...mb, controller: 'did:web:evil.example' }), K, 'acme-labs.com').listed, false);
  assert.equal(readDidDoc(didDoc({ ...mb, id: '#lab-1' }, ['#lab-1']), K, 'acme-labs.com').listed, false, 'relative ids refused (did:web)');
  // A private key in the document is never read as a public one.
  assert.equal(readDidDoc(didDoc({ ...jwk, publicKeyJwk: { ...jwk.publicKeyJwk, d: 'x' } }), K, 'acme-labs.com').listed, false);
  assert.equal(readDidDoc(didDoc({ ...mb, publicKeyMultibase: ed25519Multibase('cd'.repeat(32)) }), K, 'acme-labs.com').listed, false);
});

test('a look finds the key in did.json when there is no lab file', async () => {
  const mb = { id: `${DID}#lab-1`, type: 'Multikey', controller: DID, publicKeyMultibase: ed25519Multibase(K) };
  const seen = await checkLabDomain('acme-labs.com', K, {
    fetchFile: async () => ({ ok: false, why: 'HTTP 404', status: 404 }),
    fetchDid: async () => ({ ok: true, body: Buffer.from(didDoc(mb)) }),
    resolveTxt: async () => [],
  });
  assert.equal(seen.method, 'did');
  assert.equal(seen.did, DID);
  assert.equal(seen.didKeyId, `${DID}#lab-1`);
  assert.match(seen.fileSha256, /^[0-9a-f]{64}$/);
});

test('an outage is never a withdrawal: timeouts, 5xx and broken files are not answers', async () => {
  const ok404 = async () => ({ ok: false, why: 'HTTP 404', status: 404 });
  const noTxt = async () => { throw Object.assign(new Error('x'), { code: 'ENODATA' }); };
  for (const [name, opts] of [
    ['file timed out', { fetchFile: async () => ({ ok: false, why: 'timed out' }), fetchDid: ok404, resolveTxt: noTxt }],
    ['file 503', { fetchFile: async () => ({ ok: false, why: 'HTTP 503', status: 503 }), fetchDid: ok404, resolveTxt: noTxt }],
    ['file not JSON', { fetchFile: async () => ({ ok: true, body: Buffer.from('<html>') }), fetchDid: ok404, resolveTxt: noTxt }],
    ['did.json unreachable', { fetchFile: ok404, fetchDid: async () => ({ ok: false, why: 'could not connect' }), resolveTxt: noTxt }],
    ['DNS failed', { fetchFile: ok404, fetchDid: ok404, resolveTxt: async () => { throw Object.assign(new Error('x'), { code: 'ESERVFAIL' }); } }],
  ]) {
    const out = await checkLabDomain('acme-labs.com', K, opts);
    assert.equal(out.listed, false, name);
    assert.equal(out.answered, false, name);
  }
  const fileWithout = await checkLabDomain('acme-labs.com', K, { fetchFile: async () => ({ ok: true, body: Buffer.from(file(['cd'.repeat(32)])) }), fetchDid: ok404, resolveTxt: noTxt });
  assert.equal(fileWithout.answered, true, 'a good file without the key is an answer');
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

  // The website is down: not a withdrawal, the old look stays (and ages out after 7 days).
  setLabDomainOptions({ fetchFile: async () => ({ ok: false, why: 'timed out' }), resolveTxt: async () => [] });
  await relookLabDomains(0);
  const down = await (await fetch(`${base}/attesters/${kp.publicKey}`)).json();
  assert.equal(down.domainWithdrawn, null, 'an outage is not a withdrawal');

  setLabDomainOptions({ fetchFile: async () => ({ ok: true, body: Buffer.from(file(listed)) }), fetchDid: async () => ({ ok: false, why: 'HTTP 404', status: 404 }), resolveTxt: async () => { throw Object.assign(new Error('x'), { code: 'ENODATA' }); } });
  listed = [];
  await relookLabDomains(0);
  const after = await (await fetch(`${base}/attesters/${kp.publicKey}`)).json();
  assert.equal(after.domainCheck, null, 'removed from the lab file: no longer shown as listed');
  assert.equal(after.domainWithdrawn.domain, 'acme-labs.com', 'shown as withdrawn instead');
  assert.match(after.domainWithdrawn.withdrawnAt, /^\d{4}-/);
  assert.equal(after.domainWithdrawn.claim.issuedAt, t1, 'with the key\'s claim, so a page can check the key named it');

  // Whoever has the key can't point it at a lookalike and wipe the withdrawal.
  lastDomainLookReset();
  const moved = await post(`/attesters/${kp.publicKey}/domain`, await signClaim(kp, 'acme-1abs.com', Date.now()));
  assert.equal(moved.status, 409);
  assert.deepEqual(Object.fromEntries(Object.entries(await moved.json()).filter(([k]) => k !== 'error')), { code: 'withdrawn', domain: 'acme-labs.com' });

  // Kept at later looks, and not forgotten after 30 days.
  await relookLabDomains(0);
  assert.equal((await (await fetch(`${base}/attesters/${kp.publicKey}`)).json()).domainWithdrawn.domain, 'acme-labs.com');

  // The website lists it again: listed, no longer withdrawn.
  listed = [kp.publicKey];
  await relookLabDomains(0);
  const back = await (await fetch(`${base}/attesters/${kp.publicKey}`)).json();
  assert.equal(back.domainCheck.domain, 'acme-labs.com');
  assert.equal(back.domainWithdrawn, null);
  setLabDomainOptions({});
});

test('a domain that never listed the key is not "withdrawn"', async () => {
  const kp = await generateKeypair();
  const reg = { publicKey: kp.publicKey, issuedAt: Date.now(), displayName: 'Beta Labs', role: 'laboratory' };
  const priv = await crypto.subtle.importKey('pkcs8', Buffer.from(kp.privateKey, 'hex'), { name: 'Ed25519' }, false, ['sign']);
  reg.signature = Buffer.from(await crypto.subtle.sign('Ed25519', priv, new TextEncoder().encode(registrationPayload(reg)))).toString('hex');
  assert.equal((await post('/attesters', reg)).status, 200);
  setLabDomainOptions({ fetchFile: async () => ({ ok: false, why: 'HTTP 404', status: 404 }), resolveTxt: async () => { throw Object.assign(new Error('x'), { code: 'ENODATA' }); } });
  const r = await post(`/attesters/${kp.publicKey}/domain`, await signClaim(kp, 'beta-labs.com', Date.now()));
  assert.equal(r.status, 200);
  assert.equal((await r.json()).listed, false);
  await relookLabDomains(0);
  const a = await (await fetch(`${base}/attesters/${kp.publicKey}`)).json();
  assert.equal(a.domainCheck, null);
  assert.equal(a.domainWithdrawn, null);
  // Still free to name another website.
  lastDomainLookReset();
  assert.equal((await post(`/attesters/${kp.publicKey}/domain`, await signClaim(kp, 'beta-labs.org', Date.now()))).status, 200);
  setLabDomainOptions({});
});
