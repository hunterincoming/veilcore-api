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
const { app, db, setLabDomainOptions, relookLabDomains, lastDomainLookReset } = require('../server.js');

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

test('did.json is optional: a single-page host\'s HTML is "nothing here"; a 403 host never answers', async () => {
  const lab = async () => ({ ok: true, body: Buffer.from(file([])) });
  const noTxt = async () => { throw Object.assign(new Error('x'), { code: 'ENODATA' }); };
  const spa = await checkLabDomain('acme-labs.com', K, { fetchFile: lab, fetchDid: async () => ({ ok: true, body: Buffer.from('<!doctype html><html>app</html>') }), resolveTxt: noTxt });
  assert.equal(spa.answered, true);
  const notDid = await checkLabDomain('acme-labs.com', K, { fetchFile: lab, fetchDid: async () => ({ ok: true, body: Buffer.from('{"hello":1}') }), resolveTxt: noTxt });
  assert.equal(notDid.answered, true, 'JSON without an id is not a DID document');
  // A DID document for another DID is a broken one, not an answer.
  const otherDid = await checkLabDomain('acme-labs.com', K, { fetchFile: lab, fetchDid: async () => ({ ok: true, body: Buffer.from('{"id":"did:web:other.example"}') }), resolveTxt: noTxt });
  assert.equal(otherDid.answered, false);
  // The lab file stays strict: HTML there is never an answer.
  const spaFile = await checkLabDomain('acme-labs.com', K, { fetchFile: async () => ({ ok: true, body: Buffer.from('<html>') }), fetchDid: async () => ({ ok: false, why: 'HTTP 404', status: 404 }), resolveTxt: noTxt });
  assert.equal(spaFile.answered, false);
  const s3 = await checkLabDomain('acme-labs.com', K, { fetchFile: lab, fetchDid: async () => ({ ok: false, why: 'HTTP 403', status: 403 }), resolveTxt: noTxt });
  assert.equal(s3.answered, false, 'a 403 is not "not here": documented, such hosts can\'t record a withdrawal');
});

test('did:web: a verification method must name its controller', () => {
  const vm = { id: `${DID}#lab-1`, type: 'Multikey', publicKeyMultibase: ed25519Multibase(K) };
  assert.equal(readDidDoc(didDoc(vm), K, 'acme-labs.com').listed, false);
  assert.equal(readDidDoc(didDoc({ ...vm, controller: DID }), K, 'acme-labs.com').listed, true);
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

const H = 3_600_000;
const T0 = Date.parse('2026-12-01T00:00:00Z');
const g404 = async () => ({ ok: false, why: 'HTTP 404', status: 404 });
const noTxt = async () => { throw Object.assign(new Error('x'), { code: 'ENODATA' }); };
const get = async (k) => (await fetch(`${base}/attesters/${k}`)).json();
const register = async (name = 'Acme Labs') => {
  const kp = await generateKeypair();
  const reg = { publicKey: kp.publicKey, issuedAt: Date.now(), displayName: name, role: 'laboratory' };
  const priv = await crypto.subtle.importKey('pkcs8', Buffer.from(kp.privateKey, 'hex'), { name: 'Ed25519' }, false, ['sign']);
  reg.signature = Buffer.from(await crypto.subtle.sign('Ed25519', priv, new TextEncoder().encode(registrationPayload(reg)))).toString('hex');
  assert.equal((await post('/attesters', reg)).status, 200);
  return kp;
};
/**
 * A stand-in web: `sites[domain]` is the list of keys its lab file lists, 'down' (timed out),
 * or missing (404). did.json is always 404, DNS has no record. Looks happen at `clock.t`.
 */
const web = (sites, clock) => {
  setLabDomainOptions({
    fetchFile: async (d) => {
      if (clock.stall?.[d]) await clock.stall[d];
      const v = sites[d];
      if (v === 'down') return { ok: false, why: 'timed out' };
      if (!v) return { ok: false, why: 'HTTP 404', status: 404 };
      return { ok: true, body: Buffer.from(file(v)) };
    },
    fetchDid: g404,
    resolveTxt: noTxt,
    now: () => clock.t,
  });
  lastDomainLookReset();
};
let seq = 0;
const claim = async (kp, domain, issuedAt = Date.now() + seq++) => {
  lastDomainLookReset();
  return post(`/attesters/${kp.publicKey}/domain`, await signClaim(kp, domain, issuedAt));
};
/** The daily look, at the clock's time (everything is due). */
const daily = () => relookLabDomains(-400 * 86_400_000);

test('the route: only the key names its domain; the look is shown', async () => {
  const kp = await register();
  const other = await generateKeypair();
  const clock = { t: Date.now() };
  const sites = { 'acme-labs.com': [kp.publicKey] };
  web(sites, clock);
  // A stranger can't name a domain for the lab's key: unsigned, or signed by another key.
  assert.equal((await post(`/attesters/${kp.publicKey}/domain`, { domain: 'acme-labs-official.co' })).status, 400);
  assert.equal((await post(`/attesters/${kp.publicKey}/domain`, await signClaim(other, 'acme-labs-official.co', Date.now()))).status, 400);
  assert.equal((await post(`/attesters/${kp.publicKey}/domain`, { ...(await signClaim(kp, 'acme-labs.com', Date.now())), domain: 'evil.example' })).status, 400);
  // A claim from the far future is refused, so it can't lock out every later one.
  assert.equal((await claim(kp, 'evil.example', Number.MAX_SAFE_INTEGER)).status, 400);

  const t1 = Date.now();
  const r = await claim(kp, 'acme-labs.com', t1);
  assert.equal(r.status, 200);
  assert.equal((await r.json()).listed, true);
  assert.equal((await post(`/attesters/${kp.publicKey}/domain`, await signClaim(kp, 'acme-labs.com', t1 + 1))).status, 429, 'one look per ten minutes');
  assert.equal((await claim(kp, 'old-domain.com', t1 - 1000)).status, 400, 'an older claim is refused');
  const a = await get(kp.publicKey);
  assert.equal(a.domainCheck.domain, 'acme-labs.com');
  assert.equal(a.domainCheck.method, 'file');
  assert.equal(a.vetted, false, 'a domain listing is not the operator name check');
  assert.equal(a.domainCheck.claim.issuedAt, t1, 'the signed claim is served, so anyone can check it');
  assert.equal(a.domainWithdrawn, null);
  setLabDomainOptions({});
});

test('A: a look that gets no answer keeps the listing (7-day rule), and is retried', async () => {
  const kp = await register();
  const clock = { t: Date.now() };
  const sites = { 'acme-labs.com': [kp.publicKey] };
  web(sites, clock);
  assert.equal((await claim(kp, 'acme-labs.com')).status, 200);
  sites['acme-labs.com'] = 'down';
  clock.t += H;
  await daily();
  const down = await get(kp.publicKey);
  assert.notEqual(down.domainCheck, null, 'one timeout doesn\'t hide the listing');
  assert.equal(down.domainCheck.domain, 'acme-labs.com');
  assert.equal(down.domainWithdrawn, null);
  setLabDomainOptions({});
});

test('E: a withdrawal needs two real "not here" answers at least 20 hours apart', async () => {
  const kp = await register();
  const clock = { t: T0 };
  const sites = { 'acme-labs.com': [kp.publicKey] };
  web(sites, clock);
  assert.equal((await claim(kp, 'acme-labs.com')).status, 200);
  // The host serves 404 for everything for an afternoon, then comes back.
  delete sites['acme-labs.com'];
  clock.t = T0 + 2 * H;
  await daily();
  clock.t = T0 + 10 * H;
  await daily();
  assert.equal((await get(kp.publicKey)).domainWithdrawn, null, 'not two answers 20 hours apart');
  sites['acme-labs.com'] = [kp.publicKey];
  clock.t = T0 + 24 * H;
  await daily();
  // Now the lab really takes it down: answered at +48 h and again at +70 h.
  delete sites['acme-labs.com'];
  clock.t = T0 + 48 * H;
  await daily();
  assert.equal((await get(kp.publicKey)).domainWithdrawn, null, 'one answer is not enough');
  clock.t = T0 + 70 * H;
  await daily();
  const w = (await get(kp.publicKey)).domainWithdrawn;
  assert.equal(w.domain, 'acme-labs.com');
  assert.equal(w.withdrawnAt, new Date(T0 + 70 * H).toISOString());
  assert.equal(typeof w.claim.signature, 'string', 'with the key\'s claim, so a page can check the key named it');

  // Sticky: the key can't name another website (whoever took it can't move it to a lookalike).
  const moved = await claim(kp, 'acme-1abs.com');
  assert.equal(moved.status, 409);
  const body = await moved.json();
  assert.equal(body.code, 'withdrawn');
  assert.equal(body.domain, 'acme-labs.com');
  // Kept for longer than 30 days of looks.
  clock.t = T0 + 70 * H + 31 * 86_400_000;
  await daily();
  assert.equal((await get(kp.publicKey)).domainWithdrawn.domain, 'acme-labs.com', 'not forgotten after 30 days');
  // Listed there again: cleared.
  sites['acme-labs.com'] = [kp.publicKey];
  clock.t += H;
  await daily();
  assert.equal((await get(kp.publicKey)).domainWithdrawn, null);
  setLabDomainOptions({});
});

test('B: a thief moves the key first; the lab taking it off its real website still withdraws it', async () => {
  const kp = await register();
  const B0 = Date.now() - 60 * H;
  const clock = { t: B0 };
  const sites = { 'acme-labs.com': [kp.publicKey], 'acme-1abs.com': [kp.publicKey] };
  web(sites, clock);
  assert.equal((await claim(kp, 'acme-labs.com')).status, 200);
  // The thief names a lookalike that lists the key.
  clock.t = B0 + H;
  assert.equal((await claim(kp, 'acme-1abs.com')).status, 200);
  assert.equal((await get(kp.publicKey)).domainCheck.domain, 'acme-1abs.com');
  // The lab takes the key off its real website; the daily looks still watch it.
  delete sites['acme-labs.com'];
  clock.t = B0 + 24 * H;
  await daily();
  clock.t = B0 + 48 * H;
  await daily();
  const a = await get(kp.publicKey);
  assert.equal(a.domainWithdrawn.domain, 'acme-labs.com');
  assert.equal(a.domainCheck, null, 'a withdrawn key isn\'t shown as listed anywhere');
  // The lab can also name its real website again with a fresh claim; the thief can't move it on.
  assert.equal((await claim(kp, 'acme-labs.com')).status, 200);
  assert.equal((await claim(kp, 'acme-lab5.com')).status, 409);
  setLabDomainOptions({});
});

test('F: a slow look can\'t overwrite a withdrawal, or a newer claim, recorded while it ran', async () => {
  const kp = await register();
  const clock = { t: T0, stall: {} };
  const sites = { 'acme-labs.com': [kp.publicKey], 'slow-1abs.com': [kp.publicKey] };
  web(sites, clock);
  assert.equal((await claim(kp, 'acme-labs.com')).status, 200);
  delete sites['acme-labs.com'];
  clock.t = T0 + 24 * H;
  await daily();
  // The thief starts a look at a lookalike that answers slowly.
  let release;
  clock.stall['slow-1abs.com'] = new Promise((r) => { release = r; });
  lastDomainLookReset();
  const thief = post(`/attesters/${kp.publicKey}/domain`, await signClaim(kp, 'slow-1abs.com', Date.now() + seq++));
  await new Promise((r) => setTimeout(r, 50));
  // Meanwhile the daily look records the real website's withdrawal.
  clock.t = T0 + 48 * H;
  await daily();
  assert.equal((await get(kp.publicKey)).domainWithdrawn.domain, 'acme-labs.com');
  release();
  assert.equal((await thief).status, 409, 'checked again right before the write');
  const a = await get(kp.publicKey);
  assert.equal(a.domainWithdrawn.domain, 'acme-labs.com');
  assert.equal(a.domainCheck, null);
  setLabDomainOptions({});
});

test('F: an older claim that finishes last doesn\'t overwrite a newer one', async () => {
  const kp = await register();
  const clock = { t: Date.now(), stall: {} };
  const sites = { 'acme-labs.com': [kp.publicKey], 'slow-labs.org': [kp.publicKey] };
  web(sites, clock);
  let release;
  clock.stall['slow-labs.org'] = new Promise((r) => { release = r; });
  const t1 = Date.now();
  lastDomainLookReset();
  const older = post(`/attesters/${kp.publicKey}/domain`, await signClaim(kp, 'slow-labs.org', t1));
  await new Promise((r) => setTimeout(r, 50));
  assert.equal((await claim(kp, 'acme-labs.com', t1 + 1000)).status, 200);
  release();
  assert.equal((await older).status, 400);
  assert.equal((await get(kp.publicKey)).domainCheck.domain, 'acme-labs.com');
  setLabDomainOptions({});
});

test('D: a single-page host (HTML for a missing did.json) can still record a withdrawal', async () => {
  const kp = await register();
  const clock = { t: T0 };
  let listed = [kp.publicKey];
  setLabDomainOptions({
    fetchFile: async () => ({ ok: true, body: Buffer.from(file(listed)) }),
    fetchDid: async () => ({ ok: true, body: Buffer.from('<!doctype html><html>app</html>') }),
    resolveTxt: noTxt,
    now: () => clock.t,
  });
  assert.equal((await claim(kp, 'acme-labs.com')).status, 200);
  listed = [];
  clock.t = T0 + 24 * H;
  await daily();
  clock.t = T0 + 48 * H;
  await daily();
  assert.equal((await get(kp.publicKey)).domainWithdrawn.domain, 'acme-labs.com');
  setLabDomainOptions({});
});

test('deploy day: a key taken off its website before this version never turns "withdrawn"', async () => {
  const kp = await register();
  // A record as the previous version wrote it: listed once, then not, no `seenListed`.
  const old = { domain: 'acme-labs.com', listed: false, method: 'file', checkedAt: new Date(T0).toISOString(), listedAt: new Date(T0 - 5 * 86_400_000).toISOString(), since: new Date(T0 - 9 * 86_400_000).toISOString(), claimIssuedAt: 1, claimSignature: 'ab'.repeat(64) };
  db.prepare('UPDATE attesters SET domain_check = ? WHERE public_key = ?').run(JSON.stringify(old), kp.publicKey);
  const clock = { t: T0 + 24 * H };
  web({}, clock);
  await daily();
  clock.t = T0 + 48 * H;
  await daily();
  assert.equal((await get(kp.publicKey)).domainWithdrawn, null);
  // And it is forgotten after 30 days without a listing, as before.
  clock.t = T0 + 31 * 86_400_000;
  await daily();
  assert.equal(JSON.parse(db.prepare('SELECT domain_check FROM attesters WHERE public_key = ?').get(kp.publicKey).domain_check).forgotten, true);
  setLabDomainOptions({});
});

test('a domain that never listed the key is not "withdrawn", and the key may name another', async () => {
  const kp = await register('Beta Labs');
  const clock = { t: T0 };
  web({}, clock);
  const r = await claim(kp, 'beta-labs.com');
  assert.equal(r.status, 200);
  assert.equal((await r.json()).listed, false);
  clock.t = T0 + 24 * H;
  await daily();
  clock.t = T0 + 48 * H;
  await daily();
  const a = await get(kp.publicKey);
  assert.equal(a.domainCheck, null);
  assert.equal(a.domainWithdrawn, null);
  assert.equal((await claim(kp, 'beta-labs.org')).status, 200);
  setLabDomainOptions({});
});
