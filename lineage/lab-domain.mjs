// A lab's key, published on the lab's own website or DNS (site repo docs/lab-domain-keys.md).
//
// The operator's name check (attesters.mjs, docs/lab-name-checks.md) makes VeilCore the one
// who says whose key it is. This is the other way round: the lab itself lists its key where
// only the lab can write, and anyone can look, today or in ten years, without VeilCore.
// The same pattern as Nostr's NIP-05 (/.well-known/nostr.json), Bluesky handles
// (/.well-known/atproto-did or a _atproto TXT record) and security.txt.
//
//   https://<domain>/.well-known/veilcore-lab.json
//     { "format": "veilcore-lab/v1", "name": "Acme Labs",
//       "keys": [ { "publicKey": "<64 hex>" } ] }
//   or a W3C did:web document at https://<domain>/.well-known/did.json (id "did:web:<domain>"),
//     the key as a verificationMethod listed under assertionMethod: Multikey or
//     Ed25519VerificationKey2020 (publicKeyMultibase "z6Mk…"), or JsonWebKey2020 (OKP Ed25519 JWK)
//   or a DNS TXT record at _veilcore-lab.<domain>:
//     veilcore-lab=v1 key=<64 hex>
//
// A key the website stopped listing, when both the website and DNS answered (not a timeout
// or an outage), is recorded as withdrawn (attesters.mjs setDomainCheck) and shown as such.
//
// Both sides name each other: the key signs the domain (domainClaimPayload) and the domain
// lists the key. The registry only fetches and records what it saw (domain, how, when, and
// the file's SHA-256); it adds no judgement. A lab withdraws a key by removing it: the next look
// (daily, or anyone pressing "look again") records that it is no longer listed.
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import { promises as dnsp, lookup as dnsLookup } from 'node:dns';
import { request } from 'node:https';
import { isIP } from 'node:net';

export const LAB_FILE_PATH = '/.well-known/veilcore-lab.json';
export const DID_FILE_PATH = '/.well-known/did.json';
export const LAB_TXT_PREFIX = '_veilcore-lab.';
export const LAB_FILE_MAX = 16 * 1024;
export const LAB_KEYS_MAX = 64;
const TIMEOUT_MS = 5000;
const HEX64 = /^[0-9a-f]{64}$/;
const DOMAIN = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

/**
 * What the key signs to name its website (attack on lab-domain-keys, 5 Nov 2026): without it
 * anyone could list a lab's public key on a domain of their own and have it shown next to
 * the lab's signatures, or point the lab's record at a domain that lists nothing. Both sides
 * must name each other, as NIP-05 and Bluesky handles require.
 */
export const domainClaimPayload = ({ publicKey, domain, issuedAt }) =>
  `veilcore:lab-domain:v1\n${publicKey}\n${domain}\n${issuedAt}`;

/** Whether `signature` (128 hex) is the key's Ed25519 signature over the claim. */
export const verifyDomainClaim = async ({ publicKey, domain, issuedAt, signature }) => {
  if (!HEX64.test(publicKey ?? '') || !/^[0-9a-f]{128}$/i.test(signature ?? '') || !Number.isSafeInteger(issuedAt)) return false;
  try {
    const key = await globalThis.crypto.subtle.importKey('raw', Buffer.from(publicKey, 'hex'), { name: 'Ed25519' }, false, ['verify']);
    return await globalThis.crypto.subtle.verify('Ed25519', key, Buffer.from(signature, 'hex'), new TextEncoder().encode(domainClaimPayload({ publicKey, domain, issuedAt })));
  } catch {
    return false;
  }
};

/** A plain public domain name, lower case, or undefined. No ports, paths, IPs or "localhost". */
export const cleanDomain = (v) => {
  if (typeof v !== 'string') return undefined;
  const d = v.trim().toLowerCase().replace(/\.$/, '');
  return DOMAIN.test(d) && !isIP(d) ? d : undefined;
};

/** Whether `publicKey` is listed in a veilcore-lab/v1 file, and the name the file gives. */
export const readLabFile = (text, publicKey) => {
  let doc;
  try {
    doc = JSON.parse(text);
  } catch {
    return { ok: false, why: 'not JSON' };
  }
  if (typeof doc !== 'object' || doc === null || doc.format !== 'veilcore-lab/v1') return { ok: false, why: 'not a veilcore-lab/v1 file' };
  if (!Array.isArray(doc.keys) || doc.keys.length > LAB_KEYS_MAX) return { ok: false, why: `keys must be a list of at most ${LAB_KEYS_MAX}` };
  const keys = doc.keys.map((k) => (typeof k?.publicKey === 'string' ? k.publicKey.toLowerCase() : '')).filter((k) => HEX64.test(k));
  const name = typeof doc.name === 'string' && doc.name.length <= 200 && !/[\p{Cc}\p{Cf}]/u.test(doc.name) ? doc.name.trim() : undefined;
  return { ok: true, listed: keys.includes(publicKey), name };
};

/** Whether a TXT record set at _veilcore-lab.<domain> lists `publicKey`. */
export const readLabTxt = (records, publicKey) =>
  records.some((chunks) => {
    const t = (Array.isArray(chunks) ? chunks.join('') : String(chunks)).trim().toLowerCase();
    const m = /^veilcore-lab=v1\s+key=([0-9a-f]{64})$/.exec(t);
    return !!m && m[1] === publicKey;
  });

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
/** base58btc (multibase "z"), for Ed25519 public keys in DID documents. */
export const base58btc = (bytes) => {
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let out = '';
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  for (const b of bytes) { if (b !== 0) break; out = '1' + out; }
  return out;
};
const unbase58 = (s) => {
  let n = 0n;
  for (const ch of s) {
    const i = B58.indexOf(ch);
    if (i < 0) return null;
    n = n * 58n + BigInt(i);
  }
  const out = [];
  while (n > 0n) { out.unshift(Number(n % 256n)); n /= 256n; }
  for (const ch of s) { if (ch !== '1') break; out.unshift(0); }
  return Uint8Array.from(out);
};
/** The Ed25519 key as a multibase value (did:key, Multikey): "z" + base58btc(0xed 0x01 + key). */
export const ed25519Multibase = (publicKeyHex) => 'z' + base58btc(Uint8Array.from([0xed, 0x01, ...Buffer.from(publicKeyHex, 'hex')]));

/** The 64-hex Ed25519 key in a "z6Mk…" multibase value, or undefined. */
export const ed25519FromMultibase = (v) => {
  if (typeof v !== 'string' || !v.startsWith('z') || v.length > 60) return undefined;
  const b = unbase58(v.slice(1));
  return b && b.length === 34 && b[0] === 0xed && b[1] === 0x01 ? Buffer.from(b.slice(2)).toString('hex') : undefined;
};

/** A verification method's Ed25519 key as 64 hex, or undefined for anything else. */
const vmKeyHex = (vm) => {
  if (typeof vm !== 'object' || vm === null) return undefined;
  if (vm.type === 'Multikey' || vm.type === 'Ed25519VerificationKey2020') return ed25519FromMultibase(vm.publicKeyMultibase);
  if (vm.type === 'JsonWebKey2020' || vm.type === 'JsonWebKey') {
    const j = vm.publicKeyJwk;
    if (j && j.kty === 'OKP' && j.crv === 'Ed25519' && typeof j.x === 'string' && /^[A-Za-z0-9_-]{43}$/.test(j.x) && j.d === undefined) {
      return Buffer.from(j.x, 'base64url').toString('hex');
    }
  }
  return undefined;
};

/**
 * Whether a did:web document for `domain` lists `publicKey` as a key the DID uses to sign
 * statements (assertionMethod), the relationship a lab's signature is. The document's id must
 * be did:web:<domain> (did:web: "the ID of the resolved DID document matches"), and every
 * method id and controller must be absolute and the DID's own, so a document can't borrow
 * another DID's key. Returns the method's id too, for the record.
 */
export const readDidDoc = (text, publicKey, domain) => {
  let doc;
  try {
    doc = JSON.parse(text);
  } catch {
    return { ok: false, why: 'did.json: not JSON' };
  }
  const did = `did:web:${domain}`;
  if (typeof doc !== 'object' || doc === null || doc.id !== did) return { ok: false, why: `did.json: id is not ${did}` };
  const vms = Array.isArray(doc.verificationMethod) ? doc.verificationMethod : [];
  const assertion = Array.isArray(doc.assertionMethod) ? doc.assertionMethod : [];
  if (vms.length + assertion.length > LAB_KEYS_MAX * 2) return { ok: false, why: 'did.json: too many methods' };
  const own = (vm) => typeof vm?.id === 'string' && vm.id.startsWith(`${did}#`) && vm.controller === did;
  const byId = new Map(vms.filter(own).map((vm) => [vm.id, vm]));
  for (const a of assertion) {
    const vm = typeof a === 'string' ? byId.get(a) : own(a) ? a : undefined;
    if (vm && vmKeyHex(vm) === publicKey) return { ok: true, listed: true, did, keyId: vm.id };
  }
  return { ok: true, listed: false, did };
};

/** Addresses the registry must never connect to: loopback, private, link-local, and the like. */
export const isPublicAddress = (ip) => {
  const v = isIP(ip);
  if (v === 4) {
    const [a, b, c] = ip.split('.').map(Number);
    return !(
      a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 192 && b === 0 && (c === 0 || c === 2)) ||
      (a === 198 && (b === 18 || b === 19)) || (a === 198 && b === 51 && c === 100) ||
      (a === 203 && b === 0 && c === 113) || (a === 192 && b === 88 && c === 99) || a >= 224
    );
  }
  if (v === 6) {
    const s = ip.toLowerCase();
    const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(s);
    if (m) return isPublicAddress(m[1]);
    // Global unicast only (2000::/3), minus 6to4 (2002::/16), Teredo (2001:0::/32) and the
    // documentation range (2001:db8::/32). Everything else (::, ::1, ::a.b.c.d, fc00::/7,
    // fe80::/10, fec0::/10, ff00::/8, 64:ff9b::/96) is refused.
    const first = s.startsWith('::') ? 0 : Number.parseInt(s.split(':')[0], 16);
    const second = s.startsWith('::') ? 0 : Number.parseInt(s.split(':')[1] || '0', 16);
    if (!(first >= 0x2000 && first <= 0x3fff)) return false;
    if (first === 0x2002) return false;
    if (first === 0x2001 && (second === 0 || second === 0xdb8)) return false;
    return true;
  }
  return false;
};

/** A DNS lookup that refuses non-public addresses, used for the connection itself (no rebinding gap). */
const publicLookup = (hostname, options, cb) =>
  dnsLookup(hostname, { ...options, all: true }, (err, addrs) => {
    if (err) return cb(err);
    const ok = addrs.filter((a) => isPublicAddress(a.address));
    if (ok.length === 0) return cb(Object.assign(new Error('not a public address'), { code: 'ENOTPUBLIC' }));
    if (options?.all) return cb(null, ok);
    cb(null, ok[0].address, ok[0].family);
  });

/** GET https://<domain><path> (the lab file by default): no redirects, 16 KiB, 5 s, public addresses only. */
export const fetchLabFile = (domain, { lookup = publicLookup, port = 443, ca, deadlineMs = TIMEOUT_MS, path = LAB_FILE_PATH } = {}) =>
  new Promise((resolve) => {
    // One deadline for the whole look, body included: `timeout` alone only fires on silence,
    // so a server sending a byte every few seconds could hold a look for hours (attack, 5 Nov).
    let done = false;
    const finish = (v) => {
      if (done) return;
      done = true;
      clearTimeout(deadline);
      resolve(v);
    };
    const deadline = setTimeout(() => {
      req.destroy();
      finish({ ok: false, why: 'timed out' });
    }, deadlineMs);
    const req = request(
      { host: domain, port, path, method: 'GET', lookup, ca, timeout: TIMEOUT_MS, headers: { accept: 'application/json', 'user-agent': 'veilcore-registry' } },
      (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          return finish({ ok: false, why: `HTTP ${res.statusCode}`, status: res.statusCode });
        }
        const chunks = [];
        let n = 0;
        res.on('data', (c) => {
          n += c.length;
          if (n > LAB_FILE_MAX) {
            req.destroy();
            finish({ ok: false, why: 'file too large' });
          } else chunks.push(c);
        });
        res.on('end', () => finish({ ok: true, body: Buffer.concat(chunks) }));
        res.on('error', () => finish({ ok: false, why: 'read failed' }));
      },
    );
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', (e) => finish({ ok: false, why: e.code === 'ENOTPUBLIC' ? 'not a public address' : e.message === 'timeout' ? 'timed out' : 'could not connect' }));
    req.end();
  });

/** A 200 body that isn't a DID document at all (HTML from a single-page host, say). */
const notADidDoc = (body) => {
  try {
    const doc = JSON.parse(body.toString('utf8'));
    return typeof doc !== 'object' || doc === null || Array.isArray(doc) || typeof doc.id !== 'string';
  } catch {
    return true;
  }
};

/**
 * An answer that says "not here" (as against a timeout or an outage): a 404 or 410. A host
 * that answers 403 for missing files (S3, CloudFront) never gives one, so a withdrawal can't be
 * recorded there; the listing just ages out after 7 days (docs/lab-key-on-website.md).
 */
const goneStatus = (r) => r.status === 404 || r.status === 410;
/** DNS answers that say there is no such record. */
const NO_RECORD = new Set(['ENODATA', 'ENOTFOUND']);

/**
 * Look for `publicKey` at `domain`: the lab file, then the did:web document, then the TXT
 * record. What was seen, not a judgement:
 *   { domain, listed, method: 'file'|'did'|'dns', checkedAt, fileSha256?, listedName?, did?, didKeyId? }
 * or, not listed, { domain, listed: false, answered, checkedAt, why }. `answered` is true only
 * when every place gave a real answer (a file without the key or a 404, and a DNS answer), so
 * a website that is down or slow is never read as the lab taking its key away.
 */
export const checkLabDomain = async (
  domain,
  publicKey,
  { fetchFile = fetchLabFile, fetchDid = (d) => fetchFile(d, { path: DID_FILE_PATH }), resolveTxt = (n) => dnsp.resolveTxt(n), now = Date.now } = {},
) => {
  const d = cleanDomain(domain);
  if (!d) return { error: 'a plain domain name, like acme-labs.com' };
  if (!HEX64.test(publicKey)) return { error: 'a public key' };
  const checkedAt = new Date(now()).toISOString();
  const why = [];
  let answered = true;
  const sha = (body) => createHash('sha256').update(body).digest('hex');

  const file = await fetchFile(d);
  if (file.ok) {
    const read = readLabFile(file.body.toString('utf8'), publicKey);
    if (read.ok && read.listed) return { domain: d, listed: true, method: 'file', checkedAt, fileSha256: sha(file.body), ...(read.name ? { listedName: read.name } : {}) };
    if (!read.ok) answered = false;
    why.push(read.ok ? 'the file does not list this key' : read.why);
  } else {
    if (!goneStatus(file)) answered = false;
    why.push(`file: ${file.why}`);
  }

  const didDoc = await fetchDid(d);
  if (didDoc.ok) {
    const read = readDidDoc(didDoc.body.toString('utf8'), publicKey, d);
    if (read.ok && read.listed) return { domain: d, listed: true, method: 'did', checkedAt, fileSha256: sha(didDoc.body), did: read.did, didKeyId: read.keyId };
    // did.json is optional: a single-page host answers 200 with its HTML for any path, so a
    // 200 that isn't a JSON object with an id is "no DID document here", an answer. A DID
    // document that is one but for another DID, or broken, is not (the lab file stays strict).
    if (!read.ok && !notADidDoc(didDoc.body)) answered = false;
    why.push(read.ok ? 'did.json does not list this key' : read.why);
  } else {
    if (!goneStatus(didDoc)) answered = false;
    why.push(`did.json: ${didDoc.why}`);
  }

  try {
    const txt = await Promise.race([
      resolveTxt(LAB_TXT_PREFIX + d),
      new Promise((_, no) => setTimeout(() => no(new Error('timed out')), TIMEOUT_MS).unref()),
    ]);
    if (readLabTxt(txt, publicKey)) return { domain: d, listed: true, method: 'dns', checkedAt };
    why.push('the TXT record does not list this key');
  } catch (e) {
    if (!NO_RECORD.has(e?.code)) answered = false;
    why.push(NO_RECORD.has(e?.code) ? 'no TXT record' : 'DNS did not answer');
  }
  return { domain: d, listed: false, answered, checkedAt, why: why.join('; ') };
};

// ---- What the registry keeps about a key's websites (attesters.mjs setDomainCheck) --------
//
// One record per key:
//   { domain, listed, method, checkedAt, listedAt, since, seenListed, missingSince,
//     lastTriedAt, lastWhy, lookedAt, fileSha256, listedName, did, didKeyId,
//     claimIssuedAt, claimSignature,          the key's claim naming `domain`
//     history: [ { domain, method, listedAt, seenListed, missingSince, checkedAt,
//                  claimIssuedAt, claimSignature } ],   websites that listed the key before
//     withdrawn: { domain, method, at, claimIssuedAt, claimSignature } }
//
// Rules (review of 18 Nov 2026):
//   - a look that got no real answer (`answered` false) changes nothing but lastTriedAt, so one
//     timeout never hides a listing; the 7-day freshness rule does that;
//   - a withdrawal needs two real "not here" answers at least 20 hours apart, so a hosting
//     outage that serves 404 for everything for an hour isn't one;
//   - only a website seen listing the key by this version (`seenListed`) can withdraw it, so a
//     key a lab took down before this version (when the advice was "take it out to retire it")
//     never turns "withdrawn" on deploy day;
//   - a website the key moved away from stays watched (`history`): if a thief moves a leaked key
//     to a lookalike first, the lab taking the key off its real website still withdraws it;
//   - while withdrawn, the key can't name any other website, and the check is made again just
//     before the write, so a slow look started earlier can't overwrite it.

export const WITHDRAW_CONFIRM_MS = 20 * 3_600_000;
export const FORGET_MS = 30 * 86_400_000;
export const HISTORY_MAX = 4;

const withdrawnError = (w) => ({
  error: `${w.domain} stopped listing this key, so it can't name another website until it lists it again; make a new key`,
  code: 'withdrawn',
  domain: w.domain,
});

/** Whether a signed claim for `domain` issued at `issuedAt` may be recorded over `prev`. */
export const claimAllowed = (prev, domain, issuedAt) => {
  if (prev?.claimIssuedAt && issuedAt <= prev.claimIssuedAt) return { error: 'an older claim than the one on record' };
  if (prev?.withdrawn && domain !== prev.withdrawn.domain) return withdrawnError(prev.withdrawn);
  return { ok: true };
};

/** Every website the registry should look at for this record: the current one, the old ones, a withdrawn one. */
export const domainsToLook = (rec) =>
  [...new Set([rec?.domain, ...(rec?.history ?? []).map((h) => h.domain), rec?.withdrawn?.domain].filter((d) => typeof d === 'string'))];

/**
 * The record after a look (checkLabDomain's result) at `result.domain`. With a claim (the lab
 * pressed "Look now"): the claim is checked again here, and the domain becomes the current one.
 * Without (the daily look): only a domain the record already watches is written.
 * Returns { record } or { error, code? } or { skipped: true }.
 */
export const applyLook = (prev0, result, { claimIssuedAt, claimSignature } = {}) => {
  const prev = prev0?.forgotten
    ? { claimIssuedAt: prev0.claimIssuedAt, history: prev0.history ?? [], ...(prev0.withdrawn ? { withdrawn: prev0.withdrawn } : {}) }
    : prev0 ?? null;
  const D = result.domain;
  const at = result.checkedAt;
  const t = Date.parse(at);
  const rec = { ...(prev ?? {}), history: (prev?.history ?? []).map((h) => ({ ...h })) };

  if (claimIssuedAt !== undefined) {
    const ok = claimAllowed(prev, D, claimIssuedAt);
    if (ok.error) return ok;
    if (rec.domain !== D) {
      // Moving: keep watching the website it leaves, if this version saw the key listed there.
      if (rec.domain && rec.seenListed) {
        rec.history.unshift({
          domain: rec.domain, method: rec.method, listedAt: rec.listedAt, seenListed: true, missingSince: rec.missingSince,
          checkedAt: rec.checkedAt, claimIssuedAt: rec.claimIssuedAt, claimSignature: rec.claimSignature,
        });
      }
      const back = rec.history.find((h) => h.domain === D);
      for (const k of ['domain', 'listed', 'method', 'checkedAt', 'listedAt', 'since', 'seenListed', 'missingSince', 'lastTriedAt', 'lastWhy', 'fileSha256', 'listedName', 'did', 'didKeyId']) delete rec[k];
      Object.assign(rec, { domain: D, listed: false, since: at }, back ? { method: back.method, listedAt: back.listedAt, seenListed: back.seenListed, missingSince: back.missingSince } : {});
    }
    rec.history = rec.history.filter((h) => h.domain !== D).slice(0, HISTORY_MAX);
    rec.claimIssuedAt = claimIssuedAt;
    rec.claimSignature = claimSignature;
  }

  const entry = rec.domain === D ? rec : rec.history.find((h) => h.domain === D);
  if (!entry) {
    // A withdrawn website no longer watched otherwise: it listing the key again clears it.
    if (rec.withdrawn?.domain === D && result.listed) {
      delete rec.withdrawn;
      return { record: { ...rec, lookedAt: at } };
    }
    return { skipped: true };
  }
  rec.lookedAt = at;
  entry.lastTriedAt = at;

  if (result.listed) {
    Object.assign(entry, { listed: true, listedAt: at, checkedAt: at, seenListed: true, method: result.method });
    delete entry.missingSince;
    delete entry.lastWhy;
    if (entry === rec) {
      for (const k of ['fileSha256', 'listedName', 'did', 'didKeyId']) {
        if (result[k] !== undefined) rec[k] = result[k];
        else delete rec[k];
      }
    }
    if (rec.withdrawn?.domain === D) delete rec.withdrawn;
  } else if (result.answered !== true) {
    // No real answer: nothing changes. The listing stands until it is 7 days old.
    entry.lastWhy = result.why;
  } else {
    entry.listed = false;
    entry.checkedAt = at;
    entry.lastWhy = result.why;
    if (entry.seenListed) {
      if (!entry.missingSince) entry.missingSince = at;
      else if (t - Date.parse(entry.missingSince) >= WITHDRAW_CONFIRM_MS && !rec.withdrawn) {
        rec.withdrawn = { domain: D, method: entry.method, at, claimIssuedAt: entry.claimIssuedAt, claimSignature: entry.claimSignature };
      }
    }
  }

  // Forget a website not listing the key for 30 days (stopped answering, or never listed it),
  // keeping the newest claim's time so an old claim can't be replayed. A withdrawal is kept.
  const quiet = (e) => !e.listed && t - Math.max(Date.parse(e.listedAt ?? e.since ?? e.checkedAt ?? at), e.missingSince ? Date.parse(e.missingSince) : 0) > FORGET_MS;
  rec.history = rec.history.filter((h) => !quiet(h));
  if (rec.domain && rec.withdrawn?.domain !== rec.domain && quiet(rec)) {
    const kept = { forgotten: true, listed: false, claimIssuedAt: rec.claimIssuedAt, history: rec.history, lookedAt: at, ...(rec.withdrawn ? { withdrawn: rec.withdrawn } : {}) };
    return { record: kept, forgotten: true };
  }
  return { record: rec };
};
