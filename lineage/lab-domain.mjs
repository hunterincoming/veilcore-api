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
//   or a DNS TXT record at _veilcore-lab.<domain>:
//     veilcore-lab=v1 key=<64 hex>
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

/** GET https://<domain>/.well-known/veilcore-lab.json: no redirects, 16 KiB, 5 s, public addresses only. */
export const fetchLabFile = (domain, { lookup = publicLookup, port = 443, ca, deadlineMs = TIMEOUT_MS } = {}) =>
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
      { host: domain, port, path: LAB_FILE_PATH, method: 'GET', lookup, ca, timeout: TIMEOUT_MS, headers: { accept: 'application/json', 'user-agent': 'veilcore-registry' } },
      (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          return finish({ ok: false, why: `HTTP ${res.statusCode}` });
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

/**
 * Look for `publicKey` at `domain`: the file first, then the TXT record. What was seen, not
 * a judgement: { domain, listed, method, checkedAt, fileSha256?, listedName?, why? }.
 */
export const checkLabDomain = async (domain, publicKey, { fetchFile = fetchLabFile, resolveTxt = (n) => dnsp.resolveTxt(n), now = Date.now } = {}) => {
  const d = cleanDomain(domain);
  if (!d) return { error: 'a plain domain name, like acme-labs.com' };
  if (!HEX64.test(publicKey)) return { error: 'a public key' };
  const checkedAt = new Date(now()).toISOString();
  const why = [];
  const file = await fetchFile(d);
  if (file.ok) {
    const read = readLabFile(file.body.toString('utf8'), publicKey);
    const fileSha256 = createHash('sha256').update(file.body).digest('hex');
    if (read.ok && read.listed) return { domain: d, listed: true, method: 'file', checkedAt, fileSha256, ...(read.name ? { listedName: read.name } : {}) };
    why.push(read.ok ? 'the file does not list this key' : read.why);
  } else why.push(`file: ${file.why}`);
  try {
    const txt = await Promise.race([
      resolveTxt(LAB_TXT_PREFIX + d),
      new Promise((_, no) => setTimeout(() => no(new Error('timed out')), TIMEOUT_MS).unref()),
    ]);
    if (readLabTxt(txt, publicKey)) return { domain: d, listed: true, method: 'dns', checkedAt };
    why.push('the TXT record does not list this key');
  } catch {
    why.push('no TXT record');
  }
  return { domain: d, listed: false, checkedAt, why: why.join('; ') };
};
