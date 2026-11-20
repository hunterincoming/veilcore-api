// RFC 3161: a timestamp on each batch root from a Time Stamping Authority (TSA).
//
// Midnight and Bitcoin date a batch root, and courts weigh those case by case. A timestamp
// from a TSA is the dating lawyers and auditors already know, and where the TSA is a
// qualified trust service provider on an EU trusted list (eIDAS Articles 41 and 42), or
// accredited in Japan (the MIC scheme for 認定タイムスタンプ), the date carries a legal
// presumption. Outside reviews on 5 November 2026 put this first among what would let a
// court or an office lean on a VeilCore date without depending on Midnight.
//
// What is stamped: SHA-256 of the 32 raw bytes of the batch root (root.bin), the same file
// OpenTimestamps stamps, as `openssl ts -query -data root.bin -sha256` would ask. Anyone
// checks the token with `openssl ts -verify` or the SDK's verifyTimestampToken, with no
// VeilCore service involved (SPEC 9.2, anchor kind `rfc3161`).
//
// A token is stored only after the SDK has verified it here against the root (imprint,
// signature, time-stamping key usage), the nonce matches, its time is now, and (when a pin
// is set) it was signed by the pinned TSA certificate. `qualified` is only what the operator
// states in VEILCORE_TSA_QUALIFIED_SCHEME; a reader checks the trusted list themselves.
//
// SPDX-License-Identifier: Apache-2.0

import { createHash, randomBytes } from 'node:crypto';
import { timestampTokenBytes, verifyTimestampToken } from 'veilcore-records';

const MAX_REPLY = 64 * 1024;
const TIMEOUT_MS = 15_000;
const MAX_SKEW_MS = 10 * 60_000;

/** DER: tag, length, value. */
const der = (tag, ...parts) => {
  const body = Buffer.concat(parts);
  const n = body.length;
  const len = n < 0x80 ? Buffer.from([n]) : n < 0x100 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 0xff]);
  return Buffer.concat([Buffer.from([tag]), len, body]);
};
const derInt = (bytes) => der(0x02, bytes[0] & 0x80 ? Buffer.concat([Buffer.from([0]), bytes]) : bytes);
const SHA256_OID = Buffer.from('0609608648016503040201', 'hex'); // 2.16.840.1.101.3.4.2.1

/**
 * A TimeStampReq (RFC 3161 2.4.1): version 1, messageImprint SHA-256 of `stamped`, a
 * random nonce, certReq TRUE (so the token carries the TSA's certificate and checks alone).
 */
export const timeStampRequest = (stamped, nonce = randomBytes(8)) => {
  const digest = createHash('sha256').update(stamped).digest();
  const imprint = der(0x30, der(0x30, SHA256_OID, Buffer.from([0x05, 0x00])), der(0x04, digest));
  // A positive INTEGER in minimal form: the top bit clear and the first byte never zero.
  const n = Buffer.from(nonce);
  n[0] = (n[0] & 0x7f) | 0x01;
  return { der: der(0x30, derInt(Buffer.from([1])), imprint, derInt(n), Buffer.from([0x01, 0x01, 0xff])), nonce: n };
};

/**
 * The TSA settings from the environment, or null when no TSA is set (attack on this branch,
 * 5 Nov 2026: the token must be tied to the TSA, or anyone on the path could answer).
 *   VEILCORE_TSA_URL              one TSA, or several separated by commas or spaces (reliability
 *                                 audit, 19 Nov 2026: one service, run by one person, was a single
 *                                 point of failure). A token is asked from each, separately, so
 *                                 one that is slow or down never holds up the others. https; http
 *                                 only with a signer pin for that service
 *   VEILCORE_TSA_SIGNER_SHA256    the SHA-256 of a TSA's signing certificate(s), comma separated:
 *                                 a token signed by any other certificate is refused. A plain
 *                                 fingerprint pins every service with no pin of its own; one
 *                                 written `host=fingerprint` pins only the service at that host
 *                                 (timestamp.digicert.com=ab12…). An http service needs one
 *   VEILCORE_TSA_QUALIFIED_SCHEME the operator's statement that the FIRST service is qualified, and
 *                                 under what: "eIDAS" (an EU trusted list) or "JP-MIC" (Japan's
 *                                 accredited time-stamping). Unset: not stated qualified
 *   VEILCORE_TSA_TRUSTED_LIST     where a reader checks that (a URL)
 *   VEILCORE_TSA_AUTHORIZATION    the Authorization header a paid TSA needs, sent to the FIRST
 *                                 service only; https only
 * Returns { services: [{ url, pins, qualified, authorization }], ...the first service's fields }
 * (the first service's fields at the top, as a single-TSA setting always read), or { error }.
 */
export const tsaConfig = (env = process.env) => {
  const urls = String(env.VEILCORE_TSA_URL ?? '').split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
  if (urls.length === 0) return null;
  if (urls.length > 5) return { error: 'VEILCORE_TSA_URL lists more than five TSAs' };
  const scoped = new Map(); // host -> pins
  const plain = [];
  for (const raw of String(env.VEILCORE_TSA_SIGNER_SHA256 ?? '').split(',').map((x) => x.trim()).filter(Boolean)) {
    const eq = raw.indexOf('=');
    const host = eq > 0 ? raw.slice(0, eq).trim().toLowerCase() : null;
    const fp = (eq > 0 ? raw.slice(eq + 1) : raw).trim().toLowerCase().replace(/:/g, '');
    if (!/^[0-9a-f]{64}$/.test(fp)) return { error: 'VEILCORE_TSA_SIGNER_SHA256 must be SHA-256 fingerprints' };
    if (host !== null && !/^[a-z0-9.-]+(:\d+)?$/.test(host)) return { error: 'VEILCORE_TSA_SIGNER_SHA256: write a scoped pin as host=fingerprint' };
    if (host) scoped.set(host, [...(scoped.get(host) ?? []), fp]);
    else plain.push(fp);
  }
  const authorization = (env.VEILCORE_TSA_AUTHORIZATION ?? '').trim() || undefined;
  const scheme = (env.VEILCORE_TSA_QUALIFIED_SCHEME ?? '').trim();
  if (scheme && scheme !== 'eIDAS' && scheme !== 'JP-MIC') return { error: 'VEILCORE_TSA_QUALIFIED_SCHEME is eIDAS or JP-MIC' };
  const trustedList = (env.VEILCORE_TSA_TRUSTED_LIST ?? '').trim();
  const services = [];
  for (const [i, url] of urls.entries()) {
    let u;
    try {
      u = new URL(url);
    } catch {
      return { error: `VEILCORE_TSA_URL is not a URL (${i + 1} in the list)` };
    }
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return { error: 'VEILCORE_TSA_URL must be https (http only with a signer pin)' };
    if (u.username || u.password || u.search) return { error: 'VEILCORE_TSA_URL must carry no password or query (it is published); use VEILCORE_TSA_AUTHORIZATION' };
    if (services.some((s) => s.url === u.href)) return { error: `VEILCORE_TSA_URL lists ${u.host} twice` };
    const own = scoped.get(u.host.toLowerCase()) ?? scoped.get(u.hostname.toLowerCase());
    const pins = own ?? plain;
    // Several TSAs: an http one needs a pin of its own (security review, 19 Nov 2026). With a
    // pin shared by all, someone on the path to it could pass the request to another listed TSA
    // and its genuine token would be kept as this one's: two "independent" timestamps, one source.
    if (u.protocol === 'http:' && urls.length > 1 && !own)
      return { error: `with several TSAs, the http one (${u.host}) needs its own pin: VEILCORE_TSA_SIGNER_SHA256=${u.host}=<fingerprint>` };
    const auth = i === 0 ? authorization : undefined;
    if (u.protocol === 'http:' && pins.length === 0) return { error: `an http TSA needs VEILCORE_TSA_SIGNER_SHA256 (${u.host})` };
    if (u.protocol === 'http:' && auth) return { error: 'VEILCORE_TSA_AUTHORIZATION needs an https TSA' };
    services.push({
      url: u.href,
      pins,
      // Only what the operator states (SDK SPEC 9.2 `qualified: { scheme, trustedList }`), for
      // the first service; a reader checks the list themselves.
      qualified: i === 0 && scheme ? { scheme, ...(trustedList ? { trustedList } : {}) } : null,
      authorization: auth,
    });
  }
  for (const host of scoped.keys())
    if (!services.some((s) => new URL(s.url).host.toLowerCase() === host || new URL(s.url).hostname.toLowerCase() === host))
      return { error: `VEILCORE_TSA_SIGNER_SHA256 pins ${host}, which VEILCORE_TSA_URL doesn't list` };
  return { ...services[0], services };
};

/** The certificates a CMS SignedData token carries (its [0] IMPLICIT certificates), DER. */
const tlv = (b, at) => {
  const tag = b[at];
  let len = b[at + 1];
  let hdr = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 3) throw new Error('bad length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[at + 2 + i];
    hdr = 2 + n;
  }
  if (at + hdr + len > b.length) throw new Error('truncated');
  return { tag, start: at + hdr, end: at + hdr + len, whole: b.subarray(at, at + hdr + len) };
};
const children = (b, node) => {
  const out = [];
  for (let at = node.start; at < node.end; ) {
    const k = tlv(b, at);
    out.push(k);
    at = k.end;
  }
  return out;
};
const signedDataOf = (b) => {
  const ci = tlv(b, 0);
  const [, explicit] = children(b, ci);
  const [sd] = children(b, explicit);
  return children(b, sd);
};

export const tokenCertificates = (token) => {
  try {
    const b = Buffer.from(token);
    const certs = signedDataOf(b).find((k) => k.tag === 0xa0);
    return certs ? children(b, certs).filter((k) => k.tag === 0x30).map((k) => Buffer.from(k.whole)) : [];
  } catch {
    return [];
  }
};

/** An INTEGER's content bytes exactly as written, leading zeros kept, as the SDK compares them. */
const intValue = (b, node) => Buffer.from(b.subarray(node.start, node.end));

/** A certificate's issuer (whole DER), serial (value) and subject key identifier, if any. */
const certIds = (der) => {
  const b = Buffer.from(der);
  const [tbs] = children(b, tlv(b, 0));
  const f = children(b, tbs);
  let k = f[0].tag === 0xa0 ? 1 : 0;
  const serial = intValue(b, f[k++]);
  k++; // signature algorithm
  const issuer = Buffer.from(f[k++].whole);
  let ski;
  const ext = f.find((x) => x.tag === 0xa3);
  if (ext) {
    const [list] = children(b, ext);
    for (const e of children(b, list)) {
      const parts = children(b, e);
      if (parts[0].tag === 0x06 && b.subarray(parts[0].start, parts[0].end).equals(Buffer.from('551d0e', 'hex'))) {
        const octets = parts[parts.length - 1];
        const inner = tlv(b, octets.start);
        ski = Buffer.from(b.subarray(inner.start, inner.end));
      }
    }
  }
  return { serial, issuer, ski };
};

/**
 * The certificate the SDK verified the signature with: chosen exactly as verifyTimestampToken
 * chooses it, the first certificate in the token matching the SignerInfo's identifier (issuer
 * and serial, or subject key identifier). Second check (5 Nov 2026): matching on subject text
 * let a token signed by another key pass the pin by carrying the pinned certificate beside it.
 */
export const signerCertificate = (token) => {
  try {
    const b = Buffer.from(token);
    const sd = signedDataOf(b);
    const signerInfos = sd[sd.length - 1];
    if (signerInfos.tag !== 0x31) return undefined;
    const infos = children(b, signerInfos);
    if (infos.length !== 1) return undefined;
    const si = children(b, infos[0]);
    const sid = si[1];
    let match;
    if (sid.tag === 0x30) {
      const [issuer, serial] = children(b, sid);
      const want = { issuer: Buffer.from(issuer.whole), serial: intValue(b, serial) };
      match = (c) => c.issuer.equals(want.issuer) && c.serial.equals(want.serial);
    } else if (sid.tag === 0x80) {
      const ski = Buffer.from(b.subarray(sid.start, sid.end));
      match = (c) => !!c.ski && c.ski.equals(ski);
    } else return undefined;
    return tokenCertificates(b).find((der) => {
      try {
        return match(certIds(der));
      } catch {
        return false;
      }
    });
  } catch {
    return undefined;
  }
};

/**
 * Ask the TSA for a token on the batch root. Returns { token (base64 DER TimeStampToken),
 * genTime, signerSubject, serialNumber } or { error } with a short reason (no upstream text).
 * TSAs differ on whether http or https is offered: RFC 3161 tokens are signed, so the
 * transport adds nothing to what is checked here.
 */
export const requestTimestamp = async (rootHex, cfg, { fetchImpl = fetch, now = Date.now } = {}) => {
  if (!/^[0-9a-f]{64}$/.test(rootHex)) return { error: 'not a batch root' };
  const root = Buffer.from(rootHex, 'hex');
  const req = timeStampRequest(root);
  let reply;
  try {
    const res = await fetchImpl(cfg.url, {
      method: 'POST',
      headers: { 'content-type': 'application/timestamp-query', accept: 'application/timestamp-reply', ...(cfg.authorization ? { authorization: cfg.authorization } : {}) },
      body: req.der,
      redirect: 'error',
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) return { error: `TSA answered HTTP ${res.status}` };
    if (Number(res.headers.get('content-length') ?? 0) > MAX_REPLY) return { error: 'TSA reply too large' };
    // Read with a running count, inside the same deadline (a slow or huge body ends here).
    const chunks = [];
    let n = 0;
    for await (const c of res.body ?? []) {
      n += c.length;
      if (n > MAX_REPLY) return { error: 'TSA reply too large' };
      chunks.push(c);
    }
    reply = Buffer.concat(chunks);
  } catch {
    return { error: 'could not reach the TSA, or it was too slow' };
  }
  if (reply.length === 0) return { error: 'TSA reply empty' };
  const token = timestampTokenBytes(reply);
  if (!token) return { error: 'TSA reply is not a granted timestamp' };
  const v = await verifyTimestampToken(token, root);
  if (!v.ok) return { error: `TSA token did not verify: ${v.checks.filter((c) => !c.ok).map((c) => c.what).join('; ').slice(0, 300)}` };
  if (!v.nonce || BigInt('0x' + v.nonce) !== BigInt('0x' + req.nonce.toString('hex'))) return { error: 'TSA token nonce does not match the request' };
  // The time must be now: a token dated otherwise is a broken or lying TSA.
  const skew = Math.abs(Date.parse(v.genTime) - now());
  if (!(skew <= MAX_SKEW_MS)) return { error: 'TSA token time is not now' };
  if (cfg.pins?.length) {
    const cert = signerCertificate(token);
    const fp = cert ? createHash('sha256').update(cert).digest('hex') : '';
    if (!cfg.pins.includes(fp)) return { error: 'TSA token is not signed by the pinned certificate' };
  }
  return { token: Buffer.from(token).toString('base64'), genTime: v.genTime, signerSubject: v.signerSubject, serialNumber: v.serialNumber };
};
