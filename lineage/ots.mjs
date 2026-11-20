// OpenTimestamps: a second, independent timestamp for every sealed batch, on Bitcoin.
//
// A batch root anchored on Midnight is dated by Midnight. Stamping the same root with
// OpenTimestamps dates it again on Bitcoin, through public calendar servers. The result is
// a standard .ots file that anyone can check with the official tools (`ots verify`), with
// no dependency on VeilCore, Midnight, or this server still existing.
//
// What is stamped: the "file" is the 32 raw bytes of the batch root (root.bin), so the
// .ots proves that SHA-256(root.bin) existed by the time of the Bitcoin block. A calendar
// first returns a PENDING proof: a promise to put the digest into a Bitcoin transaction.
// That is not yet a Bitcoin timestamp, and is never described as one. Once the calendar's
// transaction confirms (a few hours), upgradeAnswer() fetches the path to the block.
//
// This file speaks the calendar protocol directly instead of using the npm
// "opentimestamps" package, last published in 2022 on deprecated dependencies.
//
// Calendars are third parties, so nothing they send is stored until it has been parsed the
// way python-opentimestamps parses it (the reference implementation), with every operation
// replayed from the digest and the reference limits applied: message and result at most
// 4096 bytes, nesting at most 256, operation arguments 1-4096 bytes, pending URIs at most
// 1000 characters from the reference's character set. Stricter than the reference in four
// places, on purpose:
//   - only sha256, append and prepend are accepted (all a Bitcoin calendar uses);
//   - only PendingAttestation is accepted in a fresh answer: a digest submitted a moment
//     ago cannot already be in a block, so a Bitcoin attestation there is a lie;
//   - a pending URI must be https and belong to the calendar that was asked (its own host,
//     or <name>.calendar.<its domain>, the pattern of the reference client's whitelist);
//   - a Bitcoin attestation from an upgrade is believed only after the block header at
//     that height is fetched and its Merkle root equals the attested message.
// Answers are merged operation by operation, as the reference Timestamp.merge does, so two
// calendars' answers can never shadow each other.
//
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';

/**
 * The aggregators the reference client uses by default. Each answers with a pending
 * attestation naming the calendar behind it, e.g. a.pool.opentimestamps.org names
 * https://alice.btc.calendar.opentimestamps.org.
 */
export const DEFAULT_CALENDARS = [
  'https://a.pool.opentimestamps.org',
  'https://b.pool.opentimestamps.org',
  'https://a.pool.eternitywall.com',
  'https://ots.btc.catallaxy.com',
];
/** Where Bitcoin block headers are fetched to check an upgraded proof (Esplora API). */
export const DEFAULT_EXPLORER = 'https://blockstream.info/api';
/**
 * The explorers the registry asks by default (reliability audit, 19 Nov 2026): two run by
 * different people, so one wrong or compromised explorer cannot make a Bitcoin stamp look
 * real on its own. Both serve the Esplora API.
 */
export const DEFAULT_EXPLORERS = [DEFAULT_EXPLORER, 'https://mempool.space/api'];

/**
 * The explorers named by VEILCORE_BTC_EXPLORER: one address, or several separated by commas.
 * Unset or empty: DEFAULT_EXPLORERS. An address that is not https is left out (fetchCapped
 * would refuse it anyway); if none is left, the defaults are used rather than none.
 */
export const explorersFrom = (setting) => {
  const list = String(setting ?? '').split(',').map((s) => s.trim().replace(/\/+$/, '')).filter((s) => s && isHttpsUrl(s));
  return list.length ? [...new Set(list)] : [...DEFAULT_EXPLORERS];
};

// "\x00OpenTimestamps\x00\x00Proof\x00" followed by 8 magic bytes, then major version 1.
const HEADER = Buffer.concat([
  Buffer.from('\x00OpenTimestamps\x00\x00Proof\x00', 'latin1'),
  Buffer.from([0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94]),
]);
const MAJOR_VERSION = 1;
const OP_SHA256 = 0x08;
const OP_APPEND = 0xf0;
const OP_PREPEND = 0xf1;
const FORK = 0xff;
const ATTESTATION = 0x00;
const UNARY_OPS = new Set([0x02, 0x03, 0x08, 0x67, 0xf2, 0xf3]); // sha1, ripemd160, sha256, keccak256, reverse, hexlify
const BINARY_OPS = new Set([OP_APPEND, OP_PREPEND]);
const ACCEPTED_OPS = new Set([OP_SHA256, OP_APPEND, OP_PREPEND]);
const TAG_PENDING = '83dfe30d2ef90c8e';
const TAG_BITCOIN = '0588960d73d71901';

// Limits from python-opentimestamps (op.py, notary.py, timestamp.py).
const MAX_MSG = 4096;
const MAX_RESULT = 4096;
const RECURSION_LIMIT = 256;
const MAX_PAYLOAD = 8192;
const MAX_URI = 1000;
const URI_CHARS = /^[A-Za-z0-9\-_/:.]*$/;
const MAX_DEPTH = 256; // childrenOf only

export const MAX_ANSWER = 10_000; // a fresh calendar answer is a few hundred bytes
export const MAX_UPGRADE = 65_536; // an upgraded path to a block is a few kilobytes

/** An error whose message is ours and safe to show an operator (never upstream text). */
export class OtsError extends Error {}

const sha256 = (b) => createHash('sha256').update(b).digest();

const readVaruint = (buf, pos) => {
  let value = 0;
  let shift = 0;
  for (;;) {
    if (pos.i >= buf.length) throw new OtsError('truncated varuint');
    const b = buf[pos.i++];
    value += (b & 0x7f) * 2 ** shift;
    if (!(b & 0x80)) return value;
    shift += 7;
    if (shift > 42) throw new OtsError('varuint too long');
  }
};

const writeVaruint = (n) => {
  const out = [];
  let v = n;
  do {
    let b = v % 128;
    v = Math.floor(v / 128);
    if (v > 0) b |= 0x80;
    out.push(b);
  } while (v > 0);
  return Buffer.from(out);
};
const varbytes = (b) => Buffer.concat([writeVaruint(b.length), b]);

class Reader {
  constructor(buf) { this.buf = buf; this.i = 0; }
  byte() {
    if (this.i >= this.buf.length) throw new OtsError('truncated timestamp');
    return this.buf[this.i++];
  }
  bytes(n) {
    if (this.i + n > this.buf.length) throw new OtsError('truncated timestamp');
    const out = this.buf.subarray(this.i, this.i + n);
    this.i += n;
    return out;
  }
  varuint() { return readVaruint(this.buf, this); }
  varbytes(max, min = 0) {
    const n = this.varuint();
    if (n > max || n < min) throw new OtsError('length out of range');
    return this.bytes(n);
  }
  eof() { if (this.i !== this.buf.length) throw new OtsError('trailing bytes after the timestamp'); }
}

/**
 * Split one serialised timestamp node into its children (each a byte range), checking
 * the structure only. Kept for callers that want the shape without replaying it; nothing
 * that is stored relies on it (see parseTimestamp).
 */
export const childrenOf = (buf, start = 0, depth = 0) => {
  if (depth > MAX_DEPTH) throw new Error('timestamp nested too deep');
  const pos = { i: start };
  const children = [];
  const skipChild = () => {
    const from = pos.i;
    if (pos.i >= buf.length) throw new Error('truncated timestamp');
    const tag = buf[pos.i++];
    if (tag === ATTESTATION) {
      pos.i += 8; // attestation type
      const len = readVaruint(buf, pos);
      pos.i += len;
      if (pos.i > buf.length) throw new Error('truncated attestation');
    } else if (UNARY_OPS.has(tag)) {
      pos.i = childrenOf(buf, pos.i, depth + 1).end;
    } else if (BINARY_OPS.has(tag)) {
      const len = readVaruint(buf, pos);
      if (len < 1 || len > 4096) throw new Error('bad operation argument length');
      pos.i += len;
      if (pos.i > buf.length) throw new Error('truncated operation argument');
      pos.i = childrenOf(buf, pos.i, depth + 1).end;
    } else {
      throw new Error(`unknown timestamp tag 0x${tag.toString(16)}`);
    }
    children.push(buf.subarray(from, pos.i));
  };
  while (pos.i < buf.length && buf[pos.i] === FORK) {
    pos.i++;
    skipChild();
  }
  skipChild();
  return { children, end: pos.i };
};

// ---- the timestamp tree, as python-opentimestamps models it ----
//
// A node: { msg, attestations: Map<key, attestation>, ops: Map<key, { op, ts }> }.
// An attestation: { kind: 'pending', uri } or { kind: 'bitcoin', height }.
// An op: { tag, arg? }.

const node = (msg) => ({ msg, attestations: new Map(), ops: new Map() });
const serialiseOp = (op) => (BINARY_OPS.has(op.tag) ? Buffer.concat([Buffer.from([op.tag]), varbytes(op.arg)]) : Buffer.from([op.tag]));
const serialiseAttestation = (a) => {
  const payload = a.kind === 'pending' ? varbytes(Buffer.from(a.uri, 'latin1')) : writeVaruint(a.height);
  return Buffer.concat([Buffer.from(a.kind === 'pending' ? TAG_PENDING : TAG_BITCOIN, 'hex'), varbytes(payload)]);
};
const keyOf = (b) => b.toString('hex');

const applyOp = (op, msg) => {
  if (msg.length > MAX_MSG) throw new OtsError('message too long for an operation');
  let out;
  if (op.tag === OP_SHA256) out = sha256(msg);
  else if (op.tag === OP_APPEND) out = Buffer.concat([msg, op.arg]);
  else out = Buffer.concat([op.arg, msg]);
  if (out.length > MAX_RESULT) throw new OtsError('operation result too long');
  return out;
};

/**
 * What a policy allows.
 *   allowBitcoin   accept BitcoinBlockHeaderAttestation (only in an upgrade)
 *   pendingUri     (uri) => boolean, beyond the reference's charset and length rules
 */
const parseAttestation = (r, msg, policy) => {
  const type = r.bytes(8).toString('hex');
  const p = new Reader(r.varbytes(MAX_PAYLOAD));
  if (type === TAG_PENDING) {
    const uri = p.varbytes(MAX_URI).toString('latin1');
    p.eof();
    if (!URI_CHARS.test(uri)) throw new OtsError('pending URI has characters the reference parser refuses');
    if (!isHttpsUri(uri) || !policy.pendingUri(uri)) throw new OtsError('pending URI does not belong to the calendar asked');
    return { kind: 'pending', uri };
  }
  if (type === TAG_BITCOIN) {
    if (!policy.allowBitcoin) throw new OtsError('a fresh calendar answer cannot carry a Bitcoin attestation');
    const height = p.varuint();
    p.eof();
    if (msg.length !== 32) throw new OtsError('a Bitcoin attestation must commit to a 32-byte Merkle root');
    return { kind: 'bitcoin', height };
  }
  throw new OtsError('attestation type not accepted');
};

const parseNode = (r, msg, limit, policy) => {
  if (limit < 1) throw new OtsError('timestamp nested too deep');
  const ts = node(msg);
  const child = (tag) => {
    if (tag === ATTESTATION) {
      const a = parseAttestation(r, msg, policy);
      const k = keyOf(serialiseAttestation(a));
      if (ts.attestations.has(k)) throw new OtsError('duplicate attestation in one node');
      ts.attestations.set(k, a);
      return;
    }
    if (!ACCEPTED_OPS.has(tag)) throw new OtsError(`operation 0x${tag.toString(16)} not accepted`);
    const op = BINARY_OPS.has(tag) ? { tag, arg: Buffer.from(r.varbytes(MAX_RESULT, 1)) } : { tag };
    const k = keyOf(serialiseOp(op));
    if (ts.ops.has(k)) throw new OtsError('duplicate operation in one node');
    ts.ops.set(k, { op, ts: parseNode(r, applyOp(op, msg), limit - 1, policy) });
  };
  let tag = r.byte();
  while (tag === FORK) {
    child(r.byte());
    tag = r.byte();
  }
  child(tag);
  return ts;
};

/** Parse a serialised timestamp on `msg`, replaying every operation. Throws OtsError. */
export const parseTimestamp = (buf, msg, policy) => {
  const r = new Reader(Buffer.from(buf));
  const ts = parseNode(r, Buffer.from(msg), RECURSION_LIMIT, { allowBitcoin: false, pendingUri: () => true, ...policy });
  r.eof();
  return ts;
};

/** Serialise a node (children in a fixed order; any order is valid). */
export const serialiseTimestamp = (ts) => {
  const children = [
    ...[...ts.attestations.values()].map((a) => Buffer.concat([Buffer.from([ATTESTATION]), serialiseAttestation(a)])),
    ...[...ts.ops.values()].map(({ op, ts: sub }) => Buffer.concat([serialiseOp(op), serialiseTimestamp(sub)])),
  ].sort(Buffer.compare);
  if (children.length === 0) throw new OtsError('empty timestamp');
  return Buffer.concat(children.flatMap((c, i) => (i < children.length - 1 ? [Buffer.from([FORK]), c] : [c])));
};

/** Merge `other` into `ts` op by op, as python-opentimestamps Timestamp.merge does. */
export const mergeInto = (ts, other) => {
  if (!ts.msg.equals(other.msg)) throw new OtsError('cannot merge timestamps on different messages');
  for (const [k, a] of other.attestations) ts.attestations.set(k, a);
  for (const [k, { op, ts: sub }] of other.ops) {
    if (!ts.ops.has(k)) ts.ops.set(k, { op, ts: node(sub.msg) });
    mergeInto(ts.ops.get(k).ts, sub);
  }
  return ts;
};

/** Every attestation in a tree, with the message it commits and the node holding it. */
export const attestationsOf = (ts, out = []) => {
  for (const a of ts.attestations.values()) out.push({ ...a, msg: ts.msg, node: ts });
  for (const { ts: sub } of ts.ops.values()) attestationsOf(sub, out);
  return out;
};

const isHttpsUri = (uri) => {
  try {
    const u = new URL(uri);
    return u.protocol === 'https:' && !u.username && !u.password && !u.port && !u.search && !u.hash;
  } catch {
    return false;
  }
};

/**
 * Whether a pending URI belongs to `calendarUrl`: the same host, or
 * <name>.calendar.<the calendar's domain> (e.g. alice.btc.calendar.opentimestamps.org), which is how the public aggregators name the
 * calendars behind them (and the reference client's upgrade whitelist pattern).
 */
export const pendingUriBelongsTo = (uri, calendarUrl) => {
  if (!isHttpsUri(uri)) return false;
  let host;
  let cal;
  try { host = new URL(uri).hostname; cal = new URL(calendarUrl).hostname; } catch { return false; }
  if (host === cal) return true;
  const domain = cal.split('.').slice(-2).join('.');
  const rest = host.endsWith(`.calendar.${domain}`) ? host.slice(0, -`.calendar.${domain}`.length) : null;
  return rest !== null && /^([a-z0-9-]{1,63}\.){0,3}[a-z0-9-]{1,63}$/.test(rest);
};

// ---- talking to calendars ----

/** A short, fixed description of a failed request: never upstream text or addresses. */
export const summarise = (e) => {
  if (e instanceof OtsError) return e.message;
  if (e?.name === 'TimeoutError' || e?.name === 'AbortError') return 'timed out';
  if (/redirect/i.test(String(e?.cause?.message ?? e?.message ?? ''))) return 'redirect refused';
  return 'connection failed';
};

/**
 * Fetch at most `cap` bytes over https, refusing redirects. Content-Length is checked
 * first and the body is read only up to the cap, so a calendar cannot make this process
 * hold more than `cap` bytes of its answer. Returns { status, body }.
 */
export const fetchCapped = async (url, init, { cap, fetchImpl = fetch, timeoutMs = 15_000, ok404 = false }) => {
  if (!isHttpsUrl(url)) throw new OtsError('only https calendars are used');
  const r = await fetchImpl(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(timeoutMs) });
  const cancel = () => { try { r.body?.cancel?.().catch?.(() => {}); } catch { /* already closed */ } };
  if (ok404 && r.status === 404) { cancel(); return { status: 404, body: Buffer.alloc(0) }; }
  if (!r.ok) { cancel(); throw new OtsError(`HTTP ${r.status}`); }
  const declared = r.headers?.get?.('content-length');
  if (declared !== null && declared !== undefined && Number(declared) > cap) { cancel(); throw new OtsError('answer too large'); }
  const chunks = [];
  let total = 0;
  const reader = r.body?.getReader?.();
  if (reader) {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > cap) {
        await reader.cancel().catch(() => {});
        throw new OtsError('answer too large');
      }
      chunks.push(Buffer.from(value));
    }
  }
  return { status: r.status, body: Buffer.concat(chunks) };
};
const isHttpsUrl = (url) => { try { return new URL(url).protocol === 'https:'; } catch { return false; } };

/** The policy for a fresh answer from `calendarUrl`. */
const freshPolicy = (calendarUrl) => ({ allowBitcoin: false, pendingUri: (u) => pendingUriBelongsTo(u, calendarUrl) });
/** The policy for an answer this registry already validated and stored. */
const storedPolicy = { allowBitcoin: true, pendingUri: () => true };

/**
 * Check one calendar answer to a fresh submission of `digest` and return it in canonical
 * form. Throws OtsError with the reason.
 */
export const validateFreshAnswer = (body, digest, calendarUrl) => {
  if (body.length === 0 || body.length > MAX_ANSWER) throw new OtsError('unexpected answer size');
  const ts = parseTimestamp(body, digest, freshPolicy(calendarUrl));
  if (!attestationsOf(ts).some((a) => a.kind === 'pending')) throw new OtsError('answer has no pending attestation');
  return serialiseTimestamp(ts);
};

/** A detached .ots file for `fileDigest` (the SHA-256 of the stamped file) from stored answers. */
export const otsFile = (fileDigest, answers) => {
  if (fileDigest.length !== 32) throw new Error('the file digest is 32 bytes');
  if (answers.length === 0) throw new OtsError('no calendar answered');
  const merged = node(Buffer.from(fileDigest));
  for (const a of answers) mergeInto(merged, parseTimestamp(a, fileDigest, storedPolicy));
  return Buffer.concat([HEADER, writeVaruint(MAJOR_VERSION), Buffer.from([OP_SHA256]), Buffer.from(fileDigest), serialiseTimestamp(merged)]);
};

/** Read a detached .ots file this module wrote, returning its timestamp. */
export const parseOtsFile = (buf, expectedDigest) => {
  const b = Buffer.from(buf);
  if (b.length < HEADER.length + 34 || !b.subarray(0, HEADER.length).equals(HEADER)) throw new OtsError('not an OpenTimestamps file');
  const pos = { i: HEADER.length };
  if (readVaruint(b, pos) !== MAJOR_VERSION) throw new OtsError('unsupported .ots version');
  if (b[pos.i++] !== OP_SHA256) throw new OtsError('not a sha256 .ots file');
  const digest = b.subarray(pos.i, pos.i + 32);
  if (expectedDigest && !digest.equals(expectedDigest)) throw new OtsError('the .ots commits to a different file');
  return parseTimestamp(b.subarray(pos.i + 32), digest, storedPolicy);
};

/** The bytes OpenTimestamps stamps for a batch: the root as 32 raw bytes. */
export const rootFile = (rootHex) => {
  if (!/^[0-9a-f]{64}$/.test(rootHex)) throw new Error('a batch root is 64 lowercase hex characters');
  return Buffer.from(rootHex, 'hex');
};
export const rootDigest = (rootHex) => sha256(rootFile(rootHex));

/**
 * Stamp a batch root with every calendar that answers acceptably. Returns each calendar's
 * validated answer (to be stored separately), the merged .ots file, and a summary of the
 * calendars that failed; throws OtsError only if none answered. `fetchImpl` and
 * `timeoutMs` are for tests.
 */
export const stampRoot = async (rootHex, { calendars = DEFAULT_CALENDARS, fetchImpl = fetch, timeoutMs = 15_000 } = {}) => {
  const digest = rootDigest(rootHex);
  const results = await Promise.all(
    calendars.map(async (url) => {
      try {
        const { body } = await fetchCapped(`${url}/digest`, {
          method: 'POST',
          headers: { Accept: 'application/vnd.opentimestamps.v1', 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'veilcore-registry' },
          body: digest,
        }, { cap: MAX_ANSWER, fetchImpl, timeoutMs });
        return { calendar: url, answer: validateFreshAnswer(body, digest, url) };
      } catch (e) {
        return { calendar: url, failure: `${url}: ${summarise(e)}` };
      }
    }),
  );
  const answers = results.filter((r) => r.answer).map(({ calendar, answer }) => ({ calendar, answer }));
  const failures = results.filter((r) => r.failure).map((r) => r.failure);
  if (answers.length === 0) throw new OtsError(`no OpenTimestamps calendar answered (${failures.join('; ')})`);
  return {
    answers,
    ots: otsFile(digest, answers.map((a) => a.answer)),
    calendars: answers.map((a) => a.calendar),
    failures,
    digest: digest.toString('hex'),
  };
};

/**
 * Check a Bitcoin attestation against the block header at `height`, fetched from an
 * Esplora explorer: the header must hash to the block hash the explorer gave, and its
 * Merkle root must equal the attested message. Returns the block time. Throws OtsError
 * (`mismatch: true` when the header was fetched and the attestation is false).
 */
export const checkBitcoinBlock = async (height, merkleRoot, { explorer = DEFAULT_EXPLORER, fetchImpl = fetch, timeoutMs = 15_000 } = {}) => {
  if (!Number.isSafeInteger(height) || height < 0) throw new OtsError('bad block height');
  const hash = (await fetchCapped(`${explorer}/block-height/${height}`, { method: 'GET' }, { cap: 128, fetchImpl, timeoutMs })).body.toString('latin1').trim();
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new OtsError('explorer gave no block hash');
  const hex = (await fetchCapped(`${explorer}/block/${hash}/header`, { method: 'GET' }, { cap: 256, fetchImpl, timeoutMs })).body.toString('latin1').trim();
  if (!/^[0-9a-f]{160}$/.test(hex)) throw new OtsError('explorer gave no block header');
  const header = Buffer.from(hex, 'hex');
  if (Buffer.from(sha256(sha256(header))).reverse().toString('hex') !== hash) throw new OtsError('explorer header does not match its block hash');
  if (!header.subarray(36, 68).equals(merkleRoot)) {
    const e = new OtsError(`Bitcoin attestation does not match block ${height}`);
    e.mismatch = true;
    throw e;
  }
  return { height, time: new Date(header.readUInt32LE(68) * 1000).toISOString(), hash };
};

/**
 * The same check with every explorer in `explorers`, which must all agree (reliability audit,
 * 19 Nov 2026). Each is asked at the same time. The block is believed only when every one of
 * them fetched a header that hashes to the hash it gave, holds the attested Merkle root, and
 * names the same block hash as the others:
 *   - any explorer whose header does not hold the root makes it a mismatch (`mismatch: true`),
 *     even if another explorer was down: one down never hides another's mismatch;
 *   - an explorer that can't be reached, or explorers naming different blocks, is an error
 *     without `mismatch`, so the answer stays pending and the upkeep timer asks again later.
 *     A stamp waiting too long raises the `ots-behind` alert, which says to look.
 * Returns { height, time, hash, explorers } (the hosts asked). Throws OtsError.
 */
export const checkBitcoinBlockAgreed = async (height, merkleRoot, { explorers = DEFAULT_EXPLORERS, fetchImpl = fetch, timeoutMs = 15_000, checkOne = checkBitcoinBlock } = {}) => {
  if (!Array.isArray(explorers) || explorers.length === 0) throw new OtsError('no Bitcoin explorer is set');
  const hostOf = (e) => { try { return new URL(e).host; } catch { return 'an explorer'; } };
  const settled = await Promise.allSettled(explorers.map((explorer) => checkOne(height, merkleRoot, { explorer, fetchImpl, timeoutMs })));
  const lied = settled.findIndex((s) => s.status === 'rejected' && s.reason?.mismatch);
  if (lied >= 0) {
    const e = new OtsError(`Bitcoin attestation does not match block ${height} (header from ${hostOf(explorers[lied])})`);
    e.mismatch = true;
    throw e;
  }
  const down = settled.findIndex((s) => s.status === 'rejected');
  if (down >= 0) throw new OtsError(`block ${height}: ${hostOf(explorers[down])} gave no usable header (${summarise(settled[down].reason)}); not believed until every explorer agrees`);
  const got = settled.map((s) => s.value);
  if (got.some((g) => g.hash !== undefined && g.hash !== got[0].hash) || got.some((g) => g.time !== got[0].time)) {
    throw new OtsError(`explorers disagree about block ${height}; not believed`);
  }
  return { ...got[0], explorers: explorers.map(hostOf) };
};

/**
 * Upgrade one stored answer: ask the calendar named by each pending attestation for the
 * path to a Bitcoin block, validate it (Bitcoin attestations now allowed), check every
 * block it names, and merge it in. Only pending URIs that belong to one of `calendars`
 * are contacted. Returns { answer, bitcoin: {height, time} | null, pending, errors }.
 */
export const upgradeAnswer = async (answer, digest, { calendars = DEFAULT_CALENDARS, fetchImpl = fetch, timeoutMs = 15_000, explorer, explorers, checkBlock = checkBitcoinBlock } = {}) => {
  // Several explorers, all of which must agree (checkBitcoinBlockAgreed). `explorer` (one
  // address) is still accepted, as before: then only that one is asked.
  const asked = Array.isArray(explorers) && explorers.length ? explorers : explorer ? [explorer] : DEFAULT_EXPLORERS;
  const ts = parseTimestamp(answer, digest, storedPolicy);
  const errors = [];
  let pending = 0;
  let best = null;
  const already = attestationsOf(ts).filter((a) => a.kind === 'bitcoin');
  for (const leaf of attestationsOf(ts).filter((a) => a.kind === 'pending')) {
    if (!calendars.some((c) => pendingUriBelongsTo(leaf.uri, c))) { errors.push(`${leaf.uri}: not a configured calendar`); continue; }
    try {
      const { status, body } = await fetchCapped(`${leaf.uri}/timestamp/${leaf.msg.toString('hex')}`, {
        method: 'GET', headers: { Accept: 'application/vnd.opentimestamps.v1', 'User-Agent': 'veilcore-registry' },
      }, { cap: MAX_UPGRADE, fetchImpl, timeoutMs, ok404: true });
      if (status === 404 || body.length === 0) { pending++; continue; }
      const up = parseTimestamp(body, leaf.msg, {
        allowBitcoin: true,
        pendingUri: (u) => calendars.some((c) => pendingUriBelongsTo(u, c)),
      });
      const blocks = attestationsOf(up).filter((a) => a.kind === 'bitcoin');
      if (blocks.length === 0) { pending++; continue; }
      const checked = [];
      for (const b of blocks) checked.push(await checkBitcoinBlockAgreed(b.height, b.msg, { explorers: asked, fetchImpl, timeoutMs, checkOne: checkBlock }));
      mergeInto(leaf.node, up);
      for (const c of checked) if (!best || c.height < best.height) best = c;
    } catch (e) {
      errors.push(`${leaf.uri}: ${summarise(e)}`);
    }
  }
  if (!best && already.length) best = { height: Math.min(...already.map((a) => a.height)), time: null };
  return { answer: serialiseTimestamp(ts), bitcoin: best, pending, errors };
};
