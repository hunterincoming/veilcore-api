// The public mirror: copy every batch the registry has dated into plain files, and refuse,
// loudly, when the registry serves a different history from the one already copied.
//
// Borrowed from Certificate Transparency monitors and Sigstore witnesses: keep what you saw,
// and never let a later answer from the log replace it. A monitor that finds the log's new
// view does not extend its old one keeps both and raises the alarm; this does the same per
// batch. See docs/run-a-witness.md.
// SPDX-License-Identifier: Apache-2.0

import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseOtsFile, attestationsOf, rootDigest } from '../../lineage/ots.mjs';
import {
  FORMAT, FILES, BATCH_ID, sha256, stableJson, writeAtomic, writeIfChanged, readJson, readIf, batchDir,
  batchRecord, compareRecords, otsChange,
} from './common.mjs';

/** Pages of this many batches (the registry allows up to 500). */
export const PAGE = 200;
/** Most any one answer may be, so a broken or hostile registry cannot fill the disk. */
const CAP = { list: 32 << 20, json: 1 << 20, 'root.bin': 64, 'root.bin.ots': 1 << 20, 'root.tst': 1 << 20 };
const MAX_PAGES = 10_000;

const isLocal = (u) => ['127.0.0.1', 'localhost', '[::1]'].includes(u.hostname);

/** GET with a size cap, a timeout and no redirects. Returns { status, body } (404 allowed). */
export const get = async (url, { cap, fetchImpl = fetch, timeoutMs = 30_000 }) => {
  const u = new URL(url);
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && isLocal(u))) throw new Error('only https registries are mirrored');
  const r = await fetchImpl(url, { redirect: 'error', signal: AbortSignal.timeout(timeoutMs), headers: { 'user-agent': 'veilcore-mirror' } });
  if (r.status === 404) { await r.body?.cancel?.().catch?.(() => {}); return { status: 404, body: Buffer.alloc(0) }; }
  if (!r.ok) throw new Error(`${u.pathname} answered ${r.status}`);
  const declared = Number(r.headers?.get?.('content-length'));
  if (declared > cap) throw new Error(`${u.pathname} is larger than expected`);
  const chunks = [];
  let total = 0;
  for await (const c of r.body ?? []) {
    total += c.length;
    if (total > cap) throw new Error(`${u.pathname} is larger than expected`);
    chunks.push(Buffer.from(c));
  }
  return { status: r.status, body: Buffer.concat(chunks) };
};

const getJson = async (url, opts) => {
  const { status, body } = await get(url, opts);
  if (status === 404) throw new Error(`${new URL(url).pathname} is not there (404)`);
  try { return JSON.parse(body.toString('utf8')); } catch { throw new Error(`${new URL(url).pathname} is not JSON`); }
};

/**
 * Every batch the registry lists. Asks for pages (`?limit=` and `?before=`, `next` in the
 * answer); a registry from before paging ignores both and sends every batch with no `next`,
 * which ends the loop the same way. A batch listed twice must be listed the same both times.
 */
export const listAll = async (api, { fetchImpl, pageSize = PAGE } = {}) => {
  const seen = new Map();
  let before = null;
  for (let page = 0; page < MAX_PAGES; page++) {
    const q = new URLSearchParams({ limit: String(pageSize), ...(before ? { before } : {}) });
    const body = await getJson(`${api}/batches?${q}`, { cap: CAP.list, fetchImpl });
    if (!body || !Array.isArray(body.batches)) throw new Error('/batches did not list batches');
    for (const row of body.batches) {
      const rec = batchRecord(row);
      const prev = seen.get(rec.batchId);
      if (prev && stableJson(prev) !== stableJson(rec)) throw new Error(`the registry listed ${rec.batchId} twice, differently`);
      seen.set(rec.batchId, rec);
    }
    const next = body.next;
    if (next === undefined || next === null) return [...seen.values()];
    if (typeof next !== 'string' || !BATCH_ID.test(next) || next === before) throw new Error('/batches gave a page cursor that goes nowhere');
    before = next;
  }
  throw new Error(`/batches still had more after ${MAX_PAGES} pages`);
};

const order = (a, b) => (a.sealedAt < b.sealedAt ? -1 : a.sealedAt > b.sealedAt ? 1 : a.batchId < b.batchId ? -1 : a.batchId > b.batchId ? 1 : 0);

/**
 * Keep what the registry served that disagrees with the mirror, beside it, once: the folder
 * is named by the UTC day and a hash of what was served, so the same disagreement seen again
 * on the next run is not written twice (it is still reported, every run, until resolved).
 */
const keepConflict = (root, id, files, reasons, now) => {
  const hash = sha256(Buffer.concat(Object.entries(files).sort().map(([n, b]) => Buffer.concat([Buffer.from(`${n}\0`), b, Buffer.from('\0')])))).slice(0, 12);
  const base = join(root, 'conflicts', id);
  const already = existsSync(base) && readdirSync(base).find((d) => d.endsWith(`-${hash}`));
  if (already) return join('conflicts', id, already);
  const dir = join(base, `${now.toISOString().slice(0, 10)}-${hash}`);
  for (const [name, bytes] of Object.entries(files)) writeAtomic(join(dir, name), bytes);
  writeAtomic(join(dir, 'conflict.json'), stableJson({ batchId: id, seenAt: now.toISOString(), reasons }));
  return join('conflicts', id, `${now.toISOString().slice(0, 10)}-${hash}`);
};

/**
 * One run. Returns a summary; `conflicts` non-empty means the registry served a history that
 * does not extend the mirror's (the caller exits 2). Nothing already in the mirror is ever
 * overwritten except by a normal update: a first anchor, a test-network anchor followed by a
 * mainnet one, a proof that only gains (pending -> Bitcoin), a token where there was none.
 *
 * `full` fetches every file of every batch again. Otherwise a batch's files are fetched only
 * while they can still change: root.bin once, root.bin.ots until it holds a Bitcoin
 * attestation, root.tst until there is one.
 */
export const mirror = async ({ api, out, fetchImpl = fetch, full = false, now = new Date(), log = () => {} }) => {
  api = api.replace(/\/+$/, '');
  const summary = { registry: api, batches: 0, added: [], updated: [], unchanged: 0, conflicts: [], missingFromRegistry: [], notes: [] };

  const wellKnown = await getJson(`${api}/.well-known/veilcore-registry`, { cap: CAP.json, fetchImpl });
  const oldWellKnown = readIf(join(out, 'registry.json'));
  if (oldWellKnown && oldWellKnown.toString() !== stableJson(wellKnown)) summary.notes.push('the registry changed /.well-known/veilcore-registry (registry.json; see the git history for the old one)');
  writeIfChanged(join(out, 'registry.json'), stableJson(wellKnown));

  const listed = await listAll(api, { fetchImpl });
  summary.batches = listed.length;
  const oldIndex = existsSync(join(out, 'index.json')) ? readJson(join(out, 'index.json')) : { batches: [] };
  const known = new Map((oldIndex.batches ?? []).map((b) => [b.batchId, b]));
  const index = new Map(known);

  for (const rec of listed) {
    const id = rec.batchId;
    const dir = batchDir(out, id);
    const had = known.get(id);
    const old = had ? readJson(join(dir, 'batch.json')) : null;
    const oldFiles = Object.fromEntries(FILES.slice(1).map((f) => [f, readIf(join(dir, f))]));
    const conflicts = [];
    const updates = [];
    if (old) {
      const c = compareRecords(old, rec);
      conflicts.push(...c.conflicts);
      updates.push(...c.updates);
    }

    // Which files to ask for this run.
    const want = new Set();
    if (full || !oldFiles['root.bin']) want.add('root.bin');
    const otsIsFinal = oldFiles['root.bin.ots'] && otsHasBitcoin(rec.root, oldFiles['root.bin.ots']);
    if (full || (!otsIsFinal && (rec.opentimestamps.status !== 'none' || oldFiles['root.bin.ots']))) want.add('root.bin.ots');
    if (full || !oldFiles['root.tst']) want.add('root.tst');

    const fetched = {};
    for (const f of want) {
      const { status, body } = await get(`${api}/batches/${encodeURIComponent(id)}/${f}`, { cap: CAP[f], fetchImpl });
      fetched[f] = status === 404 ? null : body;
    }

    // root.bin is the root itself; the registry serving anything else is a contradiction in
    // its own answers.
    if (fetched['root.bin'] !== undefined && (fetched['root.bin'] === null || fetched['root.bin'].toString('hex') !== rec.root)) {
      conflicts.push('root.bin is not the listed root');
    }
    const next = { 'root.bin': Buffer.from(rec.root, 'hex') };
    for (const f of ['root.bin.ots', 'root.tst']) {
      const was = oldFiles[f];
      const is = fetched[f];
      if (is === undefined) { if (was) next[f] = was; continue; } // not asked for this run
      if (was && is === null) { conflicts.push(`${f} was there and is gone`); next[f] = was; continue; }
      // A first copy is kept as served; the checker judges it.
      if (!was && is) { next[f] = is; if (old) updates.push(`${f} added`); continue; }
      if (!was) continue;
      if (f === 'root.tst') {
        if (!was.equals(is)) conflicts.push('root.tst changed');
        next[f] = was;
        continue;
      }
      const ch = otsChange(rec.root, was, is);
      if (ch.kind === 'conflict') { conflicts.push(`root.bin.ots: ${ch.reason}`); next[f] = was; }
      else { next[f] = ch.kind === 'same' ? was : is; if (ch.kind !== 'same') updates.push(`root.bin.ots ${ch.kind}`); }
    }

    if (conflicts.length) {
      const served = { 'batch.json': Buffer.from(stableJson(rec)) };
      for (const [f, b] of Object.entries(fetched)) if (b) served[f] = b;
      const where = keepConflict(out, id, served, conflicts, now);
      summary.conflicts.push({ batchId: id, reasons: conflicts, keptIn: where });
      log(`CONFLICT ${id}: ${conflicts.join('; ')} (what the registry served is kept in ${where}; the mirror's copy is unchanged)`);
      if (!old) continue; // a new batch that already contradicts itself is not added
      // A batch in conflict is left exactly as it was, normal updates included, until a
      // person has looked; the index notes where the other version is.
      index.set(id, { ...had, conflicts: [...new Set([...(had.conflicts ?? []), where])].sort() });
      continue;
    }

    // Write: files first, batch.json last, index at the very end.
    for (const [f, b] of Object.entries(next)) {
      if (!oldFiles[f] || !oldFiles[f].equals(b)) writeAtomic(join(dir, f), b);
    }
    const recBytes = Buffer.from(stableJson(rec));
    if (!old || stableJson(old) !== recBytes.toString()) writeAtomic(join(dir, 'batch.json'), recBytes);
    index.set(id, {
      batchId: id,
      root: rec.root,
      sealedAt: rec.sealedAt,
      anchor: rec.anchor ? { network: rec.anchor.network ?? null, txHash: rec.anchor.txHash ?? null, blockHeight: rec.anchor.blockHeight ?? null } : null,
      files: Object.fromEntries([['batch.json', sha256(recBytes)], ...Object.entries(next).map(([f, b]) => [f, sha256(b)])].sort()),
      ...(had?.conflicts ? { conflicts: had.conflicts } : {}),
    });
    if (!old) summary.added.push(id);
    else if (updates.length) summary.updated.push({ batchId: id, what: updates });
    else summary.unchanged++;
  }

  // A batch the mirror has and the registry no longer lists: history shrank.
  const listedIds = new Set(listed.map((b) => b.batchId));
  for (const id of known.keys()) {
    if (listedIds.has(id)) continue;
    summary.missingFromRegistry.push(id);
    const where = keepConflict(out, id, {}, ['the registry no longer lists this batch'], now);
    index.set(id, { ...index.get(id), conflicts: [...new Set([...(index.get(id).conflicts ?? []), where])].sort() });
    summary.conflicts.push({ batchId: id, reasons: ['the registry no longer lists this batch'], keptIn: where });
    log(`CONFLICT ${id}: the registry no longer lists this batch (the mirror keeps its copy)`);
  }

  const batches = [...index.values()].sort(order);
  writeIfChanged(join(out, 'index.json'), stableJson({ format: FORMAT, registry: api, batches }));
  return summary;
};

/**
 * Whether a .ots for `root` already has a Bitcoin attestation (then it is not asked for again
 * except in a full run). One that does not parse never counts, so it keeps being compared.
 */
export const otsHasBitcoin = (root, bytes) => {
  try {
    return attestationsOf(parseOtsFile(bytes, rootDigest(root))).some((a) => a.kind === 'bitcoin');
  } catch {
    return false;
  }
};
