// What the mirror and the checker share: the folder layout, how files are named and hashed,
// and the rule for telling a normal update from a rewrite. Node built-ins and
// lineage/ots.mjs only, so a witness needs a copy of this repository and Node, no `npm install`.
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { parseOtsFile, attestationsOf, rootDigest } from '../../lineage/ots.mjs';

/** Written into index.json, so a later layout can be told apart. */
export const FORMAT = 'veilcore-mirror/1';

/**
 * The layout, one folder per batch:
 *
 *   registry.json                        the registry's /.well-known/veilcore-registry
 *   index.json                           every batch: root, sealing, anchor, and each file's SHA-256
 *   batches/<batchId>/batch.json         the batch as the registry lists it (see batchRecord)
 *   batches/<batchId>/root.bin           the batch root as 32 raw bytes (what both timestamps stamp)
 *   batches/<batchId>/root.bin.ots       OpenTimestamps proof (Bitcoin), when there is one
 *   batches/<batchId>/root.tst           RFC 3161 token, when there is one
 *   conflicts/<batchId>/<when>-<hash>/   what the registry served that disagreed with the copy
 *                                        above, and conflict.json saying how; never deleted
 */
export const FILES = ['batch.json', 'root.bin', 'root.bin.ots', 'root.tst'];

/** A batch id becomes a folder name, and comes from the registry: nothing that could leave the folder. */
export const BATCH_ID = /^[A-Za-z0-9][A-Za-z0-9-]{0,63}$/;
export const HEX64 = /^[0-9a-f]{64}$/;

/**
 * VeilCore's main contract on Midnight mainnet, where batch roots are anchored. Pinned here,
 * not taken from the registry: it is MAINNET_VEILCORE_ADDRESS in api/src/deploy-guard.ts of
 * hunterincoming/veilcore and "Mainnet day" in this README. A witness checks it there.
 */
export const MAINNET_CONTRACT = 'a04de0a2684f3713276325649540c7278ffd07cba8b014e7489844f319a02347';

export const sha256 = (b) => createHash('sha256').update(b).digest('hex');

/** JSON with keys sorted and a final newline: the same data is always the same bytes. */
export const stableJson = (v) => `${JSON.stringify(sortKeys(v), null, 2)}\n`;
const sortKeys = (v) => {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === 'object') return Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys(v[k])]));
  return v;
};

/** Write by renaming a finished temporary file, so a crash never leaves half a file. */
export const writeAtomic = (path, bytes) => {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.tmp-${process.pid}`;
  writeFileSync(tmp, bytes);
  renameSync(tmp, path);
};

/** writeAtomic, only when the bytes differ from what is there. */
export const writeIfChanged = (path, bytes) => {
  const b = Buffer.from(bytes);
  if (existsSync(path) && readFileSync(path).equals(b)) return false;
  writeAtomic(path, b);
  return true;
};

export const readJson = (path) => JSON.parse(readFileSync(path, 'utf8'));
export const readIf = (path) => (existsSync(path) ? readFileSync(path) : null);
export const batchDir = (root, id) => {
  if (!BATCH_ID.test(id)) throw new Error(`not a batch id: ${JSON.stringify(id).slice(0, 80)}`);
  return join(root, 'batches', id);
};

/**
 * One batch as kept in batch.json: what the registry's GET /batches lists for it, minus
 * what changes with every retry (`opentimestamps.error`). `sealedAt` as an ISO instant.
 * Throws on anything malformed: the registry is not trusted to send sensible data.
 */
export const batchRecord = (row) => {
  if (!row || typeof row !== 'object') throw new Error('a listed batch is not an object');
  const batchId = row.batch_id ?? row.batchId;
  if (typeof batchId !== 'string' || !BATCH_ID.test(batchId)) throw new Error('a listed batch has no usable batch id');
  if (typeof row.root !== 'string' || !HEX64.test(row.root)) throw new Error(`${batchId}: root is not 64 lowercase hex characters`);
  const sealed = row.sealed_at ?? row.sealedAt;
  const sealedMs = typeof sealed === 'number' ? sealed : Date.parse(sealed);
  if (!Number.isFinite(sealedMs)) throw new Error(`${batchId}: no sealing time`);
  const recordCount = row.record_count ?? row.recordCount;
  if (!Number.isSafeInteger(recordCount) || recordCount < 0) throw new Error(`${batchId}: record count is not a whole number`);
  const anchor = row.anchor ?? null;
  if (anchor !== null && (typeof anchor !== 'object' || Array.isArray(anchor))) throw new Error(`${batchId}: anchor is not an object`);
  const ots = row.opentimestamps && typeof row.opentimestamps === 'object' ? row.opentimestamps : {};
  return {
    batchId,
    root: row.root,
    sealedAt: new Date(sealedMs).toISOString(),
    recordCount,
    anchor,
    ...(Array.isArray(row.earlierAnchors) && row.earlierAnchors.length ? { earlierAnchors: row.earlierAnchors } : {}),
    opentimestamps: {
      status: typeof ots.status === 'string' ? ots.status : 'none',
      ...(Number.isSafeInteger(ots.bitcoinBlockHeight) ? { bitcoinBlockHeight: ots.bitcoinBlockHeight, bitcoinBlockTime: ots.bitcoinBlockTime ?? null } : {}),
    },
  };
};

const sameAnchor = (a, b) => stableJson(a) === stableJson(b);
/** An earlier anchor as listed (it gains replacedAt) matches the anchor it was. */
const isSameTx = (listed, a) => listed && a && listed.network === a.network && listed.txHash === a.txHash
  && listed.contractAddress === a.contractAddress && (listed.chain ?? 'midnight') === (a.chain ?? 'midnight');

/**
 * Compare a batch already in the mirror with what the registry serves now. Returns
 * { conflicts: [reason...], updates: [what...] }. A conflict is anything the registry is never
 * supposed to change once it has published it; an update is the normal life of a batch.
 *
 *   never changes          batchId, root, sealedAt, recordCount
 *   anchor                 none -> one is an update; a test-network anchor followed by a
 *                          mainnet one is an update only when the new listing keeps the old
 *                          one in earlierAnchors (the registry's own rule); anything else is a
 *                          conflict. earlierAnchors only ever grows.
 *   opentimestamps status  a summary; the .ots file itself is compared in otsChange
 */
export const compareRecords = (old, now) => {
  const conflicts = [];
  const updates = [];
  for (const k of ['batchId', 'root', 'sealedAt', 'recordCount']) {
    if (old[k] !== now[k]) conflicts.push(`${k} changed from ${old[k]} to ${now[k]}`);
  }
  if (old.anchor === null && now.anchor !== null) updates.push(`anchored on ${now.anchor.network ?? 'an unnamed network'}`);
  else if (old.anchor !== null && now.anchor === null) conflicts.push(`the anchor (transaction ${old.anchor.txHash}) was removed`);
  else if (old.anchor !== null && !sameAnchor(old.anchor, now.anchor)) {
    const kept = (now.earlierAnchors ?? []).some((e) => isSameTx(e, old.anchor));
    if (old.anchor.testNetwork === true && now.anchor.network === 'mainnet' && kept) {
      updates.push(`anchored again on mainnet; the ${old.anchor.network} anchor is kept as an earlier one`);
    } else {
      conflicts.push(`the anchor changed from transaction ${old.anchor.txHash} on ${old.anchor.network} to ${now.anchor.txHash} on ${now.anchor.network}`);
    }
  }
  const was = old.earlierAnchors ?? [];
  const is = now.earlierAnchors ?? [];
  if (was.length > is.length || was.some((e, i) => !sameAnchor(e, is[i]))) conflicts.push('an earlier anchor was removed or changed');
  if (stableJson(old.opentimestamps) !== stableJson(now.opentimestamps)) {
    updates.push(`OpenTimestamps status ${old.opentimestamps.status} -> ${now.opentimestamps.status}`);
  }
  return { conflicts, updates };
};

/**
 * Whether every operation of `old` is still in `now`, and every Bitcoin attestation with it.
 * Pending attestations may go: an upgraded proof can drop the calendar's promise once it has
 * the path to the block (the reference client does the same).
 */
const covers = (now, old) => {
  for (const [k, a] of old.attestations) if (a.kind === 'bitcoin' && !now.attestations.has(k)) return false;
  for (const [k, { ts }] of old.ops) {
    const sub = now.ops.get(k);
    if (!sub || !covers(sub.ts, ts)) return false;
  }
  return true;
};

/**
 * How a batch's .ots changed between the mirror and the registry. Both are parsed for the
 * batch's own root first (the proof must commit to SHA-256 of root.bin).
 *
 *   'same'       byte for byte
 *   'upgraded'   the new file keeps everything the old one proved and adds a Bitcoin
 *                attestation: the pending -> Bitcoin step every proof goes through
 *   'extended'   keeps everything and adds something else (a calendar's answer merged in)
 *   'conflict'   anything else: a Bitcoin attestation gone, a path gone, another root,
 *                a file that does not parse. Returned with the reason.
 */
export const otsChange = (root, oldBytes, newBytes) => {
  if (oldBytes.equals(newBytes)) return { kind: 'same' };
  const digest = rootDigest(root);
  let a;
  let b;
  try { a = parseOtsFile(oldBytes, digest); } catch (e) { return { kind: 'conflict', reason: `the copy in the mirror does not parse (${e.message})` }; }
  try { b = parseOtsFile(newBytes, digest); } catch (e) { return { kind: 'conflict', reason: `the new proof does not parse for this root (${e.message})` }; }
  if (!covers(b, a)) return { kind: 'conflict', reason: 'the new proof drops something the old one proved' };
  const btc = (ts) => attestationsOf(ts).filter((x) => x.kind === 'bitcoin').length;
  const pendingGone = attestationsOf(a).filter((x) => x.kind === 'pending').length > attestationsOf(b).filter((x) => x.kind === 'pending').length;
  if (btc(b) > btc(a)) return { kind: 'upgraded' };
  if (pendingGone) return { kind: 'conflict', reason: 'the new proof drops a pending attestation and adds no Bitcoin one' };
  return { kind: 'extended' };
};
