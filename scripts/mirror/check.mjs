// The checker: given a mirror folder and no VeilCore server, check every batch.
//
//   files     each file's SHA-256 matches index.json, and root.bin is the batch root
//   RFC 3161  the token stamps SHA-256(root.bin) and its signature verifies (openssl, and the
//             SDK when installed); whose signature it is needs the TSA's root certificate
//             (--tsa-ca), which a witness gets from the TSA itself, never from us
//   Bitcoin   the .ots commits to root.bin; each Bitcoin attestation's Merkle root is
//             compared with that block's header from a block explorer (or not, --offline).
//             The full check is `ots verify` against your own Bitcoin node.
//   Midnight  the anchor transaction, looked up on a Midnight indexer you name: it exists,
//             succeeded, made exactly one call on VeilCore's mainnet contract (pinned here,
//             not taken from the registry), that call is anchorBatch, the contract state right
//             after it holds this batch root, and its block is the block the mirror recorded
//
// Each part is OK, MISMATCH (something is wrong: say so to the operator and anyone relying on
// the dates) or COULDN'T CHECK (with the reason). A batch is OK only when every part is.
// SPDX-License-Identifier: Apache-2.0

import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { parseOtsFile, attestationsOf, rootDigest, checkBitcoinBlock, DEFAULT_EXPLORER } from '../../lineage/ots.mjs';
import { FILES, HEX64, MAINNET_CONTRACT, sha256, readJson, readIf, batchDir } from './common.mjs';

export const OK = 'ok';
export const MISMATCH = 'mismatch';
export const UNCHECKED = "couldn't check";

const verdict = (status, detail) => ({ status, detail });
/** An anchor's time may be off from the chain's block by this much before it is called a mismatch. */
const SKEW_MS = 5 * 60_000;
/** Bitcoin lets a block's time run up to two hours ahead of the network's. */
const BTC_SKEW_MS = 2 * 3_600_000;

// ── RFC 3161 ────────────────────────────────────────────────────────────────────────────

const hasOpenssl = (bin) => { try { execFileSync(bin, ['version'], { stdio: 'ignore' }); return true; } catch { return false; } };

/** The SDK's verifier, if this copy of the repository has had `npm install`. Optional. */
const loadSdk = async () => { try { return (await import('veilcore-records')).verifyTimestampToken; } catch { return null; } };

/**
 * Check root.tst against root.bin. Without --tsa-ca the most this can say is "the token stamps
 * this root, and is signed by the key in the certificate it carries": anyone can make such a
 * token, so that is reported as couldn't check, not OK. A wrong imprint or a bad signature is
 * a mismatch either way.
 */
export const checkTsa = async ({ dir, rec, tsaCa, openssl = 'openssl', sdk }) => {
  const tst = readIf(join(dir, 'root.tst'));
  if (!tst) return verdict(UNCHECKED, 'no RFC 3161 token in the mirror (the registry had none to give)');
  const root = Buffer.from(rec.root, 'hex');
  let genTime;
  const notes = [];
  if (sdk) {
    let v;
    try { v = await sdk(new Uint8Array(tst), new Uint8Array(root)); } catch (e) { v = { ok: false, checks: [{ ok: false, what: e.message }] }; }
    const failed = (v.checks ?? []).filter((c) => !c.ok).map((c) => c.what);
    // A token that carries no signer certificate can only be checked with --tsa-ca (openssl
    // below); the SDK alone can't say whose it is, which is not a mismatch.
    const onlyNoCert = failed.length === 1 && /signer certificate is present/.test(failed[0]);
    if (!v.ok && !onlyNoCert) return verdict(MISMATCH, `the token does not verify against root.bin: ${failed.join('; ') || 'no reason given'}`);
    genTime = v.genTime;
    if (v.ok) notes.push('SDK: imprint and signature OK');
  }
  if (!hasOpenssl(openssl)) {
    if (!sdk) return verdict(UNCHECKED, 'neither openssl nor the SDK (npm install) is available');
    return verdict(UNCHECKED, `${notes.join('; ')}; whose signature it is not checked (no openssl)`);
  }
  const tmp = mkdtempSync(join(tmpdir(), 'veilcore-witness-'));
  try {
    const run = (args) => execFileSync(openssl, args, { cwd: tmp, stdio: ['ignore', 'pipe', 'pipe'] }).toString();
    if (!genTime) {
      try {
        const text = run(['ts', '-reply', '-in', join(dir, 'root.tst'), '-token_in', '-text']);
        genTime = /Time stamp: (.+)/.exec(text)?.[1]?.trim();
      } catch { return verdict(MISMATCH, 'root.tst is not an RFC 3161 token openssl can read'); }
    }
    let trust;
    if (tsaCa) {
      trust = ['-CAfile', tsaCa];
    } else {
      // The certificates the token carries, trusted as given: checks imprint and signature only.
      let own = '';
      try { own = run(['pkcs7', '-inform', 'DER', '-in', join(dir, 'root.tst'), '-print_certs']); } catch { /* none readable */ }
      if (!own.includes('BEGIN CERTIFICATE')) return verdict(UNCHECKED, 'the token carries no certificate, so its signature can only be checked with the TSA\'s certificate: give --tsa-ca');
      writeFileSync(join(tmp, 'own.pem'), own);
      trust = ['-CAfile', join(tmp, 'own.pem'), '-partial_chain'];
    }
    try {
      run(['ts', '-verify', '-data', join(dir, 'root.bin'), '-in', join(dir, 'root.tst'), '-token_in', ...trust]);
    } catch (e) {
      const why = String(e.stderr ?? '').split('\n').find((l) => /error|fail|mismatch/i.test(l)) ?? 'verification failed';
      return verdict(MISMATCH, `openssl ts -verify refused it${tsaCa ? ' with the TSA certificate given' : ''}: ${why.trim().slice(0, 200)}`);
    }
    if (genTime && Date.parse(genTime) < Date.parse(rec.sealedAt) - SKEW_MS) {
      return verdict(MISMATCH, `the token is dated ${genTime}, before the batch was sealed (${rec.sealedAt})`);
    }
    if (!tsaCa) return verdict(UNCHECKED, `the token stamps this root and its signature verifies (dated ${genTime}); whose signature it is was not checked: give --tsa-ca with the TSA's root certificate`);
    return verdict(OK, `dated ${genTime}, chain checked against the certificate given`);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
};

// ── OpenTimestamps / Bitcoin ────────────────────────────────────────────────────────────

/**
 * Parse root.bin.ots for this root and check every Bitcoin attestation's block. With several
 * explorers, each is asked and each must agree. Offline, the structure is checked and the
 * blocks are only named.
 */
export const checkOts = async ({ dir, rec, explorers, fetchImpl }) => {
  const ots = readIf(join(dir, 'root.bin.ots'));
  if (!ots) return verdict(UNCHECKED, 'no OpenTimestamps proof in the mirror');
  let ts;
  try { ts = parseOtsFile(ots, rootDigest(rec.root)); } catch (e) { return verdict(MISMATCH, `root.bin.ots does not prove this root: ${e.message}`); }
  const btc = attestationsOf(ts).filter((a) => a.kind === 'bitcoin');
  const claimed = rec.opentimestamps?.bitcoinBlockHeight;
  if (btc.length === 0) {
    if (Number.isSafeInteger(claimed)) return verdict(MISMATCH, `the registry says Bitcoin block ${claimed}, and the proof has no Bitcoin attestation`);
    return verdict(UNCHECKED, 'pending: the proof is not in a Bitcoin block yet (run `ots upgrade root.bin.ots` to ask the calendars yourself)');
  }
  const heights = [...new Set(btc.map((a) => a.height))].sort((a, b) => a - b);
  if (Number.isSafeInteger(claimed) && !heights.includes(claimed)) {
    return verdict(MISMATCH, `the registry says Bitcoin block ${claimed}; the proof names ${heights.join(', ')}`);
  }
  if (explorers.length === 0) return verdict(UNCHECKED, `proof parses and names Bitcoin block ${heights.join(', ')}; blocks not looked up (offline). Full check: \`ots verify\` with your own Bitcoin node`);
  // Every attestation with every explorer. One explorer down never hides another's mismatch:
  // a mismatch anywhere wins, and "couldn't check" only when nothing was wrong.
  const times = [];
  const mismatches = [];
  const unreached = [];
  for (const a of btc) {
    for (const explorer of explorers) {
      try {
        times.push(await checkBitcoinBlock(a.height, a.msg, { explorer, fetchImpl }));
      } catch (e) {
        if (e.mismatch) mismatches.push(`Bitcoin block ${a.height}'s header from ${new URL(explorer).host} does not hold the Merkle root this proof claims`);
        else unreached.push(`block ${a.height} from ${new URL(explorer).host} (${e.message})`);
      }
    }
  }
  if (mismatches.length) return verdict(MISMATCH, mismatches.join('; '));
  // Bitcoin block times can be up to two hours off; a block well before sealing cannot hold this root.
  const early = times.find((t) => Date.parse(t.time) < Date.parse(rec.sealedAt) - BTC_SKEW_MS);
  if (early) return verdict(MISMATCH, `Bitcoin block ${early.height} is dated ${early.time}, before the batch was sealed (${rec.sealedAt})`);
  if (unreached.length) return verdict(UNCHECKED, `proof parses; could not get ${unreached.join('; ')}`);
  const first = times.sort((x, y) => x.height - y.height)[0];
  return verdict(OK, `in Bitcoin block ${first.height} at ${first.time} (header from ${explorers.map((e) => new URL(e).host).join(' and ')}; full check: \`ots verify\` with your own node)`);
};

// ── Midnight ────────────────────────────────────────────────────────────────────────────

/** Same question the website's check page asks (bboard-ui/src/veilcore/chain/anchor-check.ts). */
const TX_FIELDS = `hash
    block { height timestamp }
    ... on RegularTransaction {
      identifiers
      transactionResult { status }
      contractActions { address state ... on ContractCall { entryPoint } }
    }`;
export const ANCHOR_QUERY = `query VEILCORE_ANCHOR_CHECK($byHash: TransactionOffset!, $byId: TransactionOffset!) {
  byHash: transactions(offset: $byHash) {
    ${TX_FIELDS}
  }
  byId: transactions(offset: $byId) {
    ${TX_FIELDS}
  }
}`;

const norm = (h) => (typeof h === 'string' ? h.trim().toLowerCase().replace(/^0x/, '') : '');
const isAnchorEntry = (raw) => typeof raw === 'string' && (raw === 'anchorBatch'
  || norm(raw) === Buffer.from('anchorBatch').toString('hex'));

/**
 * Whether the contract state recorded right after the call holds this batch root. The
 * website decodes the exact cell (lastBatchRoot) with the compiled contract; this registry
 * does not carry that contract, so the default looks for the root's 32 bytes, byte-aligned,
 * in the serialized state. That is weaker: it would also pass if some other cell held the
 * same 32 bytes. A witness with the veilcore repository can pass the exact decoder instead
 * (`rootOf`, see docs/run-a-witness.md).
 */
export const stateHoldsRoot = (stateHex, root) => {
  for (let i = stateHex.indexOf(root); i !== -1; i = stateHex.indexOf(root, i + 1)) if (i % 2 === 0) return true;
  return false;
};

/** An indexer's address for messages: the host only, never a key in its path or query. */
const hostOf = (u) => { try { return new URL(u).host; } catch { return 'the indexer'; } };

const askIndexer = async (indexer, { txId, contract, root, rootOf }, fetchImpl) => {
  let body;
  try {
    const res = await fetchImpl(indexer, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ query: ANCHOR_QUERY, variables: { byHash: { hash: txId }, byId: { identifier: txId } } }),
      signal: AbortSignal.timeout(30_000),
      redirect: 'error',
    });
    if (!res.ok) return { kind: 'unreachable', reason: `${hostOf(indexer)} answered ${res.status}` };
    body = await res.json();
  } catch {
    return { kind: 'unreachable', reason: `${hostOf(indexer)} did not answer` };
  }
  if (Array.isArray(body?.errors) && body.errors.length) return { kind: 'unreachable', reason: `${hostOf(indexer)} could not answer the question` };
  if (!body?.data || typeof body.data !== 'object') return { kind: 'unreachable', reason: `${hostOf(indexer)}'s answer could not be read` };
  const list = (v) => (Array.isArray(v) ? v.filter((t) => t && typeof t === 'object') : []);
  const found = new Map();
  let conflicting = false;
  const add = (t) => {
    const h = norm(t.hash);
    if (found.has(h) && JSON.stringify(found.get(h)) !== JSON.stringify(t)) conflicting = true;
    else found.set(h, t);
  };
  for (const t of list(body.data.byHash)) if (norm(t.hash) === txId) add(t);
  for (const t of list(body.data.byId)) if (Array.isArray(t.identifiers) && t.identifiers.map(norm).includes(txId) && HEX64.test(norm(t.hash))) add(t);
  if (conflicting) return { kind: 'refused', reason: 'the indexer gave two different answers for that transaction' };
  if (found.size === 0) return { kind: 'absent', reason: `${hostOf(indexer)} has no transaction ${txId.slice(0, 12)}…` };
  if (found.size > 1) return { kind: 'refused', reason: 'more than one transaction answers to that id' };
  const [[txHash, tx]] = [...found];
  if (tx.transactionResult?.status !== 'SUCCESS') return { kind: 'refused', reason: 'that transaction did not succeed' };
  const calls = (Array.isArray(tx.contractActions) ? tx.contractActions : []).filter((a) => a && norm(a.address) === contract);
  if (calls.length === 0) return { kind: 'refused', reason: "that transaction made no call on VeilCore's contract" };
  if (calls.length > 1) return { kind: 'refused', reason: "that transaction made more than one call on VeilCore's contract" };
  if (!isAnchorEntry(calls[0].entryPoint)) return { kind: 'refused', reason: 'that call is not a date stamp (anchorBatch)' };
  const state = norm(calls[0].state);
  if (!/^[0-9a-f]+$/.test(state) || state.length % 2) return { kind: 'refused', reason: 'the indexer gave no contract state for that call' };
  let holds;
  try { holds = rootOf ? norm(await rootOf(state)) === root : stateHoldsRoot(state, root); } catch { holds = false; }
  if (!holds) return { kind: 'refused', reason: 'the contract state after that call does not hold this batch root' };
  const height = tx.block?.height;
  const t = tx.block?.timestamp;
  const time = typeof t === 'number' && t > 0 ? (t < 1e12 ? t * 1000 : t) : undefined;
  if (!Number.isSafeInteger(height) || time === undefined) return { kind: 'refused', reason: 'the indexer gave no block height or time' };
  return { kind: 'ok', txHash, height, time };
};

export const checkMidnight = async ({ rec, indexers, contract = MAINNET_CONTRACT, fetchImpl, rootOf }) => {
  const a = rec.anchor;
  if (!a) return verdict(UNCHECKED, 'not anchored yet');
  if (a.network !== 'mainnet') return verdict(UNCHECKED, `anchored only on ${a.network ?? 'an unnamed network'}, a test network; its date carries no evidential weight`);
  if (norm(a.contractAddress) !== contract) return verdict(MISMATCH, `the anchor names contract ${a.contractAddress}, not VeilCore's mainnet contract`);
  const txId = norm(a.txHash);
  if (!HEX64.test(txId)) return verdict(MISMATCH, 'the anchor has no transaction hash');
  if (indexers.length === 0) return verdict(UNCHECKED, 'no Midnight indexer given (--indexer, or BLOCKFROST_PROJECT_ID)');
  const answers = [];
  for (const i of indexers) answers.push(await askIndexer(i, { txId, contract, root: rec.root, rootOf }, fetchImpl));
  const refused = answers.find((x) => x.kind === 'refused');
  if (refused) return verdict(MISMATCH, refused.reason);
  // One indexer without the transaction may only be behind, or on another network. Two or
  // more, every one of them without it, is a second source confirming it isn't there.
  const absent = answers.filter((x) => x.kind === 'absent');
  if (absent.length && absent.length === answers.length && answers.length >= 2) {
    return verdict(MISMATCH, `none of the ${answers.length} indexers has transaction ${txId.slice(0, 12)}…`);
  }
  if (absent.length) return verdict(UNCHECKED, `${absent[0].reason}: it may be behind, or on another network; a second indexer that also lacks it would make this a mismatch`);
  const down = answers.find((x) => x.kind === 'unreachable');
  if (down) return verdict(UNCHECKED, down.reason);
  const [first, ...rest] = answers;
  if (rest.some((x) => x.height !== first.height || x.time !== first.time || x.txHash !== first.txHash)) return verdict(MISMATCH, 'the indexers disagree about that transaction');
  if (Number.isSafeInteger(a.blockHeight) && a.blockHeight !== first.height) {
    return verdict(MISMATCH, `the registry recorded block ${a.blockHeight}; Midnight says block ${first.height}`);
  }
  const at = new Date(first.time).toISOString();
  if (first.time < Date.parse(rec.sealedAt) - SKEW_MS) return verdict(MISMATCH, `block ${first.height} is dated ${at}, before the batch was sealed (${rec.sealedAt})`);
  const how = rootOf ? 'the contract cell holds this root' : 'root bytes found in contract state (cell not decoded)';
  // The block is the date. The registry's anchoredAt is the operator's word (a batch anchored
  // by hand may carry the time it was recorded), so a difference is noted, not a mismatch.
  const off = a.anchoredAt && Math.abs(Date.parse(a.anchoredAt) - first.time) > SKEW_MS
    ? `; note: the registry shows ${a.anchoredAt}, the block's time is the date` : '';
  return verdict(OK, `written by transaction ${txId.slice(0, 12)}… in block ${first.height} at ${at}; ${how} (${answers.length} indexer${answers.length > 1 ? 's' : ''})${off}`);
};

// ── the whole mirror ────────────────────────────────────────────────────────────────────

export const checkFiles = ({ dir, entry, rec }) => {
  for (const f of FILES) {
    const b = readIf(join(dir, f));
    const want = entry.files?.[f];
    if (!b && want) return verdict(MISMATCH, `${f} is listed in index.json and missing`);
    if (b && !want) return verdict(MISMATCH, `${f} is there and not listed in index.json`);
    if (b && sha256(b) !== want) return verdict(MISMATCH, `${f} does not match its SHA-256 in index.json`);
  }
  if (rec.batchId !== entry.batchId || rec.root !== entry.root) return verdict(MISMATCH, 'batch.json and index.json disagree');
  const bin = readIf(join(dir, 'root.bin'));
  if (!bin || bin.toString('hex') !== rec.root) return verdict(MISMATCH, 'root.bin is not the batch root');
  if (entry.conflicts?.length) return verdict(MISMATCH, `the registry once served a different version of this batch (${entry.conflicts.join(', ')})`);
  return verdict(OK, 'files match index.json');
};

/** Check every batch. `opts`: indexers, explorers, tsaCa, contract, fetchImpl, openssl, rootOf. */
export const check = async (root, opts = {}) => {
  const { indexers = [], explorers = [DEFAULT_EXPLORER], tsaCa = null, contract = MAINNET_CONTRACT, fetchImpl = fetch, openssl = 'openssl', rootOf } = opts;
  const index = readJson(join(root, 'index.json'));
  const sdk = opts.sdk === undefined ? await loadSdk() : opts.sdk;
  const results = [];
  for (const entry of index.batches) {
    const dir = batchDir(root, entry.batchId);
    let rec;
    try { rec = readJson(join(dir, 'batch.json')); } catch { results.push({ batchId: entry.batchId, overall: MISMATCH, parts: { files: verdict(MISMATCH, 'batch.json is missing or unreadable') } }); continue; }
    const parts = {
      files: checkFiles({ dir, entry, rec }),
      rfc3161: await checkTsa({ dir, rec, tsaCa, openssl, sdk }),
      bitcoin: await checkOts({ dir, rec, explorers, fetchImpl }),
      midnight: await checkMidnight({ rec, indexers, contract, fetchImpl, rootOf }),
    };
    const all = Object.values(parts).map((p) => p.status);
    const overall = all.includes(MISMATCH) ? MISMATCH : all.every((s) => s === OK) ? OK : UNCHECKED;
    results.push({ batchId: entry.batchId, sealedAt: rec.sealedAt, overall, parts });
  }
  // A conflicts/ folder for a batch the index doesn't list: the registry served a new batch
  // that contradicted itself on first sight, so it was never added. That is a mismatch too.
  const named = new Set(index.batches.map((b) => b.batchId));
  const conflicts = existsSync(join(root, 'conflicts')) ? readdirSync(join(root, 'conflicts')).sort() : [];
  for (const id of conflicts.filter((c) => !named.has(c))) {
    const kept = readdirSync(join(root, 'conflicts', id)).sort().map((d) => `conflicts/${id}/${d}`);
    const why = verdict(MISMATCH, `never added: the registry served it in a form that contradicts itself (${kept.join(', ')})`);
    const none = verdict(UNCHECKED, 'not in the mirror');
    results.push({ batchId: id, overall: MISMATCH, parts: { files: why, rfc3161: none, bitcoin: none, midnight: none } });
  }
  // Folders the index doesn't name: the mirror was edited by hand.
  const stray = existsSync(join(root, 'batches')) ? readdirSync(join(root, 'batches')).filter((d) => !named.has(d)) : [];
  return { registry: index.registry, results, stray, conflicts };
};
