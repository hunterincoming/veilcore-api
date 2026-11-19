#!/usr/bin/env node
// A public witness of VeilCore's dated batches. Two commands:
//
//   node scripts/mirror/witness.mjs mirror <folder> [--registry URL] [--full]
//       Copy every batch from the registry into <folder>, append-only. Exit 2, with the
//       other version kept in <folder>/conflicts/, if the registry now serves a history
//       that does not extend the copy (a root, anchor, token or proof changed or gone).
//       Exit 1 if the run could not finish (registry unreachable; an answer it can't use,
//       such as a batch listed twice differently or a page cursor that goes nowhere): the
//       folder is then left exactly as it was.
//
//   node scripts/mirror/witness.mjs check <folder> [--indexer URL]... [--tsa-ca FILE]
//       [--bitcoin-explorer URL]... [--offline] [--json FILE]
//       Check every batch in <folder> with no VeilCore server. Exit 2 if any is a mismatch.
//
// Node only: no `npm install` needed (the SDK's token check is used too if it is installed).
// docs/run-a-witness.md says what each check does and does not show.
// SPDX-License-Identifier: Apache-2.0

import { realpathSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mirror } from './mirror.mjs';
import { check, OK, MISMATCH } from './check.mjs';
import { DEFAULT_EXPLORER } from '../../lineage/ots.mjs';
import { printable } from './common.mjs';

// Everything printed goes through printable(): registry text never reaches a terminal or a
// GitHub run log with a control character in it (no `::` workflow command, no fence).
const out = (line) => console.log(printable(line, 2000));
const err = (line) => console.error(printable(line, 2000));

export const DEFAULT_REGISTRY = 'https://veilcore-api-production.up.railway.app';

const usage = `usage:
  witness.mjs mirror <folder> [--registry URL] [--full]
  witness.mjs check  <folder> [--indexer URL]... [--tsa-ca FILE] [--bitcoin-explorer URL]... [--offline] [--json FILE]
Environment: BLOCKFROST_PROJECT_ID (Midnight mainnet indexer), MIDNIGHT_INDEXER_URL (comma-separated)`;

const parse = (argv) => {
  const [cmd, folder, ...rest] = argv;
  const o = { cmd, folder, indexers: [], explorers: [], full: false, offline: false };
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    const val = () => { const v = rest[++i]; if (v === undefined) throw new Error(`${a} needs a value`); return v; };
    if (a === '--registry') o.registry = val();
    else if (a === '--full') o.full = true;
    else if (a === '--indexer') o.indexers.push(val());
    else if (a === '--tsa-ca') o.tsaCa = resolve(val());
    else if (a === '--bitcoin-explorer') o.explorers.push(val());
    else if (a === '--offline') o.offline = true;
    else if (a === '--json') o.json = val();
    else throw new Error(`unknown option ${a}`);
  }
  if (!['mirror', 'check'].includes(cmd) || !folder) throw new Error('a command and a folder are needed');
  return o;
};

/** Indexers from the flags and the environment. A Blockfrost id is a key: it is never printed. */
export const indexersFrom = (flags, env = process.env) => {
  const out = [...flags];
  for (const u of (env.MIDNIGHT_INDEXER_URL ?? '').split(',').map((s) => s.trim()).filter(Boolean)) out.push(u);
  const id = (env.BLOCKFROST_PROJECT_ID ?? '').trim();
  if (id) out.push(`https://midnight-mainnet.blockfrost.io/api/v0?project_id=${encodeURIComponent(id)}`);
  return out;
};

const LABEL = { [OK]: 'OK', [MISMATCH]: 'MISMATCH' };
const label = (s) => LABEL[s] ?? "COULDN'T CHECK";

const main = async () => {
  let o;
  try { o = parse(process.argv.slice(2)); } catch (e) { err(e.message); console.error(usage); return 1; }
  const folder = resolve(o.folder);

  if (o.cmd === 'mirror') {
    const s = await mirror({ api: o.registry ?? DEFAULT_REGISTRY, out: folder, full: o.full, log: err });
    out(`${s.batches} batches listed by ${s.registry}: ${s.added.length} new, ${s.updated.length} updated, ${s.unchanged} unchanged.`);
    for (const u of s.updated) out(`  updated ${u.batchId}: ${u.what.join('; ')}`);
    for (const n of s.notes) out(`  note: ${n}`);
    if (s.conflicts.length) {
      err('');
      err(`!!! THE REGISTRY CHANGED HISTORY: ${s.conflicts.length} batch(es) no longer match the mirror. !!!`);
      for (const c of s.conflicts) err(`  ${c.batchId}: ${c.reasons.join('; ')} -> ${c.keptIn}`);
      err('The mirror keeps its copy unchanged; what the registry served now is kept beside it. Nothing was overwritten.');
      return 2;
    }
    return 0;
  }

  const report = await check(folder, {
    indexers: indexersFrom(o.indexers),
    explorers: o.offline ? [] : o.explorers.length ? o.explorers : [DEFAULT_EXPLORER],
    tsaCa: o.tsaCa ?? null,
  });
  const count = { [OK]: 0, [MISMATCH]: 0, other: 0 };
  for (const r of report.results) {
    count[r.overall in count ? r.overall : 'other']++;
    out(`${r.batchId}  ${label(r.overall)}`);
    for (const [part, v] of Object.entries(r.parts)) out(`    ${part.padEnd(9)} ${label(v.status)}: ${v.detail}`);
  }
  for (const d of report.stray) out(`note: batches/${d} is not in index.json`);
  out('');
  out(`${report.results.length} batches: ${count[OK]} OK, ${count[MISMATCH]} mismatch, ${count.other} not fully checked; ${report.stray.length} stray folder(s).`);
  if (o.json) writeFileSync(o.json, `${JSON.stringify(report, null, 2)}\n`);
  return count[MISMATCH] ? 2 : 0;
};

// Run only as a command, not when a test imports this file. Real paths on both sides: Node
// resolves symlinks for the module it runs, so comparing with argv[1] as typed would do
// nothing, silently, when the script is reached through a link.
const isMain = () => { try { return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url)); } catch { return false; } };
if (isMain()) main().then((code) => { process.exitCode = code; }, (e) => { err(`error: ${e.message}`); process.exitCode = 1; });
