#!/usr/bin/env node
// Check one item against an evidence re-stamp, offline (lineage/restamp.mjs; the site's
// docs/restamp.md). No network: everything comes from files you have.
//
//   node scripts/restamp-check.mjs --kind <kind> --item <file> --proof <proof.json> [--manifest <manifest.json>] [--root-bin <root.bin>]
//
//   kind        batch-root | attestation | withdrawal | enrolment | rfc3161
//   --item      batch-root: root.bin (32 bytes); rfc3161: the token (.tst, DER);
//               attestation, withdrawal, enrolment: the JSON as the registry served it
//   --proof     the inclusion proof (GET /restamps/:id/proof/:entry, or rebuilt from the manifest)
//   --manifest  optional: the re-stamp's manifest.json; its entries are folded again and the
//               proof must lead to its root
//   --root-bin  optional, and needed before trusting the date: the re-stamp's root.bin, the file
//               root.bin.ots stamps; it must be the root the proof leads to. Without it, a genuine
//               .ots for another root would pass `ots verify` beside a proof for this one
//
// Exit 0 when the item is in the re-stamp (and, with --root-bin, root.bin is its root). The
// root's date is then its root.bin.ots: `ots verify -f root.bin root.bin.ots`, or the evidence
// bundle's verify.html.
//
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { KINDS, itemBytes, checkRestampItem, checkManifest } from '../lineage/restamp.mjs';

const { values: a } = parseArgs({ options: { kind: { type: 'string' }, item: { type: 'string' }, proof: { type: 'string' }, manifest: { type: 'string' }, 'root-bin': { type: 'string' } } });
const fail = (why) => { console.error(`NOT CHECKED: ${why}`); process.exit(1); };
if (!KINDS.includes(a.kind) || !a.item || !a.proof) fail(`usage: --kind <${KINDS.join('|')}> --item <file> --proof <proof.json> [--manifest <manifest.json>] [--root-bin <root.bin>]`);

const raw = readFileSync(a.item);
const item = a.kind === 'batch-root' || a.kind === 'rfc3161' ? raw : JSON.parse(raw.toString('utf8'));
const proof = JSON.parse(readFileSync(a.proof, 'utf8'));
let root;
if (a.manifest) {
  const m = await checkManifest(JSON.parse(readFileSync(a.manifest, 'utf8')));
  if (!m.ok) fail(`the manifest: ${m.reason}`);
  root = m.root;
  console.log(`manifest: its entries fold to ${root}`);
}
const out = await checkRestampItem({ kind: a.kind, bytes: itemBytes(a.kind, item), proof, root });
if (!out.ok) fail(`${out.reason} (this item's entry is ${out.entry ?? 'unknown'})`);
if (a['root-bin'] !== undefined) {
  const bin = readFileSync(a['root-bin']);
  if (bin.length !== 32 || bin.toString('hex') !== out.root) fail(`root.bin is not the root the proof leads to (${out.root})`);
}
console.log(`IN THE RE-STAMP: ${a.kind} entry ${out.entry}`);
console.log(`root ${out.root} (re-stamp ${proof.batchId}, made ${proof.sealedAt})`);
if (a['root-bin'] !== undefined) {
  console.log('root.bin is this root. Its date: `ots verify -f root.bin root.bin.ots`.');
} else {
  console.log('root.bin not checked: add --root-bin root.bin before trusting a date, then `ots verify -f root.bin root.bin.ots`.');
}
