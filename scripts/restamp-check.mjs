#!/usr/bin/env node
// Check one item against an evidence re-stamp, offline (lineage/restamp.mjs; the site's
// docs/restamp.md). No network: everything comes from files you have.
//
//   node scripts/restamp-check.mjs --kind <kind> --item <file> --proof <proof.json> [--manifest <manifest.json>]
//
//   kind        batch-root | attestation | withdrawal | enrolment | rfc3161
//   --item      batch-root: root.bin (32 bytes); rfc3161: the token (.tst, DER);
//               attestation, withdrawal, enrolment: the JSON as the registry served it
//   --proof     the inclusion proof (GET /restamps/:id/proof/:entry, or rebuilt from the manifest)
//   --manifest  optional: the re-stamp's manifest.json; its entries are folded again and the
//               proof must lead to its root
//
// Exit 0 when the item is in the re-stamp. The root's date is then its root.bin.ots:
// `ots verify -f root.bin root.bin.ots`, or the evidence bundle's verify.html.
//
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { KINDS, itemBytes, checkRestampItem, checkManifest } from '../lineage/restamp.mjs';

const { values: a } = parseArgs({ options: { kind: { type: 'string' }, item: { type: 'string' }, proof: { type: 'string' }, manifest: { type: 'string' } } });
const fail = (why) => { console.error(`NOT CHECKED: ${why}`); process.exit(1); };
if (!KINDS.includes(a.kind) || !a.item || !a.proof) fail(`usage: --kind <${KINDS.join('|')}> --item <file> --proof <proof.json> [--manifest <manifest.json>]`);

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
console.log(`IN THE RE-STAMP: ${a.kind} entry ${out.entry}`);
console.log(`root ${out.root} (re-stamp ${proof.batchId}, made ${proof.sealedAt})`);
console.log('Its date: check root.bin.ots for this root, e.g. `ots verify -f root.bin root.bin.ots`.');
