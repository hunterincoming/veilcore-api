// The compiled contract this registry vendors must be the one SOURCE.json describes.
// Round D supply-chain review: nothing recorded which source and compiler produced it, so
// a silent replacement (or drift from the deployed contract) would go unnoticed. This
// fails on any change to the vendored files, so changing them means updating SOURCE.json
// in the same commit.
//
// SPDX-License-Identifier: Apache-2.0

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const dir = new URL('../lineage/managed/', import.meta.url);
const source = JSON.parse(readFileSync(new URL('SOURCE.json', dir), 'utf8'));

test('vendored contract files match the hashes recorded in lineage/managed/SOURCE.json', () => {
  for (const [file, sha] of Object.entries(source.files)) {
    const got = createHash('sha256').update(readFileSync(new URL(file, dir))).digest('hex');
    assert.equal(got, sha, `${file} changed; record its source commit and compiler in SOURCE.json`);
  }
});

test('SOURCE.json names a full commit and the runtime the compiled file checks for', () => {
  assert.match(source.commit, /^[0-9a-f]{40}$/);
  const js = readFileSync(new URL('contract/index.js', dir), 'utf8');
  assert.ok(js.includes(`checkRuntimeVersion('${source.compactRuntime}')`), 'runtime version in SOURCE.json matches the compiled file');
});

test('known answers: the pure circuits the registry uses give the values they gave when recorded', async () => {
  const { pureCircuits: C } = await import('../lineage/managed/contract/index.js');
  const hex = (u) => Buffer.from(u).toString('hex');
  const b = (n) => new Uint8Array(32).fill(n);
  assert.equal(hex(C.commit(b(7))), KNOWN.commit7);
  assert.equal(hex(C.descentEdge(b(1), b(2))), KNOWN.edge12);
});

// Computed from this build on 4 Oct 2026. When the contract is replaced from the deployed
// commit, the deployed contract's pureCircuits must give the new values here.
const KNOWN = {
  commit7: '1230fbfba4ba94de8bb3c74b99b8fa488f76cb4a82cb9e88001b21b871dedf3b',
  edge12: 'd70f3d73238b99c81b49c058eeb72c77326665f993afe547a8022fba7ce07b6c',
};
