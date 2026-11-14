// Strain and line records (veilcore/profile/strain/v1; the site's docs/strain-profile.md,
// SPEC 11.9): the registry recomputes them the way the site does, against the published
// vectors (test/fixtures/strain-v1.json, made without either checker's code).
// SPDX-License-Identifier: Apache-2.0

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { STRAIN_PROFILE, strainFieldsOf, validateStrainFields } from '../lineage/strain-profile.mjs';
import { recomputeCommitment } from '../lineage/conformance.mjs';

const V = JSON.parse(readFileSync(new URL('./fixtures/strain-v1.json', import.meta.url), 'utf8'));

test('the profile name', () => assert.equal(STRAIN_PROFILE, 'veilcore/profile/strain/v1'));

for (const r of V.records) {
  test(`recomputes as the vectors say: ${r.name}`, async () => {
    assert.deepEqual(validateStrainFields(r.fields), []);
    assert.deepEqual(strainFieldsOf(r.appRecord), r.fields);
    assert.equal(await recomputeCommitment(r.appRecord), r.fingerprint);
  });
}

for (const r of V.refusals) {
  test(`refuses ${r.name}`, () => {
    assert.ok(validateStrainFields(r.fields).length > 0);
  });
}

test('a malformed strain record is refused when recomputing, never tidied', async () => {
  const bad = { ...V.records[0].appRecord, strain: { group: 'plant', deposits: [], generation: '' } };
  await assert.rejects(() => recomputeCommitment(bad), /not a valid strain record/);
});
