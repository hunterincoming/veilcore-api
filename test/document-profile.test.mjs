// Document records (veilcore/profile/document/v1; the site's docs/document-profile.md,
// SPEC 11.11): the registry recomputes them the way the site does, against the published
// vectors (test/fixtures/document-v1.json, made without either checker's code).
// SPDX-License-Identifier: Apache-2.0

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DOCUMENT_PROFILE, documentFieldsOf, validateDocumentFields } from '../lineage/document-profile.mjs';
import { recomputeCommitment } from '../lineage/conformance.mjs';

const V = JSON.parse(readFileSync(new URL('./fixtures/document-v1.json', import.meta.url), 'utf8'));

test('the profile name', () => assert.equal(DOCUMENT_PROFILE, 'veilcore/profile/document/v1'));

for (const r of V.records) {
  test(`recomputes as the vectors say: ${r.name}`, async () => {
    assert.deepEqual(validateDocumentFields(r.fields), []);
    assert.deepEqual(documentFieldsOf(r.appRecord), r.fields);
    assert.equal(await recomputeCommitment(r.appRecord), r.fingerprint);
  });
}

for (const r of V.refusals) {
  test(`refuses ${r.name}`, () => {
    assert.ok(validateDocumentFields(r.fields).length > 0);
  });
}

test('a malformed document record is refused when recomputing, never tidied', async () => {
  const bad = { ...V.records[0].appRecord, document: { ...V.records[0].appRecord.document, files: [] } };
  await assert.rejects(() => recomputeCommitment(bad), /not a valid document record/);
});
