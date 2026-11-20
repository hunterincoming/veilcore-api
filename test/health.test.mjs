// /health is a readiness check (deep dive, 8 Oct 2026). It answered { ok: true } even when
// the lineage, transfer, batch or attester modules had failed to load, so a deploy with
// every route but /api/records answering 503 looked healthy to Railway. No network.
//
// SPDX-License-Identifier: Apache-2.0

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const child = fileURLToPath(new URL('./fixtures/health-child.mjs', import.meta.url));
const run = (failModule, extra = {}) => {
  const env = { ...process.env, FAIL_MODULE: failModule ?? '', ...extra };
  const out = execFileSync(process.execPath, [child], { env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
  return JSON.parse(out.trim().split('\n').pop());
};

test('LOW: /health is 200 only once every module has loaded', () => {
  const r = run();
  assert.equal(r.status, 200);
  assert.deepEqual(r.body, { ok: true, features: ['sealed-records-v1', 'lab-results-v1', 'animal-profile-v1', 'strain-profile-v1', 'document-profile-v1', 'claimant-offer-v1', 'sealed-custody-v1', 'record-rev-v1', 'one-correction-v1', 'license-rev-v1', 'sealed-name-v1', 'dna-pair-binding-v1', 'bred-by-grant-v1', 'name-code-v1', 'lab-doc-binding-v1', 'dating-first-v1', 'private-lab-signatures-v1', 'shared-by-proof-code-v1', 'license-notices-v1', 'license-notices-v2', 'license-notices-v3', 'record-tombstones-v1', 'license-invites-v1', 'deals-v1', 'payment-receipts-v1', 'passkey-vault-v1', 'account-copy-v1', 'account-slot-check-v1', 'lab-domain-withdrawn-v1', 'record-timestamp-v1'] });
});

test('/health names what this build serves, for the site\'s deploy preflights; lab results only once they load', () => {
  // Held back: every part /health requires is ready, lab results are not, so their routes
  // still answer 503 and the feature is not listed (CONTRACT.md #13).
  const r = run(undefined, { DELAY_MODULE: 'lab-results.mjs' });
  assert.deepEqual(r.during.body.features, ['sealed-records-v1', 'animal-profile-v1', 'strain-profile-v1', 'document-profile-v1', 'claimant-offer-v1', 'sealed-custody-v1', 'record-rev-v1', 'one-correction-v1', 'license-rev-v1', 'sealed-name-v1', 'dna-pair-binding-v1', 'bred-by-grant-v1', 'name-code-v1', 'lab-doc-binding-v1', 'dating-first-v1', 'private-lab-signatures-v1', 'shared-by-proof-code-v1', 'license-notices-v1', 'license-notices-v2', 'license-notices-v3', 'record-tombstones-v1', 'license-invites-v1', 'deals-v1', 'payment-receipts-v1', 'passkey-vault-v1', 'account-copy-v1', 'account-slot-check-v1', 'lab-domain-withdrawn-v1', 'record-timestamp-v1']);
  assert.deepEqual(r.body.features, ['sealed-records-v1', 'lab-results-v1', 'animal-profile-v1', 'strain-profile-v1', 'document-profile-v1', 'claimant-offer-v1', 'sealed-custody-v1', 'record-rev-v1', 'one-correction-v1', 'license-rev-v1', 'sealed-name-v1', 'dna-pair-binding-v1', 'bred-by-grant-v1', 'name-code-v1', 'lab-doc-binding-v1', 'dating-first-v1', 'private-lab-signatures-v1', 'shared-by-proof-code-v1', 'license-notices-v1', 'license-notices-v2', 'license-notices-v3', 'record-tombstones-v1', 'license-invites-v1', 'deals-v1', 'payment-receipts-v1', 'passkey-vault-v1', 'account-copy-v1', 'account-slot-check-v1', 'lab-domain-withdrawn-v1', 'record-timestamp-v1']);
  // A build whose lab results fail to load does not say it serves them.
  const failed = run('lab-results.mjs');
  assert.ok(!failed.body.features.includes('lab-results-v1'), JSON.stringify(failed.body));
});

for (const mod of ['routes.mjs', 'transfer.mjs', 'batches.mjs', 'attesters.mjs', 'embed.mjs']) {
  test(`LOW: /health is 503 when ${mod} failed to load`, () => {
    const r = run(mod);
    assert.equal(r.status, 503, JSON.stringify(r.body));
    assert.equal(r.body.ok, false);
    assert.ok(r.body.notReady.length > 0, JSON.stringify(r.body));
    assert.equal(r.body.status, 'failed', 'every load has finished, so it is not still starting');
    assert.doesNotMatch(JSON.stringify(r.body), /simulated|\/lineage\/|at /, 'no error text or file paths');
  });
}

test('LOW (round 2): /health says starting, not failed, while the commitment checker is still loading', () => {
  // conformance.mjs is held back until everything else has finished loading (health-child.mjs).
  const r = run(undefined, { DELAY_MODULE: 'conformance.mjs' });
  const { during } = r;
  assert.equal(during.status, 503);
  assert.deepEqual(during.body.notReady, ['conformance'], 'only the checker is missing');
  assert.equal(during.body.status, 'starting');
  assert.equal(r.status, 200, 'and ready once it has loaded');
});

test('LOW: /health is not ok until prove requests and lab results have loaded too', () => {
  // They load after the attester registry, in the same chain: /health said ok while their
  // routes still answered 503 (flaky-test hunt, 15 Oct 2026).
  for (const mod of ['prove-requests.mjs', 'lab-results.mjs']) {
    const r = run(undefined, { DELAY_MODULE: mod });
    assert.equal(r.during.status, 503, `${mod} still loading: ${JSON.stringify(r.during.body)}`);
    assert.equal(r.during.body.status, 'starting');
    assert.equal(r.status, 200, 'and ready once it has loaded');
  }
});
