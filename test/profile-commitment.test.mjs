// Records the app seals under a profile commit `profile` and `taxon` when present.
// The registry must recompute the same fingerprint, or it refuses every such record.
import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalise, sha256Hex } from 'veilcore-records';
import { checkRecord } from '../lineage/conformance.mjs';

const base = {
  strainName: 'Test Cultivar', bredBy: 'Tester', dateCreated: '2026-10-01', notes: 'n',
  loggedAt: 1759600000000, nonce: 'ab'.repeat(16), parents: [], photoFingerprints: [],
  breedingMethod: '', refId: '',
};
// Exactly what bboard-ui/src/veilcore/commitment.ts computes.
const appFingerprint = (r) => sha256Hex(canonicalise({
  breedingMethod: r.breedingMethod ?? '', bredBy: r.bredBy, dateCreated: r.dateCreated,
  loggedAt: r.loggedAt, nonce: r.nonce, notes: r.notes, parents: r.parents ?? [],
  photoFingerprints: r.photoFingerprints ?? [], refId: r.refId ?? '', strainName: r.strainName,
  ...(r.profile ? { profile: r.profile } : {}), ...(r.taxon ? { taxon: r.taxon } : {}),
}));

test('a record sealed under a profile and taxon is accepted', async () => {
  const r = { ...base, profile: 'veilcore/profile/plant-variety/v1', taxon: 'Malus domestica Borkh.' };
  r.recordFingerprint = await appFingerprint(r);
  assert.deepEqual(await checkRecord(r), { ok: true, verified: true });
});

test('a record sealed before profiles existed still recomputes', async () => {
  const r = { ...base };
  r.recordFingerprint = await appFingerprint(r);
  assert.deepEqual(await checkRecord(r), { ok: true, verified: true });
});

test('changing the profile after sealing is refused', async () => {
  const r = { ...base, profile: 'veilcore/profile/plant-variety/v1' };
  r.recordFingerprint = await appFingerprint(r);
  r.profile = 'veilcore/profile/cannabis/v0.1';
  assert.equal((await checkRecord(r)).ok, false);
});

test('adding a profile to a record sealed without one is refused', async () => {
  const r = { ...base };
  r.recordFingerprint = await appFingerprint(r);
  r.profile = 'veilcore/profile/plant-variety/v1';
  assert.equal((await checkRecord(r)).ok, false);
});
