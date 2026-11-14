// Server-side commitment verification.
//
// The registry should not store a record whose commitment does not match its contents.
// Accepting one means a buyer discovers the problem instead of us, and a registry that
// serves unverifiable records is worse than no registry.
//
// Uses the published SDK rather than a second implementation, so what the server checks
// is exactly what an outside verifier computes.
// SPDX-License-Identifier: Apache-2.0

import { canonicalise, sha256Hex } from 'veilcore-records';
import { fieldRecordCommitment, isHex64, keyBoundFingerprint } from './key-binding.mjs';
import { animalFieldsOf, isAnimal, validateAnimalFields } from './animal-profile.mjs';
import { isStrain, strainFieldsOf, validateStrainFields } from './strain-profile.mjs';
import { documentFieldsOf, isDocument, validateDocumentFields } from './document-profile.mjs';

/**
 * Recompute a record's commitment from its committed fields.
 *
 * Mirrors what the app computes. If they ever diverge, records created in the product
 * would fail verification by anyone using the package — which is why this uses the
 * package rather than reimplementing it.
 */
export const recomputeCommitment = async (record) => {
  // An animal record seals its profile's own fields (animal-profile.mjs), checked first.
  // Every other record seals the fields below, exactly as before.
  // A strain or line record (strain-profile.mjs) and a document record (document-profile.mjs)
  // the same way.
  const committed = isAnimal(record) ? checkedAnimal(record) : isStrain(record) ? checkedStrain(record) : isDocument(record) ? checkedDocument(record) : {
    breedingMethod: record.breedingMethod ?? '',
    bredBy: record.bredBy,
    dateCreated: record.dateCreated,
    loggedAt: record.loggedAt,
    nonce: record.nonce,
    notes: record.notes,
    parents: record.parents ?? [],
    photoFingerprints: record.photoFingerprints ?? [],
    refId: record.refId ?? '',
    strainName: record.strainName,
    // The app commits these two only when present (bboard-ui commitment.ts, since
    // 3 Oct 2026), so records sealed before they existed still recompute. Leaving them
    // out here refused every record the app sealed under a profile.
    ...(record.profile ? { profile: record.profile } : {}),
    ...(record.taxon ? { taxon: record.taxon } : {}),
    // A record that names its own key (key-binding.mjs, since 14 Oct 2026): sealed in the
    // fields and folded in at the top. Absent on older records, which recompute as before.
    ...(record.keyBinding !== undefined ? { keyBinding: record.keyBinding } : {}),
  };
  const digest = await sha256Hex(canonicalise(committed));
  // A document's field set (SPEC 4.5): the commitment folds its root in, as the site and SDK do.
  const content = committed.fieldSetRoot !== undefined ? fieldRecordCommitment(committed.fieldSetRoot, digest) : digest;
  return record.keyBinding !== undefined ? keyBoundFingerprint(record.keyBinding, content) : content;
};

const checkedAnimal = (record) => {
  const fields = animalFieldsOf(record);
  const problems = validateAnimalFields(fields);
  if (problems.length) throw new AnimalRefusal(problems);
  return fields;
};

const checkedStrain = (record) => {
  const fields = strainFieldsOf(record);
  const problems = validateStrainFields(fields);
  if (problems.length) throw new AnimalRefusal(problems, 'strain');
  return fields;
};

const checkedDocument = (record) => {
  const fields = documentFieldsOf(record);
  const problems = validateDocumentFields(fields);
  if (problems.length) throw new AnimalRefusal(problems, 'document');
  return fields;
};

class AnimalRefusal extends Error {
  constructor(problems, kind = 'animal') {
    super(`not a valid ${kind} record (${problems.slice(0, 5).join('; ')})`);
    this.problems = problems;
  }
}

/**
 * Check a record before storing it.
 *
 * Records without a nonce predate the canonical format and cannot be checked — they are
 * accepted and flagged rather than rejected, because refusing them would orphan records
 * a holder already relies on.
 */
export const checkRecord = async (record) => {
  // A record carrying a commitment must be checkable against it. The nonce is part
  // of the committed field set, so a record with a fingerprint and no nonce is not
  // an old record — it is one nobody can verify, and accepting it was a way to skip
  // verification by omitting a field.
  if (!record.nonce && record.recordFingerprint) {
    return {
      ok: false,
      verified: false,
      reason: 'record carries a commitment but no nonce, so the commitment cannot be recomputed',
    };
  }
  // Genuinely pre-canonical: no nonce and no commitment either. Accepted and flagged
  // rather than refused, because refusing would orphan records a holder already
  // relies on. They are stored as unverifiable and reported that way.
  if (!record.nonce) {
    return { ok: true, verified: false, reason: 'pre-canonical record, commitment not checkable' };
  }
  if (!record.recordFingerprint) {
    return { ok: false, verified: false, reason: 'record has no commitment' };
  }
  // Present means sealed: a keyBinding that isn't 64 lowercase hex can't be part of a
  // fingerprint, and null is not "absent" (SPEC 4.2).
  if (record.keyBinding !== undefined && !isHex64(record.keyBinding)) {
    return { ok: false, verified: false, reason: 'keyBinding must be 64 lowercase hex characters' };
  }
  let computed;
  try {
    computed = await recomputeCommitment(record);
  } catch (e) {
    if (e instanceof AnimalRefusal) return { ok: false, verified: false, reason: e.message };
    throw e;
  }
  return computed === record.recordFingerprint
    ? { ok: true, verified: true }
    : { ok: false, verified: false, reason: 'commitment does not match contents', computed, claimed: record.recordFingerprint };
};
