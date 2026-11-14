// An animal record: one animal, logged by its breeder or a registry (the site's
// docs/animal-profile.md, SPEC 11.8; v1 is final).
//
// The fingerprint rules don't change. For records sealed under
// veilcore/profile/animal-individual/v1 the sealed fields are the profile's own (below),
// hashed exactly as a plant record's are. Every other record is checked as before
// (conformance.mjs). The registry stores the site's record shape and turns it into the
// profile's fields the way the site does (bboard-ui veilcore/animal-profile.ts):
//   strainName → name     bredBy → breeder      dateCreated → dateOfBirth
//   taxon → species       refId → individualId  parents → sire and dam
//   animal.{breed, idScheme, sex, herd}
// Both are checked against the same published vectors (test/fixtures/animal-individual-v1.json).
// A record in any other form is refused, never tidied: one animal written two ways would
// seal as two records.
// SPDX-License-Identifier: Apache-2.0

export const ANIMAL_PROFILE = 'veilcore/profile/animal-individual/v1';
export const ANIMAL_SEXES = ['female', 'male', 'unknown'];
export const ANIMAL_LINE_MAX = 200;
export const ANIMAL_NOTES_MAX = 20_000;

export const isAnimal = (r) => r?.profile === ANIMAL_PROFILE;

/** The sealed fields under the profile's names. Nothing is filled in; validation refuses gaps. */
export const animalFieldsOf = (r) => ({
  breed: r.animal?.breed,
  breeder: r.bredBy,
  dateOfBirth: r.dateCreated,
  herd: r.animal?.herd,
  idScheme: r.animal?.idScheme,
  individualId: r.refId,
  loggedAt: r.loggedAt,
  name: r.strainName,
  nonce: r.nonce,
  notes: r.notes,
  parents: (Array.isArray(r.parents) ? r.parents : []).map((p) => ({
    individualId: p?.individualId,
    name: p?.name,
    role: p?.role,
    ...(p?.recordId !== undefined ? { recordId: p.recordId } : {}),
  })),
  photoFingerprints: r.photoFingerprints ?? [],
  profile: r.profile,
  sex: r.animal?.sex,
  species: r.taxon,
  ...(r.keyBinding !== undefined ? { keyBinding: r.keyBinding } : {}),
});

const REQUIRED = [
  'breed', 'breeder', 'dateOfBirth', 'herd', 'idScheme', 'individualId', 'loggedAt', 'name',
  'nonce', 'notes', 'parents', 'photoFingerprints', 'profile', 'sex', 'species',
];
const ALLOWED = new Set([...REQUIRED, 'keyBinding']);
const LINES = ['species', 'breed', 'name', 'individualId', 'idScheme', 'breeder', 'herd'];
const HEX64 = /^[0-9a-f]{64}$/;
const NONCE = /^(?:[0-9a-f]{2}){32,64}$/;
const RECORD_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const CONTROL = /\p{Cc}/u;
const PARENT_KEYS = new Set(['role', 'name', 'individualId', 'recordId']);

const lineProblem = (what, v) => {
  if (typeof v !== 'string') return `${what} must be text`;
  if (Array.from(v).length > ANIMAL_LINE_MAX) return `${what} must be at most ${ANIMAL_LINE_MAX} characters`;
  if (CONTROL.test(v)) return `${what} must be one line, with no tabs or control characters`;
  if (v !== v.trim()) return `${what} must not start or end with a space`;
  return undefined;
};

export const isCalendarDate = (v) => {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(v);
  if (!m) return false;
  const d = new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])));
  return d.getUTCFullYear() === Number(m[1]) && d.getUTCMonth() === Number(m[2]) - 1 && d.getUTCDate() === Number(m[3]);
};

const parentProblems = (parents) => {
  if (!Array.isArray(parents)) return ['parents must be a list'];
  if (parents.length > 2) return ['parents may name a sire and a dam, nothing more'];
  const out = [];
  const roles = [];
  parents.forEach((p, i) => {
    const at = `parent ${i + 1}`;
    if (typeof p !== 'object' || p === null || Array.isArray(p)) { out.push(`${at} must be an object`); return; }
    for (const k of Object.keys(p)) if (!PARENT_KEYS.has(k)) out.push(`${at}: ${k} is not a parent field`);
    if (p.role !== 'sire' && p.role !== 'dam') out.push(`${at}: role must be sire or dam`);
    else roles.push(p.role);
    for (const k of ['name', 'individualId']) {
      if (p[k] === undefined) out.push(`${at}: ${k} is missing`);
      else { const pr = lineProblem(`${at}: ${k}`, p[k]); if (pr) out.push(pr); }
    }
    if (p.recordId !== undefined && !(typeof p.recordId === 'string' && RECORD_ID.test(p.recordId))) out.push(`${at}: recordId is not a record id`);
    if (p.recordId === undefined && p.name === '' && p.individualId === '') out.push(`${at}: needs a name, an individual ID or a linked record`);
  });
  if (roles.length === 2 && roles[0] === roles[1]) out.push('parents may name one sire and one dam');
  else if (roles.length === 2 && roles[0] !== 'sire') out.push('the sire comes before the dam');
  return out;
};

/** What is wrong with an animal record's sealed fields, one sentence each; [] when none. */
export const validateAnimalFields = (f) => {
  if (typeof f !== 'object' || f === null || Array.isArray(f)) return ['the fields must be an object'];
  const out = [];
  if (f.profile !== ANIMAL_PROFILE) out.push(`profile must be ${ANIMAL_PROFILE}`);
  for (const k of REQUIRED) if (f[k] === undefined) out.push(`${k} is missing`);
  for (const k of Object.keys(f)) if (!ALLOWED.has(k)) out.push(`${k} is not a field of this profile`);
  for (const k of LINES) {
    if (f[k] === undefined) continue;
    const p = lineProblem(k, f[k]);
    if (p) out.push(p);
  }
  if (f.notes !== undefined) {
    if (typeof f.notes !== 'string') out.push('notes must be text');
    else if (Array.from(f.notes).length > ANIMAL_NOTES_MAX) out.push(`notes must be at most ${ANIMAL_NOTES_MAX} characters`);
  }
  const text = (k) => (typeof f[k] === 'string' ? f[k] : '');
  if (f.species !== undefined && text('species') === '') out.push('species must not be empty');
  if (f.breeder !== undefined && text('breeder') === '') out.push('breeder must not be empty');
  if (f.name !== undefined && f.individualId !== undefined && text('name') === '' && text('individualId') === '') out.push('a name or an individual ID is needed');
  if (text('individualId') !== '' && f.idScheme !== undefined && text('idScheme') === '') out.push('idScheme must say which ID scheme the individual ID belongs to');
  if (text('idScheme') !== '' && f.individualId !== undefined && text('individualId') === '') out.push('idScheme is given but individualId is empty');
  if (f.sex !== undefined && !ANIMAL_SEXES.includes(f.sex)) out.push('sex must be female, male or unknown');
  if (f.dateOfBirth !== undefined && f.dateOfBirth !== '' && !(typeof f.dateOfBirth === 'string' && isCalendarDate(f.dateOfBirth))) out.push('dateOfBirth must be empty or a date written YYYY-MM-DD');
  if (f.loggedAt !== undefined && !(typeof f.loggedAt === 'number' && Number.isSafeInteger(f.loggedAt) && f.loggedAt >= 0)) out.push('loggedAt must be a whole number of milliseconds, 0 or more');
  if (f.nonce !== undefined && !(typeof f.nonce === 'string' && NONCE.test(f.nonce))) out.push('nonce must be 32 to 64 bytes of lowercase hex');
  if (f.keyBinding !== undefined && !(typeof f.keyBinding === 'string' && HEX64.test(f.keyBinding))) out.push('keyBinding must be 64 lowercase hex characters');
  if (f.photoFingerprints !== undefined) {
    if (!Array.isArray(f.photoFingerprints) || f.photoFingerprints.length > 500) out.push('photoFingerprints must be a list of at most 500');
    else if (!f.photoFingerprints.every((p) => typeof p === 'string' && HEX64.test(p))) out.push('each photo fingerprint must be 64 lowercase hex characters');
  }
  if (f.parents !== undefined) out.push(...parentProblems(f.parents));
  return out;
};

/** A stored animal record's `animal` details, for the size checks (server.js recordProblem). */
export const animalDetailsProblem = (animal) => {
  if (animal === undefined) return null;
  if (typeof animal !== 'object' || animal === null || Array.isArray(animal)) return 'animal must be an object';
  for (const k of Object.keys(animal)) if (!['breed', 'idScheme', 'sex', 'herd'].includes(k)) return `animal.${k} is not an animal detail`;
  for (const k of ['breed', 'idScheme', 'sex', 'herd']) {
    const v = animal[k];
    if (v !== undefined && (typeof v !== 'string' || v.length > 500)) return `animal.${k} must be a string of at most 500 characters`;
  }
  return null;
};

/** The sire and dam a stranger may be shown under the parent-names grant: names and IDs, nothing else. */
export const publicParents = (r) => {
  const out = {};
  for (const p of Array.isArray(r.parents) ? r.parents : []) {
    if (!p || (p.role !== 'sire' && p.role !== 'dam') || out[p.role]) continue;
    const name = typeof p.name === 'string' ? p.name : '';
    const individualId = typeof p.individualId === 'string' ? p.individualId : '';
    if (name || individualId) out[p.role] = { name, individualId };
  }
  return out;
};
