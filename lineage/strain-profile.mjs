// A strain or line record: one microbial strain, cell line or insect line (the site's
// docs/strain-profile.md, SPEC 11.9; a draft until marked final). The registry's copy of the
// site's bboard-ui veilcore/strain-profile.ts: the same sealed fields, the same refusals,
// checked against the same vectors (test/fixtures/strain-v1.json).
//
// In the app's stored shape: strainName is the name, refId the designation, taxon the species,
// breedingMethod the method, dateCreated when it was made, bredBy the maker, parents each
// { name, individualId (the deposit), recordId? }, and strain { group, deposits, generation }.
// SPDX-License-Identifier: Apache-2.0

export const STRAIN_PROFILE = 'veilcore/profile/strain/v1';

export const STRAIN_GROUPS = [
  'bacterium',
  'archaeon',
  'yeast',
  'filamentous-fungus',
  'microalga',
  'protist',
  'virus',
  'cell-line',
  'insect',
  'other',
];


/** A strain or line record (by its profile). */
export const isStrain = (r) => r?.profile === STRAIN_PROFILE;

/** The sealed fields, under the profile's names. Nothing is filled in: a missing value stays missing. */
export const strainFieldsOf = (r) => ({
  deposits: r.strain?.deposits ? [...r.strain.deposits] : undefined,
  designation: r.refId,
  generation: r.strain?.generation,
  group: r.strain?.group,
  loggedAt: r.loggedAt,
  madeOn: r.dateCreated,
  maker: r.bredBy,
  method: r.breedingMethod,
  name: r.strainName,
  nonce: r.nonce,
  notes: r.notes,
  parents: (r.parents ?? []).map((p) => ({
    deposit: p.individualId,
    name: p.name,
    ...(p.recordId !== undefined ? { recordId: p.recordId } : {}),
  })),
  photoFingerprints: r.photoFingerprints ?? [],
  profile: r.profile,
  species: r.taxon,
  ...(r.keyBinding !== undefined ? { keyBinding: r.keyBinding } : {}),
});

// ---- validation (the profile's canonical form) ---------------------------------------------

export const STRAIN_LINE_MAX = 200;
export const STRAIN_NOTES_MAX = 20_000;
export const STRAIN_DEPOSITS_MAX = 8;

const REQUIRED = [
  'deposits',
  'designation',
  'generation',
  'group',
  'loggedAt',
  'madeOn',
  'maker',
  'method',
  'name',
  'nonce',
  'notes',
  'parents',
  'photoFingerprints',
  'profile',
  'species',
];
const ALLOWED = new Set([...REQUIRED, 'keyBinding']);
const LINES = ['species', 'name', 'designation', 'method', 'generation', 'maker'];

const HEX64 = /^[0-9a-f]{64}$/;
const NONCE = /^(?:[0-9a-f]{2}){32,64}$/;
const RECORD_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const CONTROL = /\p{Cc}/u;

const lineProblem = (what, v) => {
  if (typeof v !== 'string') return `${what} must be text`;
  if (Array.from(v).length > STRAIN_LINE_MAX) return `${what} must be at most ${STRAIN_LINE_MAX} characters`;
  if (CONTROL.test(v)) return `${what} must be one line, with no tabs or control characters`;
  if (v !== v.trim()) return `${what} must not start or end with a space`;
  return undefined;
};

const isCalendarDate = (v) => {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(v);
  if (!m) return false;
  const d = new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])));
  return d.getUTCFullYear() === Number(m[1]) && d.getUTCMonth() === Number(m[2]) - 1 && d.getUTCDate() === Number(m[3]);
};

/** What is wrong with a strain record's sealed fields, one sentence each; [] when none. */
export const validateStrainFields = (fields) => {
  if (typeof fields !== 'object' || fields === null || Array.isArray(fields)) return ['the fields must be an object'];
  const f = fields;
  const out = [];
  if (f.profile !== STRAIN_PROFILE) out.push(`profile must be ${STRAIN_PROFILE}`);
  for (const k of REQUIRED) if (f[k] === undefined) out.push(`${k} is missing`);
  for (const k of Object.keys(f)) if (!ALLOWED.has(k)) out.push(`${k} is not a field of this profile`);
  for (const k of LINES) {
    if (f[k] === undefined) continue;
    const p = lineProblem(k, f[k]);
    if (p) out.push(p);
  }
  const text = (k) => (typeof f[k] === 'string' ? f[k] : '');
  if (f.species !== undefined && text('species') === '') out.push('species must not be empty');
  if (f.maker !== undefined && text('maker') === '') out.push('maker must not be empty');
  if (f.name !== undefined && f.designation !== undefined && text('name') === '' && text('designation') === '')
    out.push('a name or a designation is needed');
  if (f.group !== undefined && !STRAIN_GROUPS.includes(f.group))
    out.push(`group must be one of ${STRAIN_GROUPS.join(', ')}`);
  if (f.deposits !== undefined) {
    if (!Array.isArray(f.deposits) || f.deposits.length > STRAIN_DEPOSITS_MAX)
      out.push(`deposits must be a list of at most ${STRAIN_DEPOSITS_MAX}`);
    else {
      f.deposits.forEach((d, i) => {
        const p = lineProblem(`deposit ${i + 1}`, d);
        if (p) out.push(p);
        else if (d === '') out.push(`deposit ${i + 1} must not be empty`);
      });
      if (new Set(f.deposits).size !== f.deposits.length) out.push('each deposit is listed once');
    }
  }
  if (f.notes !== undefined) {
    if (typeof f.notes !== 'string') out.push('notes must be text');
    else if (Array.from(f.notes).length > STRAIN_NOTES_MAX)
      out.push(`notes must be at most ${STRAIN_NOTES_MAX} characters`);
  }
  if (f.madeOn !== undefined && f.madeOn !== '' && !(typeof f.madeOn === 'string' && isCalendarDate(f.madeOn)))
    out.push('madeOn must be empty or a date written YYYY-MM-DD');
  if (
    f.loggedAt !== undefined &&
    !(typeof f.loggedAt === 'number' && Number.isSafeInteger(f.loggedAt) && f.loggedAt >= 0)
  )
    out.push('loggedAt must be a whole number of milliseconds, 0 or more');
  if (f.nonce !== undefined && !(typeof f.nonce === 'string' && NONCE.test(f.nonce)))
    out.push('nonce must be 32 to 64 bytes of lowercase hex');
  if (f.keyBinding !== undefined && !(typeof f.keyBinding === 'string' && HEX64.test(f.keyBinding)))
    out.push('keyBinding must be 64 lowercase hex characters');
  if (f.photoFingerprints !== undefined) {
    if (!Array.isArray(f.photoFingerprints) || f.photoFingerprints.length > 500)
      out.push('photoFingerprints must be a list of at most 500');
    else if (!f.photoFingerprints.every((p) => typeof p === 'string' && HEX64.test(p)))
      out.push('each photo code must be 64 lowercase hex characters');
  }
  if (f.parents !== undefined) out.push(...parentProblems(f.parents));
  return out;
};

const PARENT_KEYS = new Set(['name', 'deposit', 'recordId']);

/** At most two parent strains (one for a mutant or a subculture; two for a cross, fusion or mating). */
const parentProblems = (parents) => {
  if (!Array.isArray(parents)) return ['parents must be a list'];
  if (parents.length > 2) return ['parents may name at most two parent strains'];
  const out = [];
  parents.forEach((p, i) => {
    const at = `parent ${i + 1}`;
    if (typeof p !== 'object' || p === null || Array.isArray(p)) {
      out.push(`${at} must be an object`);
      return;
    }
    const q = p;
    for (const k of Object.keys(q)) if (!PARENT_KEYS.has(k)) out.push(`${at}: ${k} is not a parent field`);
    for (const k of ['name', 'deposit']) {
      if (q[k] === undefined) out.push(`${at}: ${k} is missing`);
      else {
        const pr = lineProblem(`${at}: ${k}`, q[k]);
        if (pr) out.push(pr);
      }
    }
    if (q.recordId !== undefined && !(typeof q.recordId === 'string' && RECORD_ID.test(q.recordId)))
      out.push(`${at}: recordId is not a record id`);
    if (q.recordId === undefined && q.name === '' && q.deposit === '')
      out.push(`${at}: needs a name, a deposit number or a linked record`);
  });
  return out;
};

