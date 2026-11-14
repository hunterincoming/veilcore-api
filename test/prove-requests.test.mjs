// The prove-request mailbox (lineage/prove-requests.mjs): a checker asks, the holder
// answers, and the registry only carries messages. No network beyond this process.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import Database from 'better-sqlite3';
import { createProveRequests, PROVE_LIMITS, cleanAsker, tokenHash } from '../lineage/prove-requests.mjs';
import { untilReady } from './helpers.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
const require = createRequire(import.meta.url);
const { app } = require('../server.js');
const hex = () => randomBytes(32).toString('hex');
/** What the checker's browser does: a 128-bit token for the link's fragment, and its hash for the registry. */
const newToken = () => {
  const token = randomBytes(16).toString('base64url');
  return { token, answerTokenHash: tokenHash(token) };
};

let base, server;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  await untilReady(base);
});
after(() => server.close());

const call = async (method, path, body) => {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { 'content-type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: res.status, json: await res.json() };
};

test('a checker asks, the holder reads it and answers, the checker reads the answer: no holder key anywhere', async () => {
  const identity = hex(), challenge = hex(), txId = hex();
  const { token, answerTokenHash } = newToken();
  const asked = await call('POST', '/prove-requests', { identity, challenge, answerTokenHash, asker: '  Example Grow Co.  ' });
  assert.equal(asked.status, 200);
  assert.match(asked.json.id, /^PR-[0-9A-F]{32}$/);

  const seen = await call('GET', `/prove-requests/${asked.json.id}`);
  assert.equal(seen.status, 200);
  assert.deepEqual(
    { identity: seen.json.identity, challenge: seen.json.challenge, asker: seen.json.asker, answers: seen.json.answers },
    { identity, challenge, asker: 'Example Grow Co.', answers: [] },
  );

  assert.equal('answerTokenHash' in seen.json, false, 'the hash is never handed back');
  assert.equal((await call('POST', `/prove-requests/${asked.json.id}/answers`, { txId: `0x${txId.toUpperCase()}`, token })).status, 200);
  const ids = async () => (await call('GET', `/prove-requests/${asked.json.id}`)).json.answers.map((a) => a.txId);
  assert.deepEqual(await ids(), [txId]);
  const [first] = (await call('GET', `/prove-requests/${asked.json.id}`)).json.answers;
  assert.equal(typeof first.answeredAt, 'number');
  assert.ok(Math.abs(first.answeredAt - Date.now()) < 60_000);
  // The same answer twice is one answer.
  await call('POST', `/prove-requests/${asked.json.id}/answers`, { txId, token });
  assert.deepEqual(await ids(), [txId]);
});

test('bad input is refused, and an unknown or malformed id reads as not found', async () => {
  const { token, answerTokenHash } = newToken();
  assert.equal((await call('POST', '/prove-requests', { identity: 'zz', challenge: hex(), answerTokenHash })).status, 400);
  assert.equal((await call('POST', '/prove-requests', { identity: hex(), challenge: 'short', answerTokenHash })).status, 400);
  assert.equal((await call('POST', '/prove-requests', { identity: hex(), challenge: hex() })).status, 400, 'no answer token hash');
  assert.equal((await call('POST', '/prove-requests', { identity: hex(), challenge: hex(), answerTokenHash: 'abc' })).status, 400);
  assert.equal((await call('POST', '/prove-requests', { identity: hex(), challenge: hex(), answerTokenHash, asker: 'x'.repeat(81) })).status, 400);
  assert.equal((await call('POST', '/prove-requests', { identity: hex(), challenge: hex(), answerTokenHash, asker: { a: 1 } })).status, 400);
  assert.equal((await call('GET', `/prove-requests/PR-${'0'.repeat(32)}`)).status, 404);
  assert.equal((await call('GET', `/prove-requests/' OR 1=1 --`)).status, 404);
  const asked = await call('POST', '/prove-requests', { identity: hex(), challenge: hex(), answerTokenHash });
  assert.equal((await call('POST', `/prove-requests/${asked.json.id}/answers`, { txId: 'nope', token })).status, 400);
});

test('the asker name cannot carry hidden or reordering characters', async () => {
  const asked = await call('POST', '/prove-requests', { identity: hex(), challenge: hex(), ...newToken(), asker: 'Lab‮oc​\u0007' });
  assert.equal((await call('GET', `/prove-requests/${asked.json.id}`)).json.asker, 'Laboc');
});

test('without the token from the link nobody can answer, so junk cannot crowd out the real answer', async () => {
  const { token, answerTokenHash } = newToken();
  const asked = await call('POST', '/prove-requests', { identity: hex(), challenge: hex(), answerTokenHash });
  const path = `/prove-requests/${asked.json.id}/answers`;
  // Someone who saw only the id tries to fill every slot.
  for (let i = 0; i < PROVE_LIMITS.maxAnswers + 2; i++) {
    assert.equal((await call('POST', path, { txId: hex() })).status, 403);
    assert.equal((await call('POST', path, { txId: hex(), token: newToken().token })).status, 403);
  }
  assert.equal((await call('POST', path, { txId: hex(), token: token.slice(0, -1) })).status, 403);
  assert.equal((await call('POST', path, { txId: hex(), token: answerTokenHash })).status, 403, 'the hash is not the token');
  assert.equal((await call('POST', path, { txId: hex(), token: { t: token } })).status, 403);
  assert.deepEqual((await call('GET', `/prove-requests/${asked.json.id}`)).json.answers, []);
  // The real holder still gets in.
  const real = hex();
  assert.equal((await call('POST', path, { txId: real, token })).status, 200);
  assert.deepEqual((await call('GET', `/prove-requests/${asked.json.id}`)).json.answers.map((a) => a.txId), [real]);
});

test('a few answers are kept, then the request says it is full', () => {
  const p = createProveRequests(new Database(':memory:'));
  const { token, answerTokenHash } = newToken();
  const { id } = p.ask({ identity: hex(), challenge: hex(), answerTokenHash });
  for (let i = 0; i < PROVE_LIMITS.maxAnswers; i++) assert.equal(p.answer(id, hex(), token).ok, true);
  assert.equal(p.answer(id, hex(), token).code, 409);
  assert.equal(p.get(id).answers.length, PROVE_LIMITS.maxAnswers);
});

test('each answer keeps when it came in', () => {
  let t = 5_000_000;
  const p = createProveRequests(new Database(':memory:'), { now: () => t });
  const { token, answerTokenHash } = newToken();
  const { id } = p.ask({ identity: hex(), challenge: hex(), answerTokenHash });
  const a = hex(), b = hex();
  t += 1000;
  p.answer(id, a, token);
  t += 60_000;
  p.answer(id, b, token);
  p.answer(id, a, token); // again: keeps the first time
  assert.deepEqual(p.get(id).answers, [{ txId: a, answeredAt: 5_001_000 }, { txId: b, answeredAt: 5_061_000 }]);
});

test('a request stored without a token hash (made before tokens) can be read but not answered', () => {
  const db = new Database(':memory:');
  db.exec(`CREATE TABLE prove_requests (id TEXT PRIMARY KEY, identity TEXT NOT NULL, challenge TEXT NOT NULL,
    asker TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, answers TEXT NOT NULL DEFAULT '[]')`);
  const id = `PR-${'A'.repeat(32)}`, old = hex();
  db.prepare('INSERT INTO prove_requests (id, identity, challenge, created_at, answers) VALUES (?, ?, ?, ?, ?)')
    .run(id, hex(), hex(), Date.now(), JSON.stringify([old]));
  const p = createProveRequests(db);
  assert.deepEqual(p.get(id).answers.map((a) => a.txId), [old]);
  assert.equal(p.answer(id, hex(), newToken().token).code, 403);
  assert.ok(db.prepare("SELECT 1 FROM pragma_index_list('prove_requests') WHERE name = 'prove_requests_created'").get());
});

test('requests expire, and expired ones are swept', () => {
  let t = 1_000_000;
  const db = new Database(':memory:');
  const p = createProveRequests(db, { now: () => t });
  const { token, answerTokenHash } = newToken();
  const { id } = p.ask({ identity: hex(), challenge: hex(), answerTokenHash });
  t += PROVE_LIMITS.ttlMs + 1;
  assert.equal(p.get(id), null);
  assert.equal(p.answer(id, hex(), token).code, 404);
  p.ask({ identity: hex(), challenge: hex(), answerTokenHash }); // asking sweeps
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM prove_requests').get().n, 1);
});

test('a sweep is not run on every ask', () => {
  let t = 1_000_000;
  const db = new Database(':memory:');
  const p = createProveRequests(db, { now: () => t });
  const { answerTokenHash } = newToken();
  p.ask({ identity: hex(), challenge: hex(), answerTokenHash }); // sweeps (first), then stores one
  t += PROVE_LIMITS.ttlMs + 1; // that one has expired
  p.ask({ identity: hex(), challenge: hex(), answerTokenHash }); // sweeps: over a minute since the last
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM prove_requests').get().n, 1);
  t += PROVE_LIMITS.ttlMs + 1; // the second has expired too
  const sweeps = [];
  const realPrepare = db.prepare.bind(db);
  db.prepare = (sql) => (sql.startsWith('DELETE') && sweeps.push(sql), realPrepare(sql));
  p.ask({ identity: hex(), challenge: hex(), answerTokenHash });
  t += 10_000;
  p.ask({ identity: hex(), challenge: hex(), answerTokenHash });
  t += 10_000;
  p.ask({ identity: hex(), challenge: hex(), answerTokenHash });
  assert.equal(sweeps.length, 1, 'three asks within a minute: one sweep');
});

test('too many live requests: asking is refused with "busy" until some expire', () => {
  let t = 1_000_000;
  const p = createProveRequests(new Database(':memory:'), { now: () => t, limits: { maxLive: 3 } });
  const { answerTokenHash } = newToken();
  for (let i = 0; i < 3; i++) assert.ok(p.ask({ identity: hex(), challenge: hex(), answerTokenHash }).id);
  assert.deepEqual(p.ask({ identity: hex(), challenge: hex(), answerTokenHash }), { error: 'busy, try later', code: 503 });
  t += PROVE_LIMITS.ttlMs + PROVE_LIMITS.sweepEveryMs + 1;
  assert.ok(p.ask({ identity: hex(), challenge: hex(), answerTokenHash }).id);
});

test('one address cannot use up every live request: each has a daily count', () => {
  let t = 5 * 86_400_000;
  const p = createProveRequests(new Database(':memory:'), { now: () => t, limits: { perClientDaily: 2 } });
  const { answerTokenHash } = newToken();
  const ask = (client) => p.ask({ identity: hex(), challenge: hex(), answerTokenHash }, client);
  assert.ok(ask('203.0.113.7').id);
  assert.ok(ask('203.0.113.7').id);
  assert.equal(ask('203.0.113.7').code, 429);
  assert.ok(ask('2001:db8:1:2::/64').id, 'another address is not affected');
  t += 86_400_000;
  assert.ok(ask('203.0.113.7').id, 'the next day');
});

test('the asker name keeps only visible text', () => {
  const hidden = {
    'U+061C arabic letter mark': '؜',
    'U+2060 word joiner': '⁠',
    'U+2061 function application': '⁡',
    'U+2062 invisible times': '⁢',
    'U+2063 invisible separator': '⁣',
    'U+2064 invisible plus': '⁤',
    'U+FEFF byte order mark': '﻿',
    'U+2028 line separator': ' ',
    'U+2029 paragraph separator': ' ',
    'U+115F hangul choseong filler': 'ᅟ',
    'U+3164 hangul filler': 'ㅤ',
    'U+202E right-to-left override': '‮',
    'U+200B zero width space': '​',
    'U+0007 bell': '\u0007',
    'U+0000 null': '\u0000',
    'U+FFA0 halfwidth hangul filler': 'ﾠ',
    'U+00AD soft hyphen': '­',
  };
  for (const [name, ch] of Object.entries(hidden)) {
    assert.equal(cleanAsker(`Ab${ch}cd`), 'Abcd', name);
    assert.equal(cleanAsker(`${ch}`), '', `${name} alone`);
  }
  // Any kind of space becomes one plain space; runs collapse; ends are trimmed.
  assert.equal(cleanAsker('  Green  Lab 　 Co.\t\n'), 'Green Lab Co.');
  // NFKC: full-width letters become plain ones.
  assert.equal(cleanAsker('Ｌａｂ'), 'Lab');
  // Real text in other scripts, accents, punctuation and symbols stays.
  assert.equal(cleanAsker('Ñandú Labs — 試験所 №5 (café) ✓'), 'Ñandú Labs — 試験所 No5 (café) ✓');
  // The cap counts characters, after cleaning.
  assert.equal(cleanAsker(`${'x'.repeat(80)}⁠⁠`), 'x'.repeat(80));
  assert.equal(cleanAsker('x'.repeat(81)), null);
  assert.equal(cleanAsker(42), null);
  assert.equal(cleanAsker(undefined), '');
});
