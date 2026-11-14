import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';

const here = dirname(fileURLToPath(import.meta.url));
const server = readFileSync(join(here, '..', 'server.js'), 'utf8');
const pkg = JSON.parse(readFileSync(join(here, '..', 'package.json'), 'utf8'));

const LOGGERS = ['morgan', 'winston', 'pino', 'pino-http', 'express-winston', 'bunyan', 'express-pino-logger'];

test('no request-logging package is a dependency', () => {
  const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
  const found = LOGGERS.filter((l) => l in deps);
  assert.deepEqual(found, [], `request logger in dependencies: ${found.join(', ')}`);
});

test('server.js imports no request logger', () => {
  const found = LOGGERS.filter((l) => new RegExp(`(require\\(|from\\s+)['"]${l}['"]`).test(server));
  assert.deepEqual(found, [], `request logger imported: ${found.join(', ')}`);
});

test('the verify path does not write', () => {
  const start = server.indexOf("app.get('/verify/:id'");
  assert.ok(start > -1, 'could not find /verify/:id');
  const next = server.indexOf('\napp.', start + 10);
  const body = server.slice(start, next === -1 ? server.length : next);
  for (const w of ['INSERT', 'UPDATE ', 'DELETE', 'appendFile', 'writeFile']) {
    assert.ok(!body.includes(w), `verify path contains a write: ${w}`);
  }
});
