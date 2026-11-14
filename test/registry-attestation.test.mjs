// Lineage answers come from the registry's database, not the chain, and must say so.
// Starts the real server on a scratch database and asks it.
// SPDX-License-Identifier: Apache-2.0

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { untilReady, waitFor } from './helpers.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

test('lineage responses are labelled registry-attested', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'veilcore-'));
  // Port 0: the system picks a free one, and the server says which (fixtures/report-port.cjs).
  const server = spawn(process.execPath, ['-r', join(root, 'test/fixtures/report-port.cjs'), 'server.js'], {
    cwd: root,
    env: { ...process.env, PORT: '0', DB_PATH: join(dir, 'test.db') },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  // Stopped before its folder is removed, so nothing is still writing into it.
  t.after(async () => {
    if (server.exitCode === null && server.signalCode === null) {
      const exited = new Promise((r) => server.once('exit', r));
      server.kill();
      await exited;
    }
    rmSync(dir, { recursive: true, force: true });
  });
  let out = '';
  server.stdout.on('data', (b) => { out += b; });
  server.stderr.on('data', (b) => { out += b; });

  const port = await waitFor('the server to say which port it has', () => {
    if (server.exitCode !== null) throw new Error(`the server stopped (${server.exitCode}):\n${out}`);
    return /listening on port (\d+)/.exec(out)?.[1];
  });
  const base = `http://127.0.0.1:${port}`;
  await untilReady(base);
  assert.equal((await fetch(`${base}/lineage/root`)).status, 200, 'server did not start with the lineage layer');

  const listing = await fetch(`${base}/lineage/obligations`);
  assert.equal(listing.headers.get('x-veilcore-attestation'), 'registry');

  const verify = await fetch(`${base}/lineage/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ record: 'ab'.repeat(32), chain: [] }),
  });
  const body = await verify.json();
  assert.equal(verify.headers.get('x-veilcore-attestation'), 'registry');
  assert.equal(body.attestation, 'registry');
  assert.match(body.note, /not from chain state/);
});
