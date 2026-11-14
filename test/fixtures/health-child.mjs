// Child process for test/health.test.mjs: start the server (with FAIL_MODULE failing to load,
// or DELAY_MODULE held back, if set), and print what /health answered once loading settled.
//
// It waits on what the server says, not on time. The server reports each of its three
// loads finishing in its log (server.js): the commitment checker, the embed verifier, and
// the lineage chain, whose last line is about lab results. A held module is let go only
// once the others have finished, and /health is asked at that moment (`during`).
// SPDX-License-Identifier: Apache-2.0
import { register } from 'node:module';
import { createRequire } from 'node:module';
import { waitFor } from '../helpers.mjs';
import { HELD } from './fail-module-hooks.mjs';

// The held module (DELAY_MODULE) waits on this before it finishes loading (fail-module-hooks.mjs).
let release;
globalThis[HELD] = new Promise((r) => { release = r; });
register(new URL('./fail-module-hooks.mjs', import.meta.url));
process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';

const logged = [];
const realLog = console.log;
console.log = (...a) => logged.push(a.join(' '));
console.error = (...a) => logged.push(a.join(' '));
const saw = (re) => logged.some((l) => re.test(l));
const finished = {
  conformance: () => saw(/^commitment verification ready/),
  embed: () => saw(/^embed verifier (ready|unavailable)/),
  lineage: () => saw(/^lab results ready|^lineage layer unavailable/),
};

const require = createRequire(import.meta.url);
const { app } = require('../../server.js');
const server = app.listen(0);
await new Promise((r) => server.once('listening', r));
const base = `http://127.0.0.1:${server.address().port}`;
const health = async () => {
  const res = await fetch(`${base}/health`);
  return { status: res.status, body: await res.json() };
};

const early = await health();
let during = null;
if (process.env.DELAY_MODULE === 'conformance.mjs') {
  await waitFor('the loads that are not held back to finish', () => finished.embed() && finished.lineage());
  during = await health();
  release();
} else if (process.env.DELAY_MODULE) {
  // A module the lineage chain loads after every part /health lists: held, the parts are all
  // there while the chain has not finished.
  during = await waitFor('every part /health lists to load', async () => {
    const h = await health();
    return (h.status === 200 || h.body.notReady?.length === 0) && h;
  });
  release();
}
await waitFor('every load to finish', () => Object.values(finished).every((f) => f()));
const settled = await health();
console.log = realLog;
console.log(JSON.stringify({ early, during, status: settled.status, body: settled.body }));
server.close();
process.exit(0);
