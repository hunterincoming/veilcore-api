// Module hooks for test/health.test.mjs: makes one lineage module fail to load, the way a
// broken deploy would (a missing file, a bad dependency), or load late. FAIL_MODULE names
// the one that fails; DELAY_MODULE the one that is held back until the child lets it go
// (health-child.mjs). Held, not delayed by a fixed time: on a busy machine the other modules
// took longer than the delay, and the moment the test looks for (everything loaded but this
// one) never came.
//
// Held in its evaluation, not its resolution (8 Nov 2026). The held module's source is given a
// first line that waits, at top level, on a promise the child keeps on globalThis; the main
// thread stays free while it waits. It used to be held in `resolve`, until a message from the
// child released it: from Node 24.22 import() waits on the hooks synchronously, so the main
// thread was blocked inside import() and could never send the message (the child hung).
// SPDX-License-Identifier: Apache-2.0

/** The global the child sets: a promise that settles when the held module may finish loading. */
export const HELD = '__veilcoreHeldModule';

export async function resolve(specifier, context, next) {
  const name = process.env.FAIL_MODULE;
  if (name && specifier.endsWith(`/${name}`)) throw new Error(`simulated load failure: ${name}`);
  return next(specifier, context);
}

export async function load(url, context, next) {
  const late = process.env.DELAY_MODULE;
  const out = await next(url, context);
  if (!late || !url.endsWith(`/${late}`) || out.format !== 'module') return out;
  const source = typeof out.source === 'string' ? out.source : Buffer.from(out.source).toString('utf8');
  // One line, so the module's own line numbers move by one and nothing else changes.
  return { ...out, source: `await globalThis.${HELD};\n${source}` };
}
