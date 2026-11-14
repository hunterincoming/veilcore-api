// Settings checked once at startup, kept apart from server.js so each rule can be tested.
// SPDX-License-Identifier: Apache-2.0

const path = require('node:path');

/**
 * The operator token guards sealing, anchoring and vetting. A short one can be guessed
 * or brute-forced against the routes, so one under 32 characters is treated as unset:
 * operator routes stay disabled and the log says why (never the token itself).
 */
const OPERATOR_TOKEN_MIN = 32;
const operatorToken = (env, log = console.error) => {
  const t = env.VEILCORE_OPERATOR_TOKEN;
  if (typeof t !== 'string' || t.trim() === '') return null;
  if (t.trim().length < OPERATOR_TOKEN_MIN) {
    log(`VEILCORE_OPERATOR_TOKEN is set but shorter than ${OPERATOR_TOKEN_MIN} characters, so registry operations stay disabled. ` +
      'Set a long random value (e.g. `openssl rand -hex 32`).');
    return null;
  }
  return t;
};

/**
 * Whether the database will survive a redeploy. On Railway a container's own disk is
 * replaced on every deploy; only a mounted volume persists, and Railway names it in
 * RAILWAY_VOLUME_MOUNT_PATH. Off Railway (a laptop, CI) nothing can be told, and nothing
 * is said. Returns the warning, or null.
 */
const persistenceWarning = (env, dbPath) => {
  if (!dbPath || dbPath === ':memory:') return null;
  const file = path.resolve(dbPath);
  const mount = (env.RAILWAY_VOLUME_MOUNT_PATH || '').trim();
  if (mount) {
    const m = path.resolve(mount);
    if (file === m || file.startsWith(m.endsWith(path.sep) ? m : m + path.sep)) return null;
    return `DB_PATH (${file}) is not on the volume mounted at ${m}, so the database is lost on every redeploy. ` +
      `Set DB_PATH to a file under ${m} (e.g. ${path.join(m, 'veilcore.db')}).`;
  }
  const onRailway = Object.keys(env).some((k) => k.startsWith('RAILWAY_'));
  if (!onRailway) return null;
  return `no Railway volume is mounted (RAILWAY_VOLUME_MOUNT_PATH is unset), so the database at ${file} is lost on every redeploy. ` +
    'Attach a volume to this service and set DB_PATH to a file on it (README, "Keeping the data").';
};

module.exports = { OPERATOR_TOKEN_MIN, operatorToken, persistenceWarning };
