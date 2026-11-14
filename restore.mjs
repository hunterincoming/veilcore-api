// Put a backup back (backup.mjs). Two jobs, one tool:
//
//   CHECK a backup opens (the drill; on the operator's own computer, touches nothing live):
//     read -s AGE_IDENTITY; export AGE_IDENTITY
//     node restore.mjs --file 2026-11-05T....sqlite.gz.age --to restored.db
//     unset AGE_IDENTITY; rm restored.db
//
//   RESTORE into service (only after a real loss; inside the container, with the registry
//   stopped as the README says): the same, with --from-bucket <object name> instead of
//   --file so nothing has to be copied in by hand, --to /data/veilcore.db --replace, and
//   --lab-results /data/lab-results to bring the lab files back too. Reading the bucket
//   needs a READ key (the service's own key can only write): make one in Backblaze for the
//   restore, give it as BACKUP_S3_KEY_ID / BACKUP_S3_SECRET in the session, delete it after.
//
// The private key is read from AGE_IDENTITY (never an argument: arguments show up in the
// process list and shell history). What is written is checked before it is used: it must
// open, pass SQLite's integrity check and hold a records table. With --replace, the file
// it replaces is kept beside it as <name>.before-restore-<time>, and a leftover journal or
// WAL is moved aside too, so SQLite can't replay it into the restored file.
// SPDX-License-Identifier: Apache-2.0

import { createReadStream, createWriteStream, existsSync, mkdirSync, renameSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { Decrypter } from 'age-encryption';
import { AwsClient } from 'aws4fetch';

const require = createRequire(import.meta.url);
const Database = require('better-sqlite3');

const LAB_ID = /^[A-Za-z0-9_-]{8,64}$/;

/** The private key, as age wants it, from text that may carry a note around it. */
export const identityFrom = (text) => {
  const m = /AGE-SECRET-KEY-1[0-9A-Z]+/.exec(String(text ?? ''));
  if (!m) throw new Error('AGE_IDENTITY holds no age private key (AGE-SECRET-KEY-1…)');
  return m[0];
};

/** Decrypt and gunzip a backup stream into a file. */
export const openBackup = async (source, identity, to) => {
  const d = new Decrypter();
  d.addIdentity(identity);
  let plain;
  try {
    plain = await d.decrypt(source);
  } catch {
    throw new Error('this key does not open that backup (wrong key, or not a backup sealed to it)');
  }
  await pipeline(Readable.fromWeb(plain.pipeThrough(new DecompressionStream('gzip'))), createWriteStream(to, { mode: 0o600 }));
};

/** Is this file a sound registry database? Returns its record count, or throws why not. */
export const checkDatabase = (path) => {
  const db = new Database(path, { readonly: true, fileMustExist: true });
  try {
    const check = db.pragma('integrity_check', { simple: true });
    if (check !== 'ok') throw new Error(`the restored file failed SQLite's integrity check: ${check}`);
    return db.prepare('SELECT count(*) AS n FROM records').get().n;
  } finally {
    db.close();
  }
};

const s3 = (env) => {
  const need = ['BACKUP_S3_ENDPOINT', 'BACKUP_S3_BUCKET', 'BACKUP_S3_KEY_ID', 'BACKUP_S3_SECRET'];
  const missing = need.filter((k) => !(env[k] ?? '').trim());
  if (missing.length) throw new Error(`reading the bucket needs ${missing.join(', ')}`);
  const endpoint = env.BACKUP_S3_ENDPOINT.trim().replace(/\/+$/, '');
  const region =
    (env.BACKUP_S3_REGION ?? '').trim() || (/^https?:\/\/s3\.([a-z0-9-]+)\.backblazeb2\.com$/.exec(endpoint)?.[1] ?? '');
  if (!region) throw new Error('set BACKUP_S3_REGION');
  const client = new AwsClient({
    accessKeyId: env.BACKUP_S3_KEY_ID.trim(),
    secretAccessKey: env.BACKUP_S3_SECRET.trim(),
    service: 's3',
    region,
  });
  const base = `${endpoint}/${encodeURIComponent(env.BACKUP_S3_BUCKET.trim())}`;
  const get = async (url, fetchImpl) => {
    const res = await fetchImpl(await client.sign(url, { method: 'GET' }));
    if (!res.ok) {
      const code = /<Code>([A-Za-z]{1,64})<\/Code>/.exec(await res.text().catch(() => ''))?.[1];
      throw new Error(`storage answered ${res.status}${code ? ` ${code}` : ''}`);
    }
    return res;
  };
  return {
    object: async (key, fetchImpl) =>
      (await get(`${base}/${key.split('/').map(encodeURIComponent).join('/')}`, fetchImpl)).body,
    /** Every object name under a prefix (ListObjectsV2, following continuation). */
    list: async (prefix, fetchImpl) => {
      const names = [];
      let token;
      do {
        const q = new URLSearchParams({ 'list-type': '2', prefix, ...(token ? { 'continuation-token': token } : {}) });
        const xml = await (await get(`${base}?${q}`, fetchImpl)).text();
        for (const m of xml.matchAll(/<Key>([^<]+)<\/Key>/g)) names.push(m[1]);
        token = /<IsTruncated>true<\/IsTruncated>/.test(xml)
          ? /<NextContinuationToken>([^<]+)<\/NextContinuationToken>/.exec(xml)?.[1]
          : undefined;
      } while (token);
      return names;
    },
  };
};

/**
 * Restore. `from` is { file } or { object } (a bucket object name). Writes `to` (refusing an
 * existing file unless `replace`), checks it, and with `labDir` brings the lab files back
 * from `<prefix>/<network>/lab-results/` next to the object. Returns what it did.
 */
export const restore = async ({ from, to, replace = false, labDir, env = process.env, fetchImpl = fetch, log = console.log }) => {
  const identity = identityFrom(env.AGE_IDENTITY);
  if (existsSync(to) && !replace) throw new Error(`${to} exists: add --replace to put the backup in its place`);
  const part = `${to}.restoring-${Date.now()}`;
  try {
    const source = from.file
      ? Readable.toWeb(createReadStream(from.file))
      : await s3(env).object(from.object, fetchImpl);
    await openBackup(source, identity, part);
    const records = checkDatabase(part);
    let keptAs;
    if (existsSync(to)) {
      keptAs = `${to}.before-restore-${new Date().toISOString().replace(/[:.]/g, '-')}`;
      renameSync(to, keptAs);
    }
    // A journal or WAL left by the file it replaces would be replayed into this one.
    for (const side of ['-journal', '-wal', '-shm']) if (existsSync(to + side)) renameSync(to + side, `${keptAs ?? to}${side}.old`);
    renameSync(part, to);
    log(`restored ${to}: ${records} records, integrity ok${keptAs ? `; the file it replaced is kept as ${keptAs}` : ''}`);
    let labFiles = 0;
    if (labDir) {
      if (!from.object) throw new Error('lab files come from the bucket: use --from-bucket');
      const prefix = `${from.object.split('/').slice(0, -1).join('/')}/lab-results/`;
      const bucket = s3(env);
      mkdirSync(labDir, { recursive: true, mode: 0o700 });
      for (const key of await bucket.list(prefix, fetchImpl)) {
        const id = key.slice(prefix.length);
        if (!LAB_ID.test(id)) continue;
        const dest = join(labDir, id);
        if (existsSync(dest)) continue;
        const tmp = `${dest}.tmp-restore`;
        await pipeline(Readable.fromWeb(await bucket.object(key, fetchImpl)), createWriteStream(tmp, { mode: 0o600 }));
        renameSync(tmp, dest);
        labFiles += 1;
      }
      log(`lab files: ${labFiles} brought back into ${labDir}`);
    }
    return { records, keptAs, labFiles };
  } finally {
    rmSync(part, { force: true });
  }
};

const main = async () => {
  const args = process.argv.slice(2);
  const val = (name) => {
    const i = args.indexOf(name);
    return i >= 0 ? args[i + 1] : undefined;
  };
  const file = val('--file');
  const object = val('--from-bucket');
  const to = val('--to');
  if ((!file && !object) || (file && object) || !to) {
    console.error(
      'usage: node restore.mjs (--file <backup.sqlite.gz.age> | --from-bucket <object name>) --to <db file> [--replace] [--lab-results <folder>]\n' +
        'The private key is read from AGE_IDENTITY: read -s AGE_IDENTITY; export AGE_IDENTITY',
    );
    process.exit(2);
  }
  try {
    await restore({ from: file ? { file } : { object }, to, replace: args.includes('--replace'), labDir: val('--lab-results') });
  } catch (e) {
    console.error(`NOT RESTORED: ${e.message}`);
    process.exit(1);
  }
};

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) await main();
