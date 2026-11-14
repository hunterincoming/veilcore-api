// Child process for test/sealed-records.test.mjs: the registry on a database FILE (DB_PATH,
// set by the test), so the test can read the bytes it leaves on disk. Sends { port } once
// listening; on 'close', stops answering, checkpoints and closes the database, sends
// 'closed' and exits. Everything it prints goes to the test, which checks it too.
// SPDX-License-Identifier: Apache-2.0
import { createRequire } from 'node:module';

process.env.VEILCORE_OTS = 'off';
const require = createRequire(import.meta.url);
const { app, db } = require('../../server.js');

const server = app.listen(0, '127.0.0.1');
server.once('listening', () => process.send({ port: server.address().port }));
process.on('message', (m) => {
  if (m !== 'close') return;
  server.close();
  server.closeAllConnections?.();
  if (db.pragma('journal_mode', { simple: true }) === 'wal') db.pragma('wal_checkpoint(TRUNCATE)');
  db.close();
  process.send('closed', () => process.exit(0));
});
