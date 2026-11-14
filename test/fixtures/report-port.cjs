// Preload for test/registry-attestation.test.mjs (node -r): the server, started with PORT=0,
// says on stdout which port it was given, so the test needs no guess at a free one. A random
// port could be one already in use (it was picked from 20000-40000, which overlaps the
// range the system hands out to outgoing connections).
// SPDX-License-Identifier: Apache-2.0
const http = require('node:http');
const listen = http.Server.prototype.listen;
http.Server.prototype.listen = function (...args) {
  this.once('listening', () => process.stdout.write(`listening on port ${this.address().port}\n`));
  return listen.apply(this, args);
};
