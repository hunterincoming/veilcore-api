// Child process for lab-results.test.mjs, run under a file-size limit: stores a 4 MB result
// in a folder store and prints whether that failed and what was left in the folder.
// SPDX-License-Identifier: Apache-2.0
import { readdirSync } from 'node:fs';
import { folderFiles } from '../../lineage/lab-results.mjs';

const dir = process.argv[2];
const files = folderFiles(dir);
let error = null;
try {
  files.put(`LR-${'F'.repeat(32)}`, Buffer.alloc(4 * 1024 * 1024, 0x61));
} catch (e) {
  error = `${e.code}: ${e.message}`;
}
console.log(JSON.stringify({ error, left: readdirSync(dir) }));
