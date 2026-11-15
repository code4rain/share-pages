// Offline export: decrypt every item of a checked-out site into readable Markdown.
// Usage: node tools/decrypt.mjs <site-dir> <out-dir>     (the site key is read from stdin, not argv)
import { readFileSync, readdirSync, writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import readline from 'node:readline/promises';
import { SMCrypto } from './smcrypto-node.mjs';

const [siteDir = '.', outDir = 'decrypted'] = process.argv.slice(2);
const site = JSON.parse(readFileSync(path.join(siteDir, 'data', 'site.json'), 'utf8'));
const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
const pass = await rl.question('사이트 키: ');
rl.close();
const key = await SMCrypto.importKey(await SMCrypto.deriveEncKey(pass, site.kdf));
if (await SMCrypto.decrypt(key, site.check, 'check') !== 'sm-pages-check-v1') { console.error('키가 맞지 않습니다'); process.exit(1); }
mkdirSync(outDir, { recursive: true });
let n = 0;
for (const f of readdirSync(path.join(siteDir, '_items'))) {
  const m = /^([0-9a-f]{24})\.md$/.exec(f);
  if (!m) continue;
  const fm = readFileSync(path.join(siteDir, '_items', f), 'utf8');
  const env = /^sm_payload: "([^"]+)"$/m.exec(fm)?.[1];
  if (!env) continue;
  const item = JSON.parse(await SMCrypto.decrypt(key, env, 'item:' + m[1]));
  writeFileSync(path.join(outDir, m[1] + '.md'), item.md);
  n++;
}
console.error(n + '개 항목을 ' + outDir + '에 저장했습니다');
