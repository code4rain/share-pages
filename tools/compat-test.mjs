// Kotlin ↔ browser compatibility check. Usage: node compat-test.mjs <fixture.json> <out.json>
// fixture: {pass, kdf, check, cases:[{context, envelope, expected}]}; out: {encKey, envelopes:[{context, envelope, plaintext}]}
import { readFileSync, writeFileSync } from 'node:fs';
import { SMCrypto, encryptForTest } from './smcrypto-node.mjs';

const [fixturePath, outPath] = process.argv.slice(2);
const fx = JSON.parse(readFileSync(fixturePath, 'utf8'));
const raw = await SMCrypto.deriveEncKey(fx.pass, fx.kdf);
const key = await SMCrypto.importKey(raw);
let failures = 0;
const chk = await SMCrypto.decrypt(key, fx.check, 'check');
if (chk !== 'sm-pages-check-v1') { console.error('check mismatch'); failures++; }
for (const c of fx.cases) {
  const got = await SMCrypto.decrypt(key, c.envelope, c.context);
  if (got !== c.expected) { console.error('mismatch for', c.context); failures++; }
  try { await SMCrypto.decrypt(key, c.envelope, c.context + 'x'); console.error('wrong context accepted'); failures++; } catch (e) {}
}
// Same key without its leading/trailing spaces must NOT open (no trimming on either side).
if (fx.pass !== fx.pass.trim()) {
  try {
    const trimmed = await SMCrypto.importKey(await SMCrypto.deriveEncKey(fx.pass.trim(), fx.kdf));
    await SMCrypto.decrypt(trimmed, fx.check, 'check'); console.error('trimmed key accepted'); failures++;
  } catch (e) {}
}
// NFD spelling of the same key must open (NFC normalization on both sides).
if (fx.passNfd) {
  const nfd = await SMCrypto.importKey(await SMCrypto.deriveEncKey(fx.passNfd, fx.kdf));
  if (await SMCrypto.decrypt(nfd, fx.check, 'check') !== 'sm-pages-check-v1') { console.error('NFD key rejected'); failures++; }
}
try {
  const wrong = await SMCrypto.importKey(await SMCrypto.deriveEncKey(fx.pass + '!', fx.kdf));
  await SMCrypto.decrypt(wrong, fx.check, 'check'); console.error('wrong key accepted'); failures++;
} catch (e) {}
const samples = ['한국어 번역 ✓ <script>alert(1)</script>', '', 'x'.repeat(5000)];
const envelopes = [];
for (const [i, s] of samples.entries()) envelopes.push({ context: 'item:js' + i, envelope: await encryptForTest(raw, s, 'item:js' + i), plaintext: s });
writeFileSync(outPath, JSON.stringify({ encKey: SMCrypto.b64u(raw), envelopes }));
if (failures) { console.error(failures + ' failure(s)'); process.exit(1); }
console.log('compat ok: ' + fx.cases.length + ' cases');
