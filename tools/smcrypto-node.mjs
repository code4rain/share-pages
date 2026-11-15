// Loads the exact browser crypto code (assets/sm/app.js) into Node so tests and the CLI share it.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const src = readFileSync(path.join(here, '..', 'assets', 'sm', 'app.js'), 'utf8');
vm.runInThisContext(src, { filename: 'app.js' });
export const SMCrypto = globalThis.SMCrypto;

export async function encryptForTest(rawKey, plaintext, context) {
  const key = await crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode('sm-pages/v1|' + context), tagLength: 128 },
    key, new TextEncoder().encode(plaintext)));
  return 'v1.' + SMCrypto.b64u(iv) + '.' + SMCrypto.b64u(ct);
}
