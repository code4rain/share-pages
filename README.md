# 공유관리 Pages (암호화)

공유관리 Android 앱이 자동으로 관리하는 저장소입니다. `_items/*.md`와 `data/*.json`은 앱이 쓰며 **암호문만** 들어 있습니다.
사이트는 GitHub Actions의 Jekyll(github-pages)로 빌드되고, 테마는 Just the Docs입니다.
내용은 브라우저에서 사이트 키를 입력해야 WebCrypto로 복호화됩니다. 직접 수정하지 마세요.

- 복호화 형식: PBKDF2-SHA256(600k) → HMAC 하위 키 → AES-256-GCM (`assets/sm/app.js`)
- 오프라인 내보내기: `node tools/decrypt.mjs <site-dir> <out-dir>` (키는 프롬프트로 입력)
