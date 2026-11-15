/* 공유관리 Pages — browser-side decryption + rendering. No innerHTML anywhere: all content is built as DOM text. */
(function () {
  'use strict';

  // ---------- crypto (must match app/src/main/java/.../pages/PagesCrypto.kt) ----------
  var te = new TextEncoder();
  var td = new TextDecoder('utf-8', { fatal: true });

  function unb64u(s) {
    if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error('bad base64');
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function b64u(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  var subtle = (globalThis.crypto || {}).subtle;

  /** passphrase + site.json kdf → raw AES key bytes (encKey = HMAC(master, "sm-pages/v1/enc")). */
  async function deriveEncKey(passphrase, kdf) {
    if (!kdf || kdf.name !== 'PBKDF2' || kdf.hash !== 'SHA-256') throw new Error('unsupported kdf');
    var iter = kdf.iterations | 0;
    if (iter < 100000 || iter > 10000000) throw new Error('bad iterations');
    var pw = te.encode(String(passphrase).normalize('NFC'));
    var base = await subtle.importKey('raw', pw, 'PBKDF2', false, ['deriveBits']);
    var master = await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: unb64u(kdf.salt), iterations: iter }, base, 256);
    var hk = await subtle.importKey('raw', master, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await subtle.sign('HMAC', hk, te.encode('sm-pages/v1/enc')));
  }
  async function importKey(raw) {
    return subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['decrypt']);
  }
  async function decrypt(key, envelope, context) {
    var p = String(envelope).trim().split('.');
    if (p.length !== 3 || p[0] !== 'v1') throw new Error('bad envelope');
    var iv = unb64u(p[1]);
    if (iv.length !== 12) throw new Error('bad iv');
    var pt = await subtle.decrypt(
      { name: 'AES-GCM', iv: iv, additionalData: te.encode('sm-pages/v1|' + context), tagLength: 128 },
      key, unb64u(p[2]));
    return td.decode(pt);
  }
  globalThis.SMCrypto = { deriveEncKey: deriveEncKey, importKey: importKey, decrypt: decrypt, b64u: b64u, unb64u: unb64u };
  if (typeof document === 'undefined') return;

  // ---------- page ----------
  if (window.top !== window.self) { document.documentElement.style.display = 'none'; return; } // no framing
  var STORE = 'sm-pages-key-v1';
  var baseMeta = document.querySelector('meta[name="sm-base"]');
  var BASE = baseMeta ? baseMeta.getAttribute('content') || '' : '';

  function el(tag, attrs, children) {
    var n = document.createElement(tag);
    if (attrs) for (var k in attrs) {
      if (k === 'text') n.textContent = attrs[k];
      else if (k === 'cls') n.className = attrs[k];
      else n.setAttribute(k, attrs[k]);
    }
    (children || []).forEach(function (c) { if (c != null) n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); });
    return n;
  }
  function safeHref(u) {
    try { var x = new URL(u); return (x.protocol === 'https:' || x.protocol === 'http:') ? x.href : null; } catch (e) { return null; }
  }
  function extLink(href, text) {
    var h = safeHref(href);
    if (!h) return document.createTextNode(text);
    return el('a', { href: h, rel: 'noopener noreferrer nofollow', target: '_blank', referrerpolicy: 'no-referrer', text: text });
  }
  async function fetchJson(path) {
    var r = await fetch(BASE + path, { cache: 'no-cache', credentials: 'omit', referrerPolicy: 'no-referrer' });
    if (!r.ok) throw new Error(path + ' ' + r.status);
    return r.json();
  }

  function storedKey() {
    try { return sessionStorage.getItem(STORE) || localStorage.getItem(STORE); } catch (e) { return null; }
  }
  function saveKey(raw, remember) {
    try {
      sessionStorage.setItem(STORE, b64u(raw));
      if (remember) localStorage.setItem(STORE, b64u(raw)); else localStorage.removeItem(STORE);
    } catch (e) { /* private mode: key lives only in memory for this page */ }
  }
  function forgetKey() {
    try { sessionStorage.removeItem(STORE); localStorage.removeItem(STORE); } catch (e) {}
  }

  // ---------- tiny, safe Markdown → DOM ----------
  var INLINE = /(\\[\\`*_\[\]()#>!-])|(`[^`\n]+`)|(\*\*[^*\n]+\*\*)|(<https?:\/\/[^>\s]+>)|(\[[^\]\n]+\]\(https?:\/\/[^)\s]+\))|(https?:\/\/[^\s<>()]+[^\s<>().,;:!?'"])/g;
  function inline(parent, text) {
    var last = 0, m;
    INLINE.lastIndex = 0;
    while ((m = INLINE.exec(text))) {
      if (m.index > last) parent.appendChild(document.createTextNode(text.slice(last, m.index)));
      var t = m[0];
      if (m[1]) parent.appendChild(document.createTextNode(t.slice(1)));
      else if (m[2]) parent.appendChild(el('code', { text: t.slice(1, -1) }));
      else if (m[3]) { var b = el('strong'); inline(b, t.slice(2, -2)); parent.appendChild(b); }
      else if (m[4]) parent.appendChild(extLink(t.slice(1, -1), t.slice(1, -1)));
      else if (m[5]) { var i = t.indexOf(']('); parent.appendChild(extLink(t.slice(i + 2, -1), t.slice(1, i))); }
      else parent.appendChild(extLink(t, t));
      last = m.index + t.length;
    }
    if (last < text.length) parent.appendChild(document.createTextNode(text.slice(last)));
  }
  function renderMarkdown(md) {
    var root = el('div', { cls: 'sm-md' });
    var lines = String(md).replace(/\r\n?/g, '\n').split('\n');
    var i = 0, para = null, list = null;
    function close() { para = null; list = null; }
    while (i < lines.length) {
      var line = lines[i];
      var fence = /^\s*```/.test(line);
      if (fence) {
        close();
        var code = [];
        i++;
        while (i < lines.length && !/^\s*```/.test(lines[i])) code.push(lines[i++]);
        i++;
        root.appendChild(el('pre', null, [el('code', { text: code.join('\n') })]));
        continue;
      }
      var h = /^(#{1,6})\s+(.*)$/.exec(line);
      var ul = /^\s*[-*•]\s+(.*)$/.exec(line);
      var ol = /^\s*(\d{1,3})[.)]\s+(.*)$/.exec(line);
      if (!line.trim()) { close(); }
      else if (h) { close(); var hn = el('h' + Math.min(6, h[1].length + 1)); inline(hn, h[2]); root.appendChild(hn); }
      else if (ul || ol) {
        var tag = ul ? 'ul' : 'ol';
        if (!list || list.tagName.toLowerCase() !== tag) { para = null; list = el(tag); root.appendChild(list); }
        var li = el('li'); inline(li, ul ? ul[1] : ol[2]); list.appendChild(li);
      } else {
        list = null;
        if (!para) { para = el('p'); root.appendChild(para); } else para.appendChild(el('br'));
        inline(para, line);
      }
      i++;
    }
    return root;
  }

  // ---------- views ----------
  var root = document.getElementById('sm-root');
  if (!root) return;
  var kind = root.getAttribute('data-kind');

  function setStatus(msg, isError) {
    var s = root.querySelector('.sm-status');
    if (s) { s.textContent = msg || ''; s.classList.toggle('sm-error', !!isError); }
  }

  function toolbar() {
    var lock = el('button', { type: 'button', cls: 'btn btn-outline sm-lock', text: '잠그기' });
    lock.addEventListener('click', function () { forgetKey(); location.reload(); });
    var home = el('a', { href: BASE + '/', cls: 'btn btn-outline', text: '목록' });
    return el('div', { cls: 'sm-toolbar' }, [kind === 'item' ? home : null, lock]);
  }

  function showLockForm(site, errorMsg) {
    root.textContent = '';
    var input = el('input', { type: 'password', id: 'sm-pass', autocomplete: 'current-password', spellcheck: 'false', autocapitalize: 'off', placeholder: '사이트 키' });
    var remember = el('input', { type: 'checkbox', id: 'sm-remember' });
    var btn = el('button', { type: 'submit', cls: 'btn btn-primary', text: '열기' });
    var form = el('form', { cls: 'sm-lockform', autocomplete: 'on' }, [
      el('h2', { text: '🔒 키가 필요합니다' }),
      el('p', { cls: 'sm-muted', text: '이 보관함의 내용은 암호화되어 있습니다. 공유관리 앱에서 정한 사이트 키를 입력하세요.' }),
      el('input', { type: 'text', name: 'username', autocomplete: 'username', value: 'share-manager', cls: 'sm-hidden', 'aria-hidden': 'true', tabindex: '-1' }),
      el('label', { for: 'sm-pass', cls: 'sm-label', text: '사이트 키' }), input,
      el('label', { cls: 'sm-check' }, [remember, ' 이 기기에서 기억하기 (공용 기기에서는 끄세요)']),
      btn,
      el('p', { cls: 'sm-status', role: 'status', 'aria-live': 'polite' })
    ]);
    form.addEventListener('submit', async function (ev) {
      ev.preventDefault();
      if (!input.value) return;
      btn.disabled = true; setStatus('키 확인 중…');
      try {
        var raw = await deriveEncKey(input.value, site.kdf);
        var key = await importKey(raw);
        if (await decrypt(key, site.check, 'check') !== 'sm-pages-check-v1') throw new Error('check');
        saveKey(raw, remember.checked);
        input.value = '';
        await render(key);
      } catch (e) {
        btn.disabled = false;
        setStatus('키가 맞지 않습니다.', true);
        input.select();
      }
    });
    root.appendChild(form);
    if (errorMsg) setStatus(errorMsg, true);
    input.focus();
  }

  function fmtDate(ms) {
    var d = new Date(ms);
    return d.getFullYear() + '. ' + (d.getMonth() + 1) + '. ' + d.getDate() + '.';
  }
  function fmtTime(ms) {
    var d = new Date(ms);
    return ('0' + d.getHours()).slice(-2) + ':' + ('0' + d.getMinutes()).slice(-2);
  }

  async function renderHome(key) {
    var file = await fetchJson('/data/index.json');
    var data = JSON.parse(await decrypt(key, file.payload, 'index'));
    var items = Array.isArray(data.items) ? data.items : [];
    root.textContent = '';
    root.appendChild(toolbar());
    var q = el('input', { type: 'search', cls: 'sm-search', placeholder: '제목·사이트·요약·분류 검색', 'aria-label': '검색' });
    var arch = el('input', { type: 'checkbox' });
    var count = el('p', { cls: 'sm-muted sm-count' });
    var list = el('div', { cls: 'sm-list' });
    root.appendChild(el('h1', { text: '보관함' }));
    root.appendChild(el('div', { cls: 'sm-filters' }, [q, el('label', { cls: 'sm-check' }, [arch, ' 아카이브 포함'])]));
    root.appendChild(count);
    root.appendChild(list);
    function draw() {
      var needle = q.value.trim().toLowerCase();
      list.textContent = '';
      var shown = 0, lastDay = '';
      items.forEach(function (it) {
        if (it.a && !arch.checked) return;
        var hay = [it.t, it.h, it.s].concat(it.c || []).join(' ').toLowerCase();
        if (needle && hay.indexOf(needle) < 0) return;
        if (!/^[0-9a-f]{24}$/.test(it.n || '')) return;
        var day = fmtDate(it.d);
        if (day !== lastDay) { list.appendChild(el('h2', { cls: 'sm-day', text: day })); lastDay = day; }
        var cats = (it.c || []).map(function (c) { return el('span', { cls: 'label label-blue', text: c }); });
        list.appendChild(el('a', { cls: 'sm-card' + (it.a ? ' sm-archived' : ''), href: BASE + '/i/' + it.n + '/' }, [
          el('span', { cls: 'sm-card-title', text: it.t || '(제목 없음)' }),
          el('span', { cls: 'sm-card-meta', text: [it.h, fmtTime(it.d)].filter(Boolean).join(' · ') }),
          it.s ? el('span', { cls: 'sm-card-snippet', text: it.s }) : null,
          cats.length ? el('span', { cls: 'sm-card-cats' }, cats) : null
        ]));
        shown++;
      });
      count.textContent = shown + '개 항목' + (shown !== items.length ? ' (전체 ' + items.length + '개)' : '');
    }
    q.addEventListener('input', draw);
    arch.addEventListener('change', draw);
    draw();
  }

  async function renderItem(key) {
    var name = root.getAttribute('data-name') || '';
    var payload = root.getAttribute('data-payload') || '';
    var item = JSON.parse(await decrypt(key, payload, 'item:' + name));
    document.title = (item.title || '항목') + ' · 공유관리';
    root.textContent = '';
    root.appendChild(toolbar());
    var url = safeHref(item.url || '');
    if (url) {
      root.appendChild(el('p', null, [el('a', { href: url, cls: 'btn btn-primary', rel: 'noopener noreferrer nofollow', target: '_blank', referrerpolicy: 'no-referrer', text: '원본 열기 ↗' })]));
    }
    root.appendChild(renderMarkdown(item.md || ''));
  }

  async function render(key) {
    if (kind === 'home') await renderHome(key); else await renderItem(key);
  }

  async function start() {
    var site;
    try { site = await fetchJson('/data/site.json'); }
    catch (e) { root.textContent = '사이트 설정(data/site.json)을 읽지 못했습니다. 앱에서 동기화가 끝났는지 확인하세요.'; return; }
    if (!subtle) { root.textContent = '이 브라우저는 WebCrypto(HTTPS)를 지원하지 않습니다.'; return; }
    var saved = storedKey();
    if (saved) {
      try {
        var key = await importKey(unb64u(saved));
        if (await decrypt(key, site.check, 'check') === 'sm-pages-check-v1') { await render(key); return; }
      } catch (e) { /* stale key (site key changed) or data error */ }
      forgetKey();
      showLockForm(site, '저장된 키가 더 이상 맞지 않습니다. 다시 입력하세요.');
      return;
    }
    showLockForm(site);
  }
  start().catch(function (e) {
    root.textContent = '';
    root.appendChild(el('p', { cls: 'sm-error', text: '내용을 열지 못했습니다: ' + (e && e.message ? e.message : e) }));
    root.appendChild(toolbar());
  });
})();
