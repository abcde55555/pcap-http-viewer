// Repeater workbench — Burp Repeater style multi-tab raw HTTP editor.
// Tabs persist to localStorage; responses/history are in-memory.
import { $, $$, esc, copyText, toast, fmtSize, fmtTime } from './util.js';

const STORAGE_KEY = 'repeater.tabs.v1';
const ACTIVE_KEY = 'repeater.active.v1';

const work = {
  tabs: [],          // {id, name, scheme, host, raw, options:{...}, dirty, history:[], activeHist:-1}
  activeId: null,
};

// isWebSocket reports whether raw HTTP text is a WebSocket upgrade request.
// A request carrying Sec-WebSocket-Key + Sec-WebSocket-Version is treated as a
// WS handshake even if the Upgrade/Connection headers are missing (the dialer
// adds them automatically).
function isWebSocket(raw) {
  const head = raw.toLowerCase();
  if (head.includes('upgrade: websocket')) return true;
  return head.includes('sec-websocket-key') &&
    (head.includes('sec-websocket-version') || head.includes('upgrade:'));
}

// wsScheme maps the editor scheme (http/https/ws/wss) to a ws/wss scheme.
function wsSchemeOf(scheme, host) {
  if (scheme === 'wss' || scheme === 'https') return 'wss';
  if (scheme === 'ws' || scheme === 'http') return 'ws';
  // Auto: wss for :443, otherwise ws.
  if (/:443(\/|$)/.test(host || '')) return 'wss';
  return 'ws';
}

// ---------- persistence ----------
function save() {
  try {
    const slim = work.tabs.map((t) => ({
      id: t.id, name: t.name, scheme: t.scheme, host: t.host, raw: t.raw, options: t.options,
    }));
    localStorage.setItem(STORAGE_KEY, JSON.stringify(slim));
    if (work.activeId) localStorage.setItem(ACTIVE_KEY, work.activeId);
  } catch {}
}

function load() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) work.tabs = JSON.parse(raw);
    const a = localStorage.getItem(ACTIVE_KEY);
    if (a) work.activeId = a;
  } catch {}
  for (const t of work.tabs) { t.history = []; t.activeHist = -1; t.dirty = false; }
  if (!work.tabs.length) newTab();
  if (!work.tabs.find((t) => t.id === work.activeId)) work.activeId = work.tabs[0].id;
}

// ---------- tab management ----------
function uid() { return 'r' + Math.random().toString(36).slice(2, 9); }

function newTab(opts = {}) {
  const t = {
    id: uid(),
    name: opts.name || ('请求 ' + (work.tabs.length + 1)),
    scheme: opts.scheme || 'http',
    host: opts.host || '',
    raw: opts.raw || 'GET / HTTP/1.1\r\nHost: \r\nUser-Agent: pcap-http-viewer\r\nAccept: */*\r\n\r\n',
    options: opts.options || { timeoutMs: 15000, followRedirects: 0, insecureTLS: true, gzipBody: false, upstreamProxy: '' },
    history: [], activeHist: -1, dirty: false,
  };
  work.tabs.push(t);
  work.activeId = t.id;
  renderTabs();
  renderWork();
  save();
  return t;
}

function closeTab(id) {
  const i = work.tabs.findIndex((t) => t.id === id);
  if (i < 0) return;
  work.tabs.splice(i, 1);
  if (work.activeId === id) work.activeId = work.tabs.length ? work.tabs[Math.min(i, work.tabs.length - 1)].id : null;
  if (!work.tabs.length) newTab();
  renderTabs(); renderWork(); save();
}

function active() { return work.tabs.find((t) => t.id === work.activeId); }

function renderTabs() {
  const bar = $('#rep-tabs');
  bar.innerHTML = '';
  for (const t of work.tabs) {
    const el = document.createElement('div');
    el.className = 'rep-tab' + (t.id === work.activeId ? ' active' : '') + (t.dirty ? ' dirty' : '');
    el.innerHTML = `<span class="tab-name">${esc(t.name)}</span><span class="tab-close" title="关闭">✕</span>`;
    el.addEventListener('click', (e) => {
      if (e.target.classList.contains('tab-close')) { e.stopPropagation(); closeTab(t.id); return; }
      work.activeId = t.id; renderTabs(); renderWork(); save();
    });
    el.addEventListener('dblclick', (e) => {
      if (e.target.classList.contains('tab-close')) return;
      const name = prompt('标签名', t.name);
      if (name) { t.name = name; renderTabs(); save(); }
    });
    bar.appendChild(el);
  }
  const plus = document.createElement('button');
  plus.className = 'ghost small'; plus.textContent = '＋'; plus.title = '新建标签';
  plus.style.margin = '4px';
  plus.addEventListener('click', () => newTab());
  bar.appendChild(plus);
  $('#rep-empty').hidden = work.tabs.length === 0;
}

// ---------- work area ----------
function renderWork() {
  const root = $('#rep-work');
  const t = active();
  if (!t) { root.innerHTML = ''; root.classList.remove('active'); return; }
  root.classList.add('active');
  $('#rep-empty').hidden = true;
  const isWS = isWebSocket(t.raw);
  root.innerHTML = `
    <div class="rep-targetbar">
      <select id="rep-scheme" title="协议">
        <option value="http"${t.scheme === 'http' ? ' selected' : ''}>http</option>
        <option value="https"${t.scheme === 'https' ? ' selected' : ''}>https</option>
        <option value="ws"${t.scheme === 'ws' ? ' selected' : ''}>ws</option>
        <option value="wss"${t.scheme === 'wss' ? ' selected' : ''}>wss</option>
      </select>
      <label>目标</label>
      <input type="text" id="rep-host" value="${esc(t.host)}" placeholder="host:port（留空则用 Host 头）" spellcheck="false">
      <span class="seg" id="seg-gzip"><input type="checkbox" id="opt-gzip" ${t.options.gzipBody ? 'checked' : ''}>gzip请求体</span>
      <span class="seg"><input type="checkbox" id="opt-insecure" ${t.options.insecureTLS ? 'checked' : ''}>跳过TLS校验</span>
      <label id="lbl-redirects">重定向</label>
      <select id="opt-redirects" title="0=不跟随, 1=跟随1次, -1=全部">
        <option value="0" ${t.options.followRedirects === 0 ? 'selected' : ''}>不跟随</option>
        <option value="1" ${t.options.followRedirects === 1 ? 'selected' : ''}>跟随1次</option>
        <option value="-1" ${t.options.followRedirects === -1 ? 'selected' : ''}>全部跟随</option>
      </select>
      <label>超时(ms)</label>
      <input type="number" id="opt-timeout" value="${t.options.timeoutMs || 15000}" min="1000" step="1000">
      <button id="rep-send2" class="primary rep-send-btn" title="发送 (Ctrl+Enter)">${isWS ? '连接 WS' : '发送 ▶'}</button>
      <button id="rep-ws-close" class="ghost" hidden title="断开 WebSocket">断开</button>
      <span id="rep-status" class="rep-status"></span>
    </div>
    <div class="rep-split" id="rep-split">
      <div class="rep-pane request">
        <div class="rep-pane-head"><span>请求</span><span class="pane-actions">
          <button class="ghost small" id="rep-copyraw">复制</button>
        </span></div>
        <textarea id="rep-editor" class="rep-editor" spellcheck="false" autocomplete="off"></textarea>
      </div>
      <div class="rep-splitter" id="rep-splitter"></div>
      <div class="rep-pane response">
        <div class="rep-pane-head"><span>响应</span><span class="pane-actions">
          <select id="rep-resp-view" class="small-select">
            <option value="auto">自动</option><option value="text">文本</option>
            <option value="json">JSON</option><option value="hex">Hex</option><option value="image">图片</option>
          </select>
          <button class="ghost small" id="rep-copyresp">复制</button>
          <button class="ghost small" id="rep-downloadresp">下载</button>
        </span></div>
        <div class="rep-response" id="rep-response">
          <div class="rep-empty-hint">点「发送 ▶」或按 Ctrl+Enter 发送请求${isWS ? '；WebSocket 请求点「连接 WS」建立连接' : ''}</div>
        </div>
        <div class="ws-composer" id="ws-composer" hidden>
          <select id="ws-opcode" class="small-select" title="帧类型">
            <option value="text">文本帧</option>
            <option value="binary">二进制帧</option>
          </select>
          <textarea id="ws-input" placeholder="输入要发送的帧内容（文本或 hex:前缀的十六进制）…" spellcheck="false"></textarea>
          <button id="ws-send" class="primary">发送帧</button>
        </div>
        <div class="ws-frames" id="ws-frames" hidden></div>
      </div>
    </div>
    <div class="rep-history" id="rep-history"><div class="rep-history-head">发送历史（点击回看）</div></div>
  `;
  const editor = $('#rep-editor');
  editor.value = t.raw;

  // Wire targetbar (changes mark dirty + persist).
  const bind = (id, ev, fn) => { const el = $(id); if (el) el.addEventListener(ev, fn); };
  bind('#rep-scheme', 'change', (e) => { t.scheme = e.target.value; t.dirty = true; save(); });
  bind('#rep-host', 'input', (e) => { t.host = e.target.value.trim(); t.dirty = true; scheduleSave(); });
  bind('#opt-gzip', 'change', (e) => { t.options.gzipBody = e.target.checked; save(); });
  bind('#opt-insecure', 'change', (e) => { t.options.insecureTLS = e.target.checked; save(); });
  bind('#opt-redirects', 'change', (e) => { t.options.followRedirects = parseInt(e.target.value, 10); save(); });
  bind('#opt-timeout', 'change', (e) => { t.options.timeoutMs = parseInt(e.target.value, 10) || 15000; save(); });
  editor.addEventListener('input', () => {
    t.raw = editor.value;
    t.dirty = true;
    const first = editor.value.split('\n')[0] || '';
    const parts = first.trim().split(/\s+/);
    if (parts.length >= 2) { t.name = (parts[0] + ' ' + parts[1]).slice(0, 60); }
    // Auto-switch button label/scheme between HTTP and WebSocket.
    const ws = isWebSocket(editor.value);
    const sendBtn = $('#rep-send2');
    if (sendBtn && sendBtn.textContent.includes(ws ? '发送' : '连接')) {
      sendBtn.textContent = ws ? '连接 WS' : '发送 ▶';
    }
    if (ws) {
      const sch = $('#rep-scheme');
      if (sch && (sch.value === 'http' || sch.value === 'https')) sch.value = wsSchemeOf(sch.value, t.host);
      if (sch) t.scheme = sch.value;
    }
    scheduleSave();
  });

  const send2 = $('#rep-send2');
  if (send2) send2.onclick = isWS ? () => wsConnect(t) : send;
  const closeBtn = $('#rep-ws-close');
  if (closeBtn) closeBtn.onclick = () => wsDisconnect(t);
  $('#rep-new').onclick = () => newTab();
  $('#rep-copyraw').onclick = () => copyText(editor.value, '已复制请求');
  $('#rep-copyresp').onclick = () => { if (t.lastResp) copyText(atob(t.lastResp.bodyB64 || ''), '已复制响应体'); };
  $('#rep-downloadresp').onclick = () => {
    if (!t.lastResp) return;
    const blob = b64ToBlob(t.lastResp.bodyB64, ctFromResp(t.lastResp));
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = 'response.bin'; a.click();
  };
  $('#rep-resp-view').addEventListener('change', () => renderResponse(t));

  // Ctrl+Enter to send (or connect for WS).
  editor.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      if (isWebSocket(editor.value)) wsConnect(t); else send();
    }
  });

  makeSplitter($('#rep-split'), $('#rep-splitter'));
  renderHistory(t);
  if (t.activeHist >= 0 && t.history[t.activeHist]) renderResponse(t, t.history[t.activeHist]);
  else if (t.lastResp) renderResponse(t);
}

let saveTimer = null;
function scheduleSave() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => { renderTabs(); save(); }, 400);
}

function b64ToBlob(b64, type) {
  const bin = atob(b64 || '');
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new Blob([bytes], { type: type || 'application/octet-stream' });
}
function ctFromResp(r) {
  return (r.headers && (r.headers['Content-Type'] || r.headers['content-type'])) || '';
}

// ---------- splitter ----------
function makeSplitter(container, handle) {
  let dragging = false, startX = 0, startFlex = 0;
  const reqPane = container.querySelector('.rep-pane.request');
  handle.addEventListener('mousedown', (e) => {
    dragging = true; document.body.classList.add('resizing');
    startX = e.clientX;
    const total = container.clientWidth;
    startFlex = (reqPane.getBoundingClientRect().width) / total;
    e.preventDefault();
  });
  window.addEventListener('mousemove', (e) => {
    if (!dragging) return;
    const total = container.clientWidth;
    let frac = startFlex + (e.clientX - startX) / total;
    frac = Math.min(0.85, Math.max(0.15, frac));
    reqPane.style.flex = frac;
    container.querySelector('.rep-pane.response').style.flex = 1 - frac;
  });
  window.addEventListener('mouseup', () => { dragging = false; document.body.classList.remove('resizing'); });
}

// ---------- websocket ----------
// ensureWSHeaders guarantees the Upgrade/Connection headers are present, since
// some captured/copied handshakes omit them. The Go dialer ignores these and
// sets its own, but http.ReadRequest needs them to classify the request.
function ensureWSHeaders(raw) {
  const lower = raw.toLowerCase();
  if (!lower.includes('upgrade:')) {
    // Insert after the request line (first CRLF).
    const idx = raw.indexOf('\r\n');
    if (idx >= 0) raw = raw.slice(0, idx + 2) + 'Upgrade: websocket\r\n' + raw.slice(idx + 2);
    else raw = 'Upgrade: websocket\r\n' + raw;
  }
  if (!lower.includes('connection:')) {
    const idx = raw.indexOf('\r\n');
    if (idx >= 0) raw = raw.slice(0, idx + 2) + 'Connection: Upgrade\r\n' + raw.slice(idx + 2);
  }
  return raw;
}

async function wsConnect(t) {
  t.raw = ensureWSHeaders($('#rep-editor').value);
  $('#rep-editor').value = t.raw;
  const status = $('#rep-status');
  const btn = $('#rep-send2');
  const closeBtn = $('#rep-ws-close');
  const frames = $('#ws-frames');
  const composer = $('#ws-composer');
  status.className = 'rep-status';
  status.textContent = '连接中…';
  btn.disabled = true;
  try {
    const payload = {
      scheme: wsSchemeOf(t.scheme, t.host), host: t.host,
      raw: btoa(unescape(encodeURIComponent(t.raw))),
      options: t.options,
    };
    const res = await fetch('/api/repeater/ws/connect', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const d = await res.json();
    if (!res.ok) throw new Error(d.error || res.statusText);
    t.wsId = d.id;
    status.className = 'rep-status ok';
    status.textContent = '已连接 ' + d.target;
    btn.hidden = true; closeBtn.hidden = false;
    frames.hidden = false; composer.hidden = false;
    // Clear any previous HTTP response content so the frame log owns the pane.
    $('#rep-response').innerHTML = '';
    frames.innerHTML = `<div class="ws-frame sys">连接已建立 → ${esc(d.target)}</div>`;
    $('#rep-response').appendChild(frames);
    $('#rep-response').appendChild(composer);

    // SSE event stream.
    const es = new EventSource('/api/repeater/ws/events?id=' + encodeURIComponent(d.id));
    t.wsES = es;
    es.onmessage = (e) => {
      let ev; try { ev = JSON.parse(e.data); } catch { return; }
      if (ev.type === 'ping') return;
      if (ev.type === 'open') addWSFrame(frames, 'sys', ev.message || 'open');
      else if (ev.type === 'error') {
        addWSFrame(frames, 'err', ev.message || 'error');
        status.className = 'rep-status err'; status.textContent = 'WS 错误: ' + (ev.message || '');
      } else if (ev.type === 'close') {
        addWSFrame(frames, 'sys', '连接已关闭: ' + (ev.message || ''));
        wsResetUI(t);
      } else if (ev.type === 'sent' || ev.type === 'message') {
        addWSFrame(frames, ev.direction === 'sent' ? 'sent' : 'recv',
          ev.binary ? '(binary ' + (ev.data || '').length + ' bytes, base64)' : ev.data, ev.opcode);
      }
    };
    es.onerror = () => { addWSFrame(frames, 'err', '事件流失连接'); wsResetUI(t); };

    // Send-frame button.
    const sendFrame = $('#ws-send');
    if (sendFrame) sendFrame.onclick = () => wsSendFrame(t);
    $('#ws-input').addEventListener('keydown', (e) => {
      if (e.ctrlKey && (e.key === 'Enter' || e.key === 'r')) { e.preventDefault(); wsSendFrame(t); }
    });
    toast('WebSocket 已连接');
  } catch (err) {
    status.className = 'rep-status err';
    status.textContent = '连接失败: ' + err.message;
    btn.disabled = false;
  }
}

function wsResetUI(t) {
  const btn = $('#rep-send2'), closeBtn = $('#rep-ws-close'), composer = $('#ws-composer');
  if (btn) { btn.hidden = false; btn.disabled = false; btn.textContent = '连接 WS'; }
  if (closeBtn) closeBtn.hidden = true;
  if (composer) composer.hidden = true;
  if (t.wsES) { t.wsES.close(); t.wsES = null; }
  t.wsId = null;
}

async function wsDisconnect(t) {
  if (!t.wsId) return;
  await fetch('/api/repeater/ws/close', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: t.wsId }) });
  wsResetUI(t);
  toast('已断开');
}

async function wsSendFrame(t) {
  if (!t.wsId) return;
  const ta = $('#ws-input');
  const opcode = $('#ws-opcode').value;
  let data = ta.value;
  let binary = opcode === 'binary';
  if (data.startsWith('hex:')) { binary = true; data = hexToText(data.slice(4)); }
  try {
    const res = await fetch('/api/repeater/ws/send', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: t.wsId, data, binary }),
    });
    if (!res.ok) { toast('发送失败'); return; }
    ta.value = '';
  } catch (e) { toast('发送失败: ' + e.message); }
}

function hexToText(hex) {
  hex = hex.replace(/[^0-9a-fA-F]/g, '');
  let out = '';
  for (let i = 0; i + 1 < hex.length; i += 2) out += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
  return out;
}

function addWSFrame(container, dir, text, opcode) {
  const line = document.createElement('div');
  line.className = 'ws-frame ' + dir;
  const time = new Date().toLocaleTimeString('zh-CN', { hour12: false }) + '.' + String(Date.now() % 1000).padStart(3, '0');
  const label = dir === 'sent' ? '→ 发送' : dir === 'recv' ? '← 接收' : dir === 'err' ? '⚠ 错误' : '· 系统';
  line.innerHTML = `<span class="ws-time">${time}</span><span class="ws-dir ${dir}">${label}</span>` +
    (opcode ? `<span class="ws-op">${opcode}</span>` : '') +
    `<pre class="ws-data">${esc(text)}</pre>`;
  container.appendChild(line);
  container.scrollTop = container.scrollHeight;
}

// ---------- send ----------
async function send() {
  const t = active(); if (!t) return;
  t.raw = $('#rep-editor').value;
  const status = $('#rep-status');
  status.className = 'rep-status';
  status.textContent = '发送中…';
  $('#rep-send').disabled = true;
  const sb2 = $('#rep-send2'); if(sb2){sb2.disabled=true; sb2.textContent='发送中…';}

  const payload = {
    scheme: t.scheme, host: t.host,
    raw: btoa(unescape(encodeURIComponent(t.raw))),
    options: t.options,
  };
  try {
    const res = await fetch('/api/repeater/send', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const r = await res.json();
    t.lastResp = r;
    t.history.unshift({ sentAt: Date.now(), response: r });
    if (t.history.length > 20) t.history.pop();
    t.activeHist = 0;
    if (r.error) {
      status.className = 'rep-status err';
      status.textContent = '错误: ' + r.error;
    } else {
      status.className = 'rep-status ok';
      status.textContent = `${r.statusCode} ${(r.reason || '').replace(/^HTTP\/[\d. ]+/, '')} · ${r.durationMs}ms · ${fmtSize(r.length)}` +
        (r.remoteAddr ? ' · ' + r.remoteAddr : '');
    }
    renderHistory(t);
    renderResponse(t);
  } catch (err) {
    status.className = 'rep-status err';
    status.textContent = '请求失败: ' + err.message;
  } finally {
    $('#rep-send').disabled = false;
  const sb3 = $('#rep-send2'); if(sb3){sb3.disabled=false; sb3.textContent='发送 ▶';}
  }
}

// ---------- response rendering ----------
function renderResponse(t, hist) {
  const r = hist ? hist.response : t.lastResp;
  const box = $('#rep-response');
  if (!r) { box.innerHTML = '<div class="rep-empty-hint">点「发送 ▶」或按 Ctrl+Enter 发送请求</div>'; return; }
  const head = document.createElement('div');
  head.className = 'rep-resp-head';
  if (r.error) {
    head.innerHTML = `<span class="rep-hist-err">⚠ ${esc(r.error)}</span>`;
    box.innerHTML = ''; box.appendChild(head);
    if (r.redirects && r.redirects.length) {
      const div = document.createElement('div');
      div.className = 'rep-resp-body';
      div.textContent = '重定向: \n' + r.redirects.join('\n');
      box.appendChild(div);
    }
    return;
  }
  let headerText = `${r.proto} ${r.statusCode} ${r.reason || ''}    ${r.durationMs}ms · ${fmtSize(r.length)}` +
    (r.tlsVersion ? ' · ' + r.tlsVersion : '') + (r.remoteAddr ? ' · ' + r.remoteAddr : '');
  head.innerHTML = `<span>${esc(headerText)}</span>`;
  // copy header value row
  const hdrRows = Object.entries(r.headers || {}).map(([k, v]) =>
    `<div class="header-row"><span class="k">${esc(k)}:</span><span class="v">${esc(v)}</span></div>`).join('');
  const bodyCtn = document.createElement('div');
  bodyCtn.className = 'rep-resp-body';
  box.innerHTML = '';
  box.appendChild(head);
  const hdrCtn = document.createElement('div');
  hdrCtn.className = 'headers selectable';
  hdrCtn.innerHTML = hdrRows;
  box.appendChild(hdrCtn);
  box.appendChild(bodyCtn);

  const bytes = b64ToBytes(r.bodyB64);
  const ct = ctFromResp(r);
  const viewAs = $('#rep-resp-view').value;
  renderBodyBytes(bodyCtn, bytes, ct, viewAs, r.length);
}

function b64ToBytes(b64) {
  const bin = atob(b64 || '');
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// Render body bytes into a container. Mirrors the browser view logic.
function renderBodyBytes(container, bytes, ct, viewAs, totalLen) {
  let mode = viewAs;
  if (mode === 'auto') mode = detectMode(bytes, ct);
  container.innerHTML = '';
  if (bytes.length >= (totalLen || bytes.length) - 1 && totalLen > bytes.length) {
    const note = document.createElement('div');
    note.className = 'trunc-note';
    note.textContent = `仅显示前 ${fmtSize(bytes.length)} / 共 ${fmtSize(totalLen)}`;
    container.appendChild(note);
  }
  if (mode === 'image') {
    const img = document.createElement('img');
    img.src = URL.createObjectURL(new Blob([bytes], { type: ct || 'application/octet-stream' }));
    container.appendChild(img); return;
  }
  if (mode === 'hex') { container.innerHTML = hexView(bytes); return; }
  if (mode === 'json') {
    const text = new TextDecoder().decode(bytes);
    try { container.innerHTML = highlightJSON(JSON.stringify(JSON.parse(text), null, 2)); return; }
    catch { container.textContent = text; return; }
  }
  container.textContent = new TextDecoder().decode(bytes);
}

function detectMode(bytes, ct) {
  ct = (ct || '').toLowerCase();
  if (ct.startsWith('image/')) return 'image';
  if (ct.includes('json')) return 'json';
  if (ct.includes('text') || ct.includes('html') || ct.includes('xml') || ct.includes('javascript')) return 'text';
  if (bytes.length >= 8) {
    if (bytes[0] === 0x89 && bytes[1] === 0x50) return 'image';
    if (bytes[0] === 0xff && bytes[1] === 0xd8) return 'image';
    if (bytes[0] === 0x47 && bytes[1] === 0x49) return 'image';
  }
  const txt = new TextDecoder().decode(bytes.slice(0, 64)).trimStart();
  if (txt.startsWith('{') || txt.startsWith('[')) return 'json';
  for (let i = 0; i < Math.min(bytes.length, 512); i++) if (bytes[i] === 0) return 'hex';
  return 'text';
}

function hexView(bytes) {
  const max = Math.min(bytes.length, 64 * 1024);
  let out = '';
  for (let i = 0; i < max; i += 16) {
    const s = bytes.subarray(i, Math.min(i + 16, bytes.length));
    let hex = '', ascii = '';
    for (let j = 0; j < 16; j++) {
      if (j < s.length) { hex += s[j].toString(16).padStart(2, '0') + ' '; ascii += (s[j] >= 32 && s[j] < 127) ? String.fromCharCode(s[j]) : '.'; }
      else { hex += '   '; ascii += ' '; }
    }
    out += `<div class="hex-line"><span class="hex-off">${i.toString(16).padStart(8, '0')}</span>  ${hex} ${ascii}</div>`;
  }
  if (bytes.length > max) out += `\n… (共 ${fmtSize(bytes.length)})`;
  return out;
}

function highlightJSON(s) {
  s = esc(s);
  return s.replace(/("(\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, (m) => {
    let cls = 'num';
    if (/^"/.test(m)) cls = /:$/.test(m) ? 'key' : 'str';
    else if (/true|false/.test(m)) cls = 'bool';
    else if (/null/.test(m)) cls = 'null';
    return `<span class="${cls}">${m}</span>`;
  });
}

// ---------- history ----------
function renderHistory(t) {
  const box = $('#rep-history');
  if (!box) return;
  box.innerHTML = '<div class="rep-history-head">发送历史（点击回看）</div>';
  t.history.forEach((h, i) => {
    const r = h.response;
    const row = document.createElement('div');
    row.className = 'rep-hist-row' + (i === t.activeHist ? ' active' : '');
    const sc = r.statusCode ? Math.floor(r.statusCode / 100) : 0;
    const tStr = new Date(h.sentAt).toLocaleTimeString('zh-CN', { hour12: false });
    row.innerHTML = `<span class="rep-hist-time">${tStr}</span>` +
      (r.error
        ? `<span class="rep-hist-err">${esc(r.error.slice(0, 60))}</span>`
        : `<span class="rep-hist-status s${sc}">${r.statusCode || ''}</span>
           <span class="rep-hist-dur">${r.durationMs}ms</span>
           <span class="rep-hist-len">${fmtSize(r.length)}</span>`);
    row.addEventListener('click', () => { t.activeHist = i; renderHistory(t); renderResponse(t, h); });
    box.appendChild(row);
  });
}

// ---------- public API ----------
export function init() {
  load();
  renderTabs();
  renderWork();
  $$('.mod-btn').forEach((b) => b.addEventListener('click', () => switchMod(b.dataset.mod)));
  $('#rep-send').onclick = send;
  $('#rep-new').onclick = () => newTab();
}

export function switchMod(mod) {
  $$('.mod-btn').forEach((b) => b.classList.toggle('active', b.dataset.mod === mod));
  $('#mod-browser').hidden = mod !== 'browser';
  $('#mod-repeater').hidden = mod !== 'repeater';
  $('#browser-tools').hidden = mod !== 'browser';
  $('#repeater-tools').hidden = mod !== 'repeater';
  if (mod === 'repeater') renderWork();
}

// seedFromTx: called from the browser list's context menu.
export async function seedFromTx(id) {
  switchMod('repeater');
  try {
    const res = await fetch('/api/repeater/seed?id=' + id);
    if (!res.ok) { toast('加载请求失败'); return; }
    const d = await res.json();
    const raw = decodeURIComponent(escape(atob(d.rawBase64)));
    newTab({ name: (d.method || 'REQ') + ' ' + (d.url || '/'), scheme: d.scheme, host: d.host, raw });
    toast('已发送到重放器');
  } catch (e) {
    toast('发送到重放器失败: ' + e.message);
  }
}
