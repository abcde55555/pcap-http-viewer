// Main UI logic: virtual list, request/response detail, body rendering, filters,
// and the rule-management modal. Heavy filtering runs in worker-filter.js.
import { $, $$, esc, fmtSize, fmtTime, toast, copyText, truncate } from './util.js';
import * as Repeater from './repeater.js';

const ROW_H = 26;
const SEVRANK = { info: 1, low: 2, medium: 3, high: 4, critical: 5 };

const state = {
  all: new Map(),          // id -> metadata
  order: [],               // ids in pcap order
  filtered: [],            // Uint32Array after query
  selectedId: null,
  detailCache: new Map(),  // id -> detail JSON
  worker: null,
  queryTimer: null,
  timeBounds: { min: 0, max: 0 },
  sortKey: 't',
  sortDir: 'asc',
};

function fmtBytes(n) { return fmtSize(n); }

// ---------- data loading ----------
async function loadSessions() {
  const res = await fetch('/api/sessions');
  // NDJSON streaming parser — feed the worker as lines arrive for fast first paint.
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let buf = '';
  let count = 0;
  state.all.clear();
  state.order = [];
  state.detailCache.clear();
  state.selectedId = null;
  scrollEl.innerHTML = '';
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      if (!line) continue;
      const m = JSON.parse(line);
      state.all.set(m.id, m);
      state.order.push(m.id);
      count++;
    }
    if (count % 200 === 0) {
      // Throttle re-render.
    }
  }
  // Establish time bounds for the datetime inputs.
  let min = Infinity, max = 0;
  for (const m of state.all.values()) {
    if (m.t) { if (m.t < min) min = m.t; if (m.t > max) max = m.t; }
  }
  if (isFinite(min)) {
    state.timeBounds = { min, max };
    $('#time-from').min = toLocalInput(min);
    $('#time-to').max = toLocalInput(max);
  }
  populateHosts();
  // Send metadata to worker once.
  const items = Array.from(state.all.values());
  state.worker.postMessage({ type: 'data', items });
  runQuery();
  // Update the global findings badge from metadata.
  let total = 0;
  for (const m of state.all.values()) total += m.fn || 0;
  $('#findings-total').textContent = total ? total : '';
}

function toLocalInput(ms) {
  const d = new Date(ms);
  d.setSeconds(0, 0);
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function populateHosts() {
  const hosts = new Set();
  for (const m of state.all.values()) {
    if (m.h) hosts.add(m.h);
    else if (m.sni) hosts.add(m.sni);
  }
  const dl = $('#host-list');
  dl.innerHTML = '';
  for (const h of hosts) {
    const o = document.createElement('option');
    o.value = h;
    dl.appendChild(o);
  }
}

// ---------- virtual list ----------
const scrollEl = $('#list-scroll');
function renderList() {
  const ids = state.filtered;
  const total = ids.length;
  const scrollTop = scrollEl.scrollTop;
  const viewH = scrollEl.clientHeight;
  const startIdx = Math.max(0, Math.floor(scrollTop / ROW_H) - 5);
  const endIdx = Math.min(total, Math.ceil((scrollTop + viewH) / ROW_H) + 5);

  // Set spacer height.
  scrollEl.style.content = '';
  let html = `<div style="height:${total * ROW_H}px;position:relative;">`;
  for (let i = startIdx; i < endIdx; i++) {
    const id = ids[i];
    const m = state.all.get(id);
    if (!m) continue;
    html += renderRow(m, i);
  }
  html += '</div>';
  scrollEl.innerHTML = html;

  $$('#list-scroll .row').forEach((el) => {
    el.addEventListener('click', () => selectSession(parseInt(el.dataset.id)));
  });
}

function renderRow(m, i) {
  const sel = m.id === state.selectedId ? ' selected' : '';
  const tls = m.tls ? ' tls' : '';
  const sev = m.sev ? `<span class="col-sev ${m.sev}" title="${m.sev}"></span>` : '<span class="col-sev"></span>';
  const findBadge = m.fn ? ` <span class="finding-tag ${m.sev || ''}" title="${m.fn} 命中">${m.fn}</span>` : '';
  const method = m.tls ? 'TLS' : (m.m || '');
  const host = m.h || m.sni || '';
  let url = m.u || '';
  if (m.tls) url = m.sni ? `🔒 ${m.sni}` : '🔒 (encrypted)';
  const statusCls = m.s ? `s-${Math.floor(m.s / 100)}` : '';
  const size = m.ps ? fmtSize(m.ps) : (m.rs ? fmtSize(m.rs) : '');
  const ipTip = (m.ip || m.dip) ? `\n${m.ip}:${m.sp || ''} → ${m.dip || ''}:${m.dp || ''}` : '';
  return `<div class="row${sel}${tls}" data-id="${m.id}" title="${esc(method)} ${esc(host)}${esc(url)}${ipTip}" style="position:absolute;top:${i * ROW_H}px;left:0;right:0;height:${ROW_H}px;">
    ${sev}
    <span class="col-time">${fmtTime(m.t)}</span>
    <span class="col-method method-${method}">${esc(method)}</span>
    <span class="col-host" title="${esc(host)}">${esc(host)}</span>
    <span class="col-url" title="${esc(url)}">${esc(url)}${findBadge}</span>
    <span class="col-status ${statusCls}">${m.s || ''}</span>
    <span class="col-size">${size}</span>
    <span class="col-dur">${m.d ? m.d + 'ms' : ''}</span>
  </div>`;
}

scrollEl.addEventListener('scroll', () => {
  requestAnimationFrame(renderList);
});

// ---------- selection / detail ----------
async function selectSession(id) {
  state.selectedId = id;
  $$('#list-scroll .row').forEach((r) => r.classList.toggle('selected', parseInt(r.dataset.id) === id));
  $('#empty-detail').hidden = true;
  $('#detail').hidden = false;
  const detail = await loadDetail(id);
  renderDetail(detail);
}

async function loadDetail(id) {
  if (state.detailCache.has(id)) return state.detailCache.get(id);
  const res = await fetch('/api/session/' + id);
  const d = await res.json();
  state.detailCache.set(id, d);
  return d;
}

function renderDetail(d) {
  // Title & status lines
  // Build a network info line shown in both panels: src -> dst.
  const src = d.srcIp ? `${d.srcIp}:${d.srcPort ?? ''}` : '';
  const dst = d.dstIp ? `${d.dstIp}:${d.dstPort ?? ''}` : '';
  const netLine = (src && dst)
    ? `<div class="net-info"><span class="net-src" title="源">${esc(src)}</span> <span class="net-arrow">→</span> <span class="net-dst" title="目的">${esc(dst)}</span> <span class="net-meta">流 #${d.streamId}${d.durationMs ? ' · ' + d.durationMs + 'ms' : ''}${d.requestSize || d.responseSize ? ' · ↑' + fmtSize(d.requestSize) + ' ↓' + fmtSize(d.responseSize) : ''}</span></div>`
    : '';

  if (d.tls) {
    $('#detail-title').textContent = `TLS · ${d.sni || ''} · ${d.tlsVersion || ''}`;
    $('#req-line').textContent = `(加密会话: ${d.sni || '未知 SNI'}) 源 ${d.srcIp}:${d.srcPort} → 目的 ${d.dstIp}:${d.dstPort} · ${d.tlsVersion || ''}`;
    $('#resp-line').textContent = '无可展示的明文内容 (未提供 TLS 密钥日志)';
    $('#req-headers').innerHTML = '<div class="header-section">网络</div>' + netLine;
    $('#resp-headers').innerHTML = '';
    $('#req-body').innerHTML = '<div class="loading">此会话为 TLS 加密。当前版本不展示密文。<br>SNI: ' + esc(d.sni || '') + ' · ' + esc(d.tlsVersion || '') + '</div>';
    $('#resp-body').innerHTML = '';
    return;
  }
  const path = d.url || '';
  $('#detail-title').textContent = `${d.method || ''} ${d.host || ''}${path}`;
  renderReqLine(d.method, path, d.httpVersion);
  $('#resp-line').textContent = `${d.httpVersion} ${d.statusCode || ''} ${d.reasonPhrase || ''}  ·  ${fmtSize(d.responseSize)}`;

  $('#req-headers').innerHTML = '<div class="header-section">网络</div>' + netLine +
    renderHeaderSections('请求头', d.requestHeader, d.findings, 'req.header');
  $('#resp-headers').innerHTML = '<div class="header-section">网络</div>' + netLine +
    renderHeaderSections('响应头', d.responseHeader, d.findings, 'resp.header');

  // Findings summary: bounded height, grouped by rule with actual matched values.
  renderFindingsBar(d);

  loadBody(d, 'req');
  loadBody(d, 'resp');
}

// renderReqLine shows the request line; if the URL overflows (hits the right
// edge), an expand caret appears and clicking toggles full wrap display.
let reqLineExpanded = false;
function renderReqLine(method, path, version) {
  const el = $('#req-line');
  el.classList.remove('wrap');
  reqLineExpanded = false;
  const line = `${method || ''} ${path || ''} ${version || ''}`.trim();
  el.innerHTML = '';
  const text = document.createElement('span');
  text.className = 'req-line-text';
  text.textContent = line;
  el.appendChild(text);
  const caret = document.createElement('button');
  caret.className = 'req-expand ghost small';
  caret.title = '展开 / 收起完整 URL';
  caret.textContent = '↵';
  caret.hidden = true;
  el.appendChild(caret);
  caret.addEventListener('click', (e) => {
    e.stopPropagation();
    reqLineExpanded = !reqLineExpanded;
    el.classList.toggle('wrap', reqLineExpanded);
    caret.textContent = reqLineExpanded ? '⤢' : '↵';
  });
  // Decide overflow after layout.
  const check = () => { caret.hidden = text.scrollWidth <= el.clientWidth + 1; };
  requestAnimationFrame(check);
  // Re-check when the detail pane is resized (split drag / window resize).
  if (typeof ResizeObserver !== 'undefined') {
    const ro = new ResizeObserver(check);
    ro.observe(el);
    // Disconnect when a new request line is rendered.
    const prev = el._ro;
    el._ro = ro;
    if (prev) prev.disconnect();
  }
}

function renderFindingsBar(d) {
  const bar = $('#findings-bar');
  if (!d.findings || d.findings.length === 0) {
    bar.hidden = true;
    bar.innerHTML = '';
    return;
  }
  // Group findings by rule.
  const byRule = new Map();
  for (const f of d.findings) {
    if (!byRule.has(f.ruleId)) byRule.set(f.ruleId, { name: f.name, severity: f.severity, items: [] });
    byRule.get(f.ruleId).items.push(f);
  }
  let html = '<div class="fb-head">⚠ 敏感信息命中 <span class="fb-count">' + d.findings.length + '</span></div>';
  for (const [, g] of byRule) {
    const values = g.items.map((f) => {
      const loc = f.location || '';
      const where = loc.startsWith('req') ? '请' : loc.startsWith('resp') ? '响' : '';
      const val = f.match || f.snippet || '(header)';
      return `<li><span class="fb-where">${where}</span><code title="${esc(f.snippet || '')}">${esc(truncate(val, 80))}</code></li>`;
    }).join('');
    html += `<div class="fb-group">
      <span class="finding-tag ${g.severity}">${esc(g.name)}</span>
      <ul class="fb-values">${values}</ul>
    </div>`;
  }
  bar.innerHTML = html;
  bar.hidden = false;
}

// ---------- copy / toast (helpers imported from util.js) ----------

// Copy a single header value (event delegation).
document.addEventListener('click', (e) => {
  const row = e.target.closest('.copy-row');
  if (row) {
    e.stopPropagation();
    copyText(row.dataset.val, '已复制 ' + row.dataset.name);
  }
});

// Copy all headers of one side.
$$('.copy-headers').forEach((btn) => {
  btn.addEventListener('click', async () => {
    if (state.selectedId == null) return;
    const d = await loadDetail(state.selectedId);
    const side = btn.dataset.side;
    const headers = side === 'req' ? d.requestHeader : d.responseHeader;
    const line = side === 'req'
      ? `${d.method} ${d.url} ${d.httpVersion}\n`
      : `${d.httpVersion} ${d.statusCode} ${d.reasonPhrase || ''}\n`;
    const text = line + Object.entries(headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n');
    copyText(text, '已复制' + (side === 'req' ? '请求' : '响应') + '头');
  });
});

// Copy body (fetches full body, not just truncated view).
$$('.copy-body').forEach((btn) => {
  btn.addEventListener('click', async () => {
    if (state.selectedId == null) return;
    const side = btn.dataset.side;
    toast('加载中…');
    try {
      const res = await fetch(`/api/session/${state.selectedId}/body?side=${side}&limit=0`);
      if (!res.ok) { toast('无 body'); return; }
      const text = await res.text();
      copyText(text, '已复制' + (side === 'req' ? '请求' : '响应') + '体');
    } catch (err) {
      toast('复制失败: ' + err.message);
    }
  });
});

// Copy as cURL.
$$('.copy-curl').forEach((btn) => {
  btn.addEventListener('click', async () => {
    if (state.selectedId == null) return;
    const d = await loadDetail(state.selectedId);
    if (d.tls) { toast('TLS 会话无法生成 cURL'); return; }
    let url = d.fullUrl || `http://${d.host || ''}${d.url || ''}`;
    let parts = [`curl -X ${d.method || 'GET'} '${url.replace(/'/g, `'\\''`)}'`];
    for (const [k, v] of Object.entries(d.requestHeader || {})) {
      parts.push(`  -H '${k}: ${String(v).replace(/'/g, `'\\''`)}'`);
    }
    // Include body for methods that have one.
    if (d.requestBody && d.requestBody.length) {
      try {
        const res = await fetch(`/api/session/${state.selectedId}/body?side=req&limit=0`);
        const txt = await res.text();
        if (txt) parts.push(`  --data-raw '${txt.replace(/'/g, `'\\''`)}'`);
      } catch {}
    }
    copyText(parts.join(' \\\n'), '已复制 cURL');
  });
});

// ---------- list context menu (Burp-like) ----------
const ctxMenu = $('#ctx-menu');
let ctxRowId = null;

function fullUrlOf(m) {
  if (!m) return '';
  if (m.tls) return m.sni ? 'https://' + m.sni + '/' : '';
  const scheme = 'http://';
  return scheme + (m.h || '') + (m.u || '');
}

function showContextMenu(e, id) {
  e.preventDefault();
  ctxRowId = id;
  const m = state.all.get(id);
  if (!m) return;
  const fullUrl = fullUrlOf(m);
  const isHttp = !m.tls && m.m;
  const items = [
    { label: '🔁 发送到重放器', action: () => Repeater.seedFromTx(id), disabled: m.tls || !m.m },
    { sep: true },
    { label: '复制 URL', action: () => copyText(fullUrl, '已复制 URL'), disabled: !fullUrl },
    { label: '复制主机', action: () => copyText(m.h || m.sni || '', '已复制主机') },
    { label: '复制路径 (含查询)', action: () => copyText(m.u || '', '已复制路径'), disabled: !m.u },
    { sep: true },
    { label: '复制请求行', action: () => copyText(`${m.m} ${m.u} HTTP/1.1`, '已复制请求行'), disabled: !isHttp },
    { label: '复制为 cURL', action: () => buildAndCopyCurl(id), disabled: !isHttp },
    { sep: true },
    { label: '复制源 IP:端口', action: () => copyText(`${m.ip || ''}:${m.sp || ''}`, '已复制源地址') },
    { label: '复制目的 IP:端口', action: () => copyText(`${m.dip || ''}:${m.dp || ''}`, '已复制目的地址') },
    { sep: true },
    { label: '在浏览器打开', action: () => window.open(fullUrl, '_blank'), disabled: !/^https?:\/\//.test(fullUrl) || m.tls },
  ];
  ctxMenu.innerHTML = '';
  for (const it of items) {
    if (it.sep) { ctxMenu.appendChild(Object.assign(document.createElement('li'), { className: 'sep' })); continue; }
    const li = document.createElement('li');
    li.textContent = it.label;
    if (it.disabled) li.classList.add('disabled');
    else li.addEventListener('click', () => { hideContextMenu(); it.action(); });
    ctxMenu.appendChild(li);
  }
  // Position, keeping it within the viewport.
  ctxMenu.hidden = false;
  const mw = ctxMenu.offsetWidth, mh = ctxMenu.offsetHeight;
  const x = Math.min(e.clientX, window.innerWidth - mw - 4);
  const y = Math.min(e.clientY, window.innerHeight - mh - 4);
  ctxMenu.style.left = x + 'px';
  ctxMenu.style.top = y + 'px';
}

function hideContextMenu() {
  ctxMenu.hidden = true;
  ctxRowId = null;
}

scrollEl.addEventListener('contextmenu', (e) => {
  const row = e.target.closest('.row');
  if (!row) return;
  const id = parseInt(row.dataset.id);
  selectSession(id);
  showContextMenu(e, id);
});
document.addEventListener('click', hideContextMenu);
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') hideContextMenu(); });
window.addEventListener('blur', hideContextMenu);
window.addEventListener('resize', hideContextMenu);

async function buildAndCopyCurl(id) {
  const d = await loadDetail(id);
  const m = state.all.get(id);
  const url = fullUrlOf(m);
  let parts = [`curl -X ${d.method || m.m || 'GET'} '${url.replace(/'/g, `'\\''`)}'`];
  for (const [k, v] of Object.entries(d.requestHeader || {})) {
    parts.push(`  -H '${k}: ${String(v).replace(/'/g, `'\\''`)}'`);
  }
  if (d.requestBody && d.requestBody.length) {
    try {
      const res = await fetch(`/api/session/${id}/body?side=req&limit=0`);
      const txt = await res.text();
      if (txt) parts.push(`  --data-raw '${txt.replace(/'/g, `'\\''`)}'`);
    } catch {}
  }
  copyText(parts.join(' \\\n'), '已复制 cURL');
}

// Double-click a host/url cell in the list to copy its full text.
scrollEl.addEventListener('dblclick', (e) => {
  const cell = e.target.closest('.col-host, .col-url, .col-time, .col-method, .col-status');
  if (cell) {
    const row = cell.closest('.row');
    const m = state.all.get(parseInt(row.dataset.id));
    if (!m) return;
    let val = '';
    if (cell.classList.contains('col-host')) val = m.h || m.sni || '';
    else if (cell.classList.contains('col-url')) val = m.u || '';
    else if (cell.classList.contains('col-time')) val = new Date(m.t).toISOString();
    else if (cell.classList.contains('col-method')) val = m.m || '';
    else if (cell.classList.contains('col-status')) val = String(m.s || '');
    if (val) copyText(val, '已复制');
  }
});

function renderHeaderSections(title, headers, findings, locPrefix) {
  if (!headers || !Object.keys(headers).length) {
    return `<div class="header-section">${title} (空)</div>`;
  }
  const hits = new Set();
  if (findings) {
    for (const f of findings) {
      if (f.location === locPrefix) hits.add(f.header);
    }
  }
  const rows = Object.entries(headers).map(([k, v]) => {
    const hit = hits.has(k) ? 'style="color:var(--yellow);"' : '';
    return `<div class="header-row" ${hit}><span class="k">${esc(k)}:</span><span class="v">${esc(v)}</span><span class="copy-row" data-name="${esc(k)}" data-val="${esc(v)}" title="复制值">复制</span></div>`;
  }).join('');
  return `<div class="header-section">${title}</div>${rows}`;
}

async function loadBody(d, side) {
  const container = $(`#${side}-body`);
  const sizeField = side === 'req' ? d.requestBody?.length : d.responseBody?.length;
  if (!sizeField) {
    container.innerHTML = '<span class="loading">(无 body)</span>';
    return;
  }
  container.innerHTML = '<span class="loading">加载中…</span>';
  const limit = 256 * 1024;
  let url = `/api/session/${d.id}/body?side=${side}&limit=${limit}`;
  const res = await fetch(url);
  const buf = await res.arrayBuffer();
  const bytes = new Uint8Array(buf);
  const truncated = bytes.length >= limit && bytes.length < sizeField;
  const ct = (side === 'req' ? d.requestHeader?.['Content-Type'] : d.responseHeader?.['Content-Type']) || '';
  renderBody(container, bytes, ct, $(`#${side}-view-as`).value, truncated, sizeField, d.id, side);
}

function renderBody(container, bytes, contentType, viewAs, truncated, totalSize, id, side) {
  // Decide the view: auto = detect.
  let mode = viewAs;
  if (mode === 'auto') mode = detectMode(bytes, contentType);

  container.innerHTML = '';
  if (truncated) {
    const note = document.createElement('div');
    note.className = 'trunc-note';
    note.textContent = `仅显示前 ${fmtSize(bytes.length)} / 共 ${fmtSize(totalSize)}。`;
    const dl = document.createElement('button');
    dl.className = 'ghost small';
    dl.textContent = '下载完整 body';
    dl.style.marginLeft = '8px';
    dl.onclick = () => downloadBody(id, side);
    note.appendChild(dl);
    container.appendChild(note);
  }

  const content = document.createElement('div');
  if (mode === 'image') {
    const blob = new Blob([bytes], { type: contentType || 'application/octet-stream' });
    const img = document.createElement('img');
    img.src = URL.createObjectURL(blob);
    content.appendChild(img);
  } else if (mode === 'hex') {
    content.innerHTML = hexView(bytes);
  } else if (mode === 'json') {
    const text = new TextDecoder().decode(bytes);
    try {
      const obj = JSON.parse(text);
      content.innerHTML = highlightJSON(JSON.stringify(obj, null, 2));
    } catch {
      content.textContent = text;
    }
  } else {
    // text
    const text = new TextDecoder().decode(bytes);
    content.textContent = text;
  }
  content.className = 'body-inner ' + mode;
  container.appendChild(content);
}

function detectMode(bytes, ct) {
  ct = (ct || '').toLowerCase();
  if (ct.startsWith('image/')) return 'image';
  if (ct.includes('json')) return 'json';
  if (ct.includes('html') || ct.includes('xml') || ct.includes('javascript') || ct.includes('text')) return 'text';
  // Sniff magic bytes.
  if (bytes.length >= 8) {
    if (bytes[0] === 0x89 && bytes[1] === 0x50) return 'image'; // PNG
    if (bytes[0] === 0xff && bytes[1] === 0xd8) return 'image';  // JPEG
    if (bytes[0] === 0x47 && bytes[1] === 0x49) return 'image';  // GIF
  }
  // JSON sniff
  const txt = new TextDecoder().decode(bytes.slice(0, 64)).trimStart();
  if (txt.startsWith('{') || txt.startsWith('[')) return 'json';
  // Heuristic: binary if any NUL in first 512 bytes.
  const probe = bytes.slice(0, 512);
  for (let i = 0; i < probe.length; i++) if (probe[i] === 0) return 'hex';
  return 'text';
}

function hexView(bytes) {
  const max = Math.min(bytes.length, 64 * 1024);
  let out = '';
  for (let i = 0; i < max; i += 16) {
    const slice = bytes.subarray(i, Math.min(i + 16, bytes.length));
    const off = i.toString(16).padStart(8, '0');
    let hex = '', ascii = '';
    for (let j = 0; j < 16; j++) {
      if (j < slice.length) {
        hex += slice[j].toString(16).padStart(2, '0') + ' ';
        ascii += (slice[j] >= 32 && slice[j] < 127) ? String.fromCharCode(slice[j]) : '.';
      } else { hex += '   '; ascii += ' '; }
    }
    out += `<div class="hex-line"><span class="hex-off">${off}</span>  ${hex} ${esc(ascii)}</div>`;
  }
  if (bytes.length > max) out += `\n… (共 ${fmtSize(bytes.length)}，仅显示前 64KB)`;
  return out;
}

function highlightJSON(s) {
  s = esc(s);
  return s.replace(
    /("(\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,
    (m) => {
      let cls = 'num';
      if (/^"/.test(m)) cls = /:$/.test(m) ? 'key' : 'str';
      else if (/true|false/.test(m)) cls = 'bool';
      else if (/null/.test(m)) cls = 'null';
      return `<span class="${cls}">${m}</span>`;
    }
  );
}

function downloadBody(id, side) {
  window.open(`/api/session/${id}/body?side=${side}`, '_blank');
}

// ---------- filters ----------
function runQuery() {
  if (!state.worker) return;
  const filters = {
    q: $('#q').value,
    method: $('#method').value,
    host: $('#host').value,
    status: $('#status').value,
    from: $('#time-from').value,
    to: $('#time-to').value,
    onlySensitive: $('#only-sensitive').checked,
    hideTls: $('#hide-tls').checked,
  };
  state.worker.postMessage({ type: 'query', filters, sortKey: state.sortKey, sortDir: state.sortDir });
}

// ---------- column sorting ----------
function updateSortArrows() {
  $$('.list-header .sortable').forEach((el) => {
    const arrow = el.querySelector('.sort-arrow');
    if (!arrow) return;
    if (el.dataset.sort === state.sortKey) {
      arrow.textContent = state.sortDir === 'desc' ? ' ▼' : ' ▲';
    } else {
      arrow.textContent = '';
    }
  });
}
$$('.list-header .sortable').forEach((el) => {
  el.addEventListener('click', () => {
    const key = el.dataset.sort;
    if (state.sortKey === key) {
      state.sortDir = state.sortDir === 'asc' ? 'desc' : 'asc';
    } else {
      state.sortKey = key;
      state.sortDir = (key === 't' || key === 'd' || key === 'ps' || key === 's') ? 'desc' : 'asc';
    }
    updateSortArrows();
    runQuery();
  });
});
updateSortArrows();

function debounceQuery() {
  clearTimeout(state.queryTimer);
  state.queryTimer = setTimeout(runQuery, 180);
}

['q', 'host', 'method', 'status', 'time-from', 'time-to', 'only-sensitive', 'hide-tls'].forEach((id) => {
  const el = $('#' + id);
  const ev = (el.tagName === 'SELECT' || el.type === 'checkbox' || el.type === 'datetime-local') ? 'change' : 'input';
  el.addEventListener(ev, debounceQuery);
});
$('#clear-filters').addEventListener('click', () => {
  ['q', 'host', 'time-from', 'time-to'].forEach((id) => $('#' + id).value = '');
  $('#method').value = '';
  $('#status').value = '';
  $('#only-sensitive').checked = false;
  $('#hide-tls').checked = false;
  runQuery();
});

// view-as switching
['req', 'resp'].forEach((side) => {
  $(`#${side}-view-as`).addEventListener('change', async () => {
    if (state.selectedId == null) return;
    const d = await loadDetail(state.selectedId);
    loadBody(d, side);
  });
  $(`#${side}-download`).addEventListener('click', () => {
    if (state.selectedId != null) downloadBody(state.selectedId, side);
  });
});

// tabs
$$('.tab').forEach((tab) => {
  tab.addEventListener('click', () => {
    if (panels.classList.contains('split')) return; // tabs ignored in split mode
    $$('.tab').forEach((t) => t.classList.remove('active'));
    $$('.panel').forEach((p) => p.classList.remove('active'));
    tab.classList.add('active');
    $('#panel-' + tab.dataset.tab).classList.add('active');
  });
});

// ---------- layout toggle (tab vs side-by-side) ----------
const panels = $('#detail-panels');
const splitter = $('#splitter');
const layoutBtn = $('#btn-layout');

function setLayout(mode) {
  const split = mode === 'split';
  panels.classList.toggle('split', split);
  splitter.hidden = !split;
  $('.tab-group').style.visibility = split ? 'hidden' : 'visible';
  layoutBtn.querySelector('.layout-label').textContent = split ? '单栏' : '并排';
  layoutBtn.title = split ? '切换为 Tab 单栏显示' : '切换为左右并排 (请求|响应)';
  if (split) {
    // Both panels visible.
    $$('.panel').forEach((p) => p.classList.add('active'));
  } else {
    $$('.panel').forEach((p) => {
      p.classList.remove('active');
      p.style.flex = ''; // clear drag-resized fractions (column layout)
    });
    const activeTab = $('.tab.active') || $('.tab');
    activeTab.classList.add('active');
    $('#panel-' + activeTab.dataset.tab).classList.add('active');
  }
  state.layout = mode;
  try { localStorage.setItem('layout', mode); } catch {}
}
layoutBtn.addEventListener('click', () => setLayout(panels.classList.contains('split') ? 'tab' : 'split'));

// Drag the splitter to resize request/response panes.
let dragging = false;
splitter.addEventListener('mousedown', (e) => {
  dragging = true;
  splitter.classList.add('dragging');
  document.body.classList.add('resizing');
  e.preventDefault();
});
window.addEventListener('mousemove', (e) => {
  if (!dragging) return;
  const rect = panels.getBoundingClientRect();
  const frac = Math.min(0.85, Math.max(0.15, (e.clientX - rect.left) / rect.width));
  $('#panel-req').style.flex = frac;
  $('#panel-resp').style.flex = 1 - frac;
});
window.addEventListener('mouseup', () => {
  if (!dragging) return;
  dragging = false;
  splitter.classList.remove('dragging');
  document.body.classList.remove('resizing');
});

try {
  if (localStorage.getItem('layout') === 'split') setLayout('split');
} catch {}

// ---------- open file ----------
function pickFile() { $('#file-input').click(); }
$('#btn-open').addEventListener('click', pickFile);
$('#landing-choose').addEventListener('click', pickFile);

async function handleFile(file) {
  if (!file) return;
  $('#parse-progress').textContent = '上传并解析中…';
  $('#file-name').textContent = file.name;
  $('#btn-scan').disabled = false;
  $('#btn-scan').textContent = '🔍 扫描敏感信息';
  state.all.clear(); state.order = []; state.detailCache.clear();
  scrollEl.innerHTML = ''; $('#result-count').textContent = '';
  const fd = new FormData();
  fd.append('file', file);
  const res = await fetch('/api/upload', { method: 'POST', body: fd });
  if (!res.ok) {
    $('#parse-progress').textContent = '错误: ' + (await res.text());
    return;
  }
  // SSE delivers progress; on "done" the list reloads and the landing hides.
}

$('#file-input').addEventListener('change', (e) => {
  if (e.target.files[0]) handleFile(e.target.files[0]);
  e.target.value = ''; // allow re-picking the same file
});

// Drag & drop onto the window (works on landing and main UI).
window.addEventListener('dragover', (e) => { e.preventDefault(); document.body.classList.add('dragover'); });
window.addEventListener('dragleave', () => document.body.classList.remove('dragover'));
window.addEventListener('drop', (e) => {
  e.preventDefault();
  document.body.classList.remove('dragover');
  if (e.dataTransfer.files && e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]);
});

// Manual sensitive-info scan (opt-in).
$('#btn-scan').addEventListener('click', async () => {
  if (state.order.length === 0) { alert('请先打开一个抓包文件'); return; }
  $('#btn-scan').disabled = true;
  $('#btn-scan').textContent = '扫描中…';
  const res = await fetch('/api/scan', { method: 'POST' });
  if (!res.ok) {
    alert('扫描失败: ' + await res.text());
    $('#btn-scan').disabled = false;
    $('#btn-scan').textContent = '🔍 扫描敏感信息';
  }
  // SSE scan-done will re-enable the button.
});

async function openPath(path) {
  $('#parse-progress').textContent = '打开中…';
  $('#file-name').textContent = path;
  const res = await fetch('/api/open?path=' + encodeURIComponent(path), { method: 'POST' });
  if (!res.ok) {
    const t = await res.text();
    $('#parse-progress').textContent = '错误: ' + t;
  }
}

// ---------- SSE progress ----------
function connectProgress() {
  const es = new EventSource('/api/progress');
  es.onmessage = (e) => {
    const p = JSON.parse(e.data);
    const msg = p.message || p.phase;
    if (p.phase === 'parsing') {
      $('#parse-progress').textContent =
        `${msg}  包 ${p.packets} · 会话 ${p.transactions} · TLS ${p.tlsSessions} · ${p.elapsedMs}ms`;
    } else if (p.phase === 'scanning') {
      $('#parse-progress').textContent = msg || '扫描中…';
    } else if (p.phase === 'done') {
      $('#parse-progress').textContent = `✓ ${p.message || '完成'} (${p.elapsedMs}ms)`;
      $('#landing').classList.add('hidden');
      loadSessions();
    } else if (p.phase === 'scan-done') {
      $('#parse-progress').textContent = `✓ 敏感信息扫描完成`;
      $('#btn-scan').disabled = false;
      $('#btn-scan').textContent = '🔍 扫描敏感信息';
      loadSessions();
      refreshFindingsBadge();
      setTimeout(() => {
        if ($('#parse-progress').textContent.startsWith('✓ 敏感信息扫描完成')) {
          $('#parse-progress').textContent = '';
        }
      }, 2500);
    } else if (p.phase === 'error') {
      $('#parse-progress').textContent = '错误: ' + p.message;
    }
  };
}

// ---------- global findings view ----------
let findingsGroups = [];
$('#btn-findings').addEventListener('click', openFindings);
$('#findings-close').addEventListener('click', () => $('#findings-modal').hidden = true);
$('#findings-modal').addEventListener('click', (e) => {
  if (e.target.id === 'findings-modal') $('#findings-modal').hidden = true;
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') { $('#findings-modal').hidden = true; }
});
$('#findings-search').addEventListener('input', () => renderFindingsModal());

async function refreshFindingsBadge() {
  try {
    const groups = await (await fetch('/api/findings')).json();
    let total = 0;
    for (const g of groups) total += g.count;
    $('#findings-total').textContent = total ? total : '';
  } catch {}
}

async function openFindings() {
  $('#findings-modal').hidden = false;
  $('#findings-search').value = '';
  const body = $('#findings-body');
  body.innerHTML = '<div class="loading">加载中…</div>';
  try {
    const res = await fetch('/api/findings');
    findingsGroups = await res.json();
  } catch (e) {
    body.innerHTML = '<div class="loading">加载失败</div>';
    return;
  }
  renderFindingsModal();
}

function renderFindingsModal() {
  const body = $('#findings-body');
  if (!findingsGroups.length) {
    body.innerHTML = '<div class="loading">暂无命中。请先点「🔍 扫描敏感信息」。</div>';
    return;
  }
  const q = $('#findings-search').value.trim().toLowerCase();
  let total = 0;
  const groups = findingsGroups.map((g) => {
    let items = g.items;
    if (q) {
      items = items.filter((it) =>
        (it.match || '').toLowerCase().includes(q) ||
        (it.host || '').toLowerCase().includes(q) ||
        (it.url || '').toLowerCase().includes(q) ||
        (it.srcIp || '').includes(q) || (it.dstIp || '').includes(q)
      );
    }
    total += items.length;
    return { ...g, items };
  }).filter((g) => g.items.length > 0);

  groups.sort((a, b) => (SEVRANK[b.severity] || 0) - (SEVRANK[a.severity] || 0));

  let html = `<div class="find-summary">共 <b>${total}</b> 处命中，<b>${groups.length}</b> 个规则类别</div>`;
  for (const g of groups) {
    html += `<div class="find-group">
      <div class="find-group-head">
        <span class="finding-tag ${g.severity}">${esc(g.name)}</span>
        <span class="find-cat">${esc(g.category)}</span>
        <span class="find-count">${g.items.length}</span>
      </div>
      <ul class="find-items">`;
    // De-duplicate identical match values but keep clickable rows.
    const seen = new Set();
    for (const it of g.items) {
      const key = it.match + it.txId;
      if (seen.has(key)) continue;
      seen.add(key);
      const val = it.match || it.snippet || '';
      html += `<li class="find-item" data-tx="${it.txId}">
        <code class="find-val">${esc(truncate(val, 120))}</code>
        <span class="find-ctx">${esc(it.method || '')} ${esc(it.host || '')}${esc(it.url || '')} <span class="find-ip">${esc(it.srcIp || '')} → ${esc(it.dstIp || '')}</span> <span class="find-time">${fmtTime(it.t)}</span></span>
      </li>`;
    }
    html += `</ul></div>`;
  }
  body.innerHTML = html;
  body.querySelectorAll('.find-item').forEach((li) => {
    li.addEventListener('click', () => {
      const id = parseInt(li.dataset.tx);
      $('#findings-modal').hidden = true;
      selectSession(id);
      scrollListToId(id);
    });
  });
}

function scrollListToId(id) {
  // Find the index of id in state.filtered then scroll there.
  const idx = state.filtered.findIndex((x) => x === id);
  if (idx >= 0) {
    scrollEl.scrollTop = idx * ROW_H;
    requestAnimationFrame(renderList);
  }
}

// ---------- rules modal ----------
$('#btn-rules').addEventListener('click', openRules);
$('#rules-close').addEventListener('click', () => $('#rules-modal').hidden = true);
$('#rules-modal').addEventListener('click', (e) => {
  if (e.target.id === 'rules-modal') $('#rules-modal').hidden = true;
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') $('#rules-modal').hidden = true;
});

async function openRules() {
  $('#rules-modal').hidden = false;
  const res = await fetch('/api/rules');
  const rules = await res.json();
  renderRules(rules);
}

function renderRules(rules) {
  const list = $('#rules-list');
  list.innerHTML = rules.map((r, i) => `
    <div class="rule-card ${r.enabled ? '' : 'disabled'}" data-i="${i}">
      <div class="rule-head">
        <input type="checkbox" ${r.enabled ? 'checked' : ''} class="rule-enable">
        <span class="rule-name">${esc(r.name)}</span>
        <span class="badge ${r.severity}">${r.severity}</span>
        <span class="rule-id">${esc(r.id)}</span>
      </div>
      <div class="rule-meta">
        ${esc(r.category || '')} · 范围: ${(r.scope || []).join(', ')}
        ${r.headerName ? ' · header: ' + esc(r.headerName) : ''}
        ${r.pattern ? ' · <code>' + esc(r.pattern.slice(0, 80)) + (r.pattern.length > 80 ? '…' : '') + '</code>' : ''}
      </div>
    </div>`).join('');
  list.querySelectorAll('.rule-enable').forEach((cb) => {
    cb.addEventListener('change', () => {
      const i = parseInt(cb.closest('.rule-card').dataset.i);
      rules[i].enabled = cb.checked;
      cb.closest('.rule-card').classList.toggle('disabled', !cb.checked);
      saveRules(rules);
    });
  });
}

async function saveRules(rules) {
  const res = await fetch('/api/rules', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(rules),
  });
  if (!res.ok) {
    const e = await res.json().catch(() => ({}));
    alert('规则错误: ' + ((e.errors || []).join('; ') || res.statusText));
  }
  // Rules are saved but NOT scanned automatically; click "扫描敏感信息" to apply.
}

$('#rules-enable-all').addEventListener('click', async () => {
  const r = await (await fetch('/api/rules')).json();
  r.forEach((x) => x.enabled = true);
  renderRules(r); saveRules(r);
});
$('#rules-disable-all').addEventListener('click', async () => {
  const r = await (await fetch('/api/rules')).json();
  r.forEach((x) => x.enabled = false);
  renderRules(r); saveRules(r);
});
$('#rules-import').addEventListener('change', async (e) => {
  const f = e.target.files[0];
  if (!f) return;
  const fd = new FormData();
  fd.append('file', f);
  const res = await fetch('/api/rules/import', { method: 'POST', body: fd });
  if (res.ok) { openRules(); } else { alert('导入失败'); }
});
$('#rules-export').addEventListener('click', () => window.open('/api/rules/export', '_blank'));

// ---------- worker + init ----------
function initWorker() {
  state.worker = new Worker('worker-filter.js');
  state.worker.onmessage = (e) => {
    if (e.data.type === 'ready') {
      $('#result-count').textContent = `${state.order.length} 个会话`;
      runQuery();
    } else if (e.data.type === 'results') {
      state.filtered = e.data.ids;
      $('#result-count').textContent =
        `${state.filtered.length} / ${state.order.length} 个会话 (${e.data.ms}ms)`;
      renderList();
    }
  };
}

// Boot.
Repeater.init();
initWorker();
connectProgress();
fetch('/api/status').then((r) => r.json()).then((s) => {
  if (s.file) {
    $('#file-name').textContent = s.file;
    if (s.count > 0) {
      $('#landing').classList.add('hidden');
      loadSessions();
    }
  }
});
