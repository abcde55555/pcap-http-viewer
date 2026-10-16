// Filter worker. It receives all session metadata once (as NDJSON via fetch),
// builds in-memory indexes, and answers filter queries by returning matched ids
// as a Uint32Array (transferred zero-copy). All heavy scanning lives off the
// main thread so scrolling stays at 60fps.

let all = [];          // Metadata[]
let allById = new Map(); // id -> Metadata
let searchBlob = [];   // pre-lowercased searchable text per item
let times = new Float64Array(0); // sorted? we keep item order (pcap order = time order)

const SEVERITY_RANK = { info:1, low:2, medium:3, high:4, critical:5 };

self.onmessage = (e) => {
  const { type } = e.data;
  if (type === 'data') {
    all = e.data.items;
    buildIndex();
    self.postMessage({ type: 'ready', count: all.length });
    return;
  }
  if (type === 'query') {
    const start = performance.now();
    const ids = runQuery(e.data.filters);
    const { sortKey, sortDir } = e.data;
    if (sortKey) sortResults(ids, sortKey, sortDir === 'desc' ? -1 : 1);
    const buf = new Uint32Array(ids);
    // Transfer the underlying ArrayBuffer so the main thread gets it zero-copy.
    self.postMessage({ type: 'results', ids: buf, ms: Math.round(performance.now() - start) }, [buf.buffer]);
  }
}

const COMP = {
  t: (m) => m.t || 0,
  m: (m) => (m.m || '').toUpperCase(),
  h: (m) => (m.h || m.sni || '').toUpperCase(),
  u: (m) => (m.u || '').toUpperCase(),
  s: (m) => m.s || 0,
  ps: (m) => m.ps || m.rs || 0,
  d: (m) => m.d || 0,
};

// sortResults sorts the id array in place using the metadata map.
function sortResults(ids, key, dir) {
  const get = COMP[key];
  if (!get) return;
  // Build a small parallel array of sort values to avoid repeated lookups.
  const n = ids.length;
  const vals = new Array(n);
  for (let i = 0; i < n; i++) vals[i] = get(allById.get(ids[i]));
  // Indirect sort.
  const idx = Array.from({ length: n }, (_, i) => i);
  idx.sort((a, b) => {
    const va = vals[a], vb = vals[b];
    if (typeof va === 'number' && typeof vb === 'number') return (va - vb) * dir;
    if (va < vb) return -dir;
    if (va > vb) return dir;
    return 0;
  });
  const sorted = new Uint32Array(n);
  for (let i = 0; i < n; i++) sorted[i] = ids[idx[i]];
  ids.set(sorted);
}

function buildIndex() {
  searchBlob = new Array(all.length);
  times = new Float64Array(all.length);
  allById = new Map();
  for (let i = 0; i < all.length; i++) {
    allById.set(all[i].id, all[i]);
    const m = all[i];
    // Pre-build a single lowercased blob for fast keyword includes().
    // We don't include body here (bodies are loaded on demand); header text is
    // partially available via host/url/contentType. Body search is done server-side
    // via a dedicated endpoint if added later.
    searchBlob[i] = [m.m || '', m.h || '', m.u || '', m.ct || '', m.ip || '', m.sni || ''].join(' ').toLowerCase();
    times[i] = m.t || 0;
  }
}

function runQuery(f) {
  const q = (f.q || '').trim().toLowerCase();
  const method = (f.method || '').toUpperCase();
  const host = (f.host || '').trim().toLowerCase();
  const statusClass = f.status || '';
  const from = f.from ? Date.parse(f.from) : 0;
  const to = f.to ? Date.parse(f.to) : 0;
  const onlySensitive = !!f.onlySensitive;
  const hideTls = !!f.hideTls;

  const n = all.length;
  // Collect into a reusable array; max length n.
  const out = new Uint32Array(n);
  let w = 0;

  for (let i = 0; i < n; i++) {
    const m = all[i];
    if (hideTls && m.tls) continue;
    if (method && (m.m || '') !== method) continue;
    if (host && !(m.h || '').toLowerCase().includes(host) && !(m.sni || '').toLowerCase().includes(host)) continue;
    if (statusClass) {
      const sc = Math.floor((m.s || 0) / 100);
      if (String(sc) !== statusClass) continue;
    }
    if (from && m.t && m.t < from) continue;
    if (to && m.t && m.t > to) continue;
    if (onlySensitive && (m.fn || 0) === 0) continue;
    if (q && !searchBlob[i].includes(q)) continue;
    out[w++] = m.id;
  }
  return out.slice(0, w);
}
