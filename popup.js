// popup.js — allowlist toggle
import { HEADER_RECS } from "./utilsconstants.js";

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

function originFrom(inputValue) { try { return new URL(inputValue).origin; } catch { return null; } }
async function getActiveTab() { const [tab] = await chrome.tabs.query({ active: true, currentWindow: true }); return tab; }
async function getAllowlist() { const res = await chrome.storage.sync.get({ allowlist: [] }); return new Set(res.allowlist || []); }
async function setAllowlist(set) { await chrome.storage.sync.set({ allowlist: Array.from(set) }); }

function renderList(el, title, items, getRow) {
  el.innerHTML = `<div class="item"><h3>${title}</h3>${items.length ? '' : '<p><small class="muted">No issues found.</small></p>'}</div>`;
  const box = el.querySelector('.item');
  items.forEach(it => { const row = document.createElement('div'); row.className = 'row'; row.innerHTML = getRow(it); box.appendChild(row); });
}
function toCsv(rows) {
  if (!rows.length) return '';
  const headers = Object.keys(rows[0]);
  const esc = (s) => ('"' + String(s).replace(/"/g, '""') + '"');
  return [headers.join(','), ...rows.map(r => headers.map(h => esc(r[h] ?? '')).join(',')).join('\n')].join('\n');
}

// Allowlist UI
async function syncAllowUI(tab) {
  const allowInput = $('#allowInput'); const allowToggle = $('#allowToggle'); const status = $('#allowStatus'); const runBtn = $('#runAll');
  const currentOrigin = new URL(tab.url).origin;
  if (!allowInput.value) allowInput.value = currentOrigin;
  const set = await getAllowlist();
  const enabled = set.has(currentOrigin);
  allowToggle.checked = enabled;
  status.textContent = enabled ? 'Enabled for this site' : 'Disabled';
  runBtn.disabled = !enabled;
}
async function onToggleChanged() {
  const tab = await getActiveTab();
  const inputOrigin = originFrom($('#allowInput').value) || new URL(tab.url).origin;
  const set = await getAllowlist();
  if ($('#allowToggle').checked) { set.add(inputOrigin); } else { set.delete(inputOrigin); }
  await setAllowlist(set); await syncAllowUI(tab);
}
$('#useCurrent')?.addEventListener('click', async () => { const tab = await getActiveTab(); $('#allowInput').value = new URL(tab.url).origin; await syncAllowUI(tab); });
$('#allowToggle')?.addEventListener('change', onToggleChanged);

// Tabs
$$('nav.tabs button').forEach(btn => btn.addEventListener('click', () => {
  $$('.tabs button').forEach(b => b.classList.remove('active')); btn.classList.add('active');
  $$('.tab').forEach(t => t.classList.remove('active')); document.getElementById(btn.dataset.tab).classList.add('active');
}));

async function runAll() {
  const tab = await getActiveTab(); const set = await getAllowlist(); const currentOrigin = new URL(tab.url).origin;
  if (!set.has(currentOrigin)) {
    $('#summary').innerHTML = `<div class="item"><small class="muted">This site is not enabled. Toggle <b>Enabled</b> above to scan <span class="mono">${currentOrigin}</span>.</small></div>`;
    return;
  }
  const content = await chrome.tabs.sendMessage(tab.id, { type: 'RUN_CONTENT_SCANS' }).catch(() => null);
  const hdr     = await chrome.runtime.sendMessage({ type: 'GET_HEADERS', tabId: tab.id }).catch(() => null);
  const cks     = await chrome.runtime.sendMessage({ type: 'GET_COOKIES', url: tab.url }).catch(() => null);

  const findings = {
    xss:     content?.ok ? content.data.xss   : { inline:[], jsHrefs:[], suspiciousReflections:[] },
    csrf:    content?.ok ? content.data.csrf  : { forms:[] },
    mixed:   content?.ok ? content.data.mixed : { items:[], isSecureContext:false },
    headers: hdr?.analysis ?? { present:[], missing:[], notes:[], hstsOk:false },
    cookies: cks?.analysis ?? { count:0, issues:[] },
    _raw:    { cookies: cks?.cookies ?? [], headers: hdr?.headers ?? {}, url: tab.url },
    meta:    { ts: new Date().toISOString(), url: tab.url }
  };

  const scoreResp = await chrome.runtime.sendMessage({ type: 'COMPUTE_SCORE', payload: findings }).catch(() => ({ ok:false }));
  const score = scoreResp?.ok ? scoreResp.score : '--';
  $('#score').textContent = score; $('#lastScan').innerHTML = `<small class="muted">Last scan: ${new Date().toLocaleString()}</small>`;

  // Dashboard
  $('#summary').innerHTML = `
    <div class="item"><div class="kv">
      <div>Missing Headers</div><div>${findings.headers.missing.length}</div>
      <div>Cookie Issues</div><div>${findings.cookies.issues.length}</div>
      <div>Mixed Content</div><div>${findings.mixed.items.length}</div>
      <div>XSS Hints</div><div>${findings.xss.inline.length + findings.xss.jsHrefs.length + findings.xss.suspiciousReflections.length}</div>
      <div>Forms Analyzed</div><div>${findings.csrf.forms.length}</div>
    </div></div>`;

  // XSS tab
  const xr = $('#xssResults'); xr.innerHTML = '';
  renderList(xr, 'Inline event handlers', findings.xss.inline, (n) => `<div class="item"><div><span class="tag">${n.tag}</span> <span class="mono">${n.handlers.join(', ')}</span></div><div class="mono">${n.snippet}</div></div>`);
  renderList(xr, 'javascript: links', findings.xss.jsHrefs, (a) => `<div class="item"><span class="tag">${a.tag}</span> <span class="mono">${a.href}</span></div>`);
  renderList(xr, 'Suspicious reflections', findings.xss.suspiciousReflections, (r) => `<div class="item">Param <b>${r.key}</b> reflected near script context <span class="mono">${r.valueSample}</span></div>`);

  // CSRF tab
  const cr = $('#csrfResults'); cr.innerHTML = '';
  renderList(cr, 'Forms', findings.csrf.forms, (f) => `<div class="item"><div><b>${f.method}</b> → <span class="mono">${f.action}</span></div><div>${f.hiddenTokenCount ? '<span class="ok">Token detected</span>' : '<span class="bad">No token</span>'}</div>${(f.tokenIssues||[]).map(i => `<div class="warn">• ${i.issue}${i.name? ' ('+i.name+')':''}</div>`).join('')}</div>`);

  // Cookies tab
  const ck = $('#cookieResults');
  const cookieRows = (findings._raw.cookies || []).map(c => ({ Name: c.name, Domain: c.domain, Path: c.path, Secure: c.secure, HttpOnly: c.httpOnly, SameSite: c.sameSite, Session: c.session, Size: c.size }));
  ck.innerHTML = `<div class="item"><table class="table"><thead><tr><th>Name</th><th>Domain</th><th>Flags</th><th>SameSite</th><th>Session</th><th>Size</th></tr></thead><tbody>${cookieRows.map(r => `<tr><td class="mono">${r.Name}</td><td class="mono">${r.Domain}</td><td>${r.Secure?'Secure':''} ${r.HttpOnly?'<span class="tag">HttpOnly</span>':''}</td><td>${r.SameSite}</td><td>${r.Session}</td><td>${r.Size}</td></tr>`).join('')}</tbody></table><div class="item">${(findings.cookies.issues||[]).map(i => `<div class="${i.severity==='High'?'bad': i.severity==='Medium'?'warn':'ok'}">• ${i.name}: ${i.issue}</div>`).join('') || '<small class="muted">No cookie issues detected.</small>'}</div></div>`;

  // SSL/HTTPS tab
  const sr = $('#sslResults');
  sr.innerHTML = `<div class="item"><div>Secure Context: ${findings.mixed.isSecureContext ? '<span class="ok">Yes</span>' : '<span class="bad">No</span>'}</div><div>Mixed Content items: ${findings.mixed.items.length}</div>${(findings.mixed.items||[]).slice(0,10).map(i => `<div class="warn mono">• ${i.tag}[${i.attr}] → ${i.url}</div>`).join('')}<div class="${findings.headers.hstsOk? 'ok':'warn'}">HSTS header: ${findings.headers.hstsOk? 'Present/looks OK':'Missing or incomplete'}</div><small class="muted">Note: detailed TLS/cipher/cert info requires a remote scanner. Configure in Options if desired.</small></div>`;

  // Headers tab
  const hr = $('#headerResults');
  const present = findings.headers.present.map(h => `<div class="ok">• ${h.name}: <span class="mono">${h.value}</span></div>`).join('');
  const missing = findings.headers.missing.map(n => `<div class="warn">• Missing: <b>${n}</b> — ${HEADER_RECS[n] || ''}</div>`).join('');
  const notes = findings.headers.notes.map(n => `<div class="warn">• ${n.name}: ${n.issue}</div>`).join('');
  hr.innerHTML = `<div class="item">${present || '<small class="muted">No security headers detected.</small>'}${missing}${notes}</div>`;

  // Export
  $('#exportJson').onclick = () => { const blob = new Blob([JSON.stringify({ score, ...findings }, null, 2)], { type: 'application/json' }); const url = URL.createObjectURL(blob); chrome.downloads ? chrome.downloads.download({ url, filename: 'security-report.json' }) : window.open(url); };
  $('#exportCsv').onclick = () => { const rows = [ ...findings.cookies.issues.map(i => ({ Type:'Cookie', Name:i.name, Issue:i.issue, Severity:i.severity })), ...findings.headers.missing.map(n => ({ Type:'Header', Name:n, Issue:'Missing', Severity:'High' })), ...findings.headers.notes.map(n => ({ Type:'Header', Name:n.name, Issue:n.issue, Severity:'Medium' })), ...findings.mixed.items.map(m => ({ Type:'MixedContent', Name:`${m.tag}[${m.attr}]`, Issue:m.url, Severity:'High' })) ]; const csv = toCsv(rows); const blob = new Blob([csv], { type: 'text/csv' }); const url = URL.createObjectURL(blob); chrome.downloads ? chrome.downloads.download({ url, filename: 'security-report.csv' }) : window.open(url); };
}

document.getElementById('runAll').addEventListener('click', runAll);

// Init
(async () => {
  const tab = await getActiveTab(); await syncAllowUI(tab);
  const set = await getAllowlist(); const currentOrigin = new URL(tab.url).origin;
  if (set.has(currentOrigin)) runAll();
})();
