// popup.js — allowlist toggle
import { HEADER_RECS } from "./utilsconstants.js";
import { SecurityUtils } from "./security-utils-client.js";

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

function originFrom(inputValue) { 
  const sanitized = SecurityUtils.validation.sanitizeString(inputValue);
  if (!SecurityUtils.validation.isValidUrl(sanitized)) return null;
  try { 
    return new URL(sanitized).origin; 
  } catch { 
    return null; 
  } 
}
async function getActiveTab() { const [tab] = await chrome.tabs.query({ active: true, currentWindow: true }); return tab; }
async function getAllowlist() { const res = await chrome.storage.sync.get({ allowlist: [] }); return new Set(res.allowlist || []); }
async function setAllowlist(set) { await chrome.storage.sync.set({ allowlist: Array.from(set) }); }

function renderList(el, title, items, getRow) {
  if (!el) return;
  
  // Clear container safely
  el.textContent = '';
  
  // Create structure safely
  const itemDiv = SecurityUtils.escaping.createSafeElement('div', { class: 'item' });
  const titleH3 = SecurityUtils.escaping.createSafeElement('h3', {}, title);
  itemDiv.appendChild(titleH3);
  
  if (items.length === 0) {
    const noItems = SecurityUtils.escaping.createSafeElement('p');
    const small = SecurityUtils.escaping.createSafeElement('small', { class: 'muted' }, 'No issues found.');
    noItems.appendChild(small);
    itemDiv.appendChild(noItems);
  }
  
  el.appendChild(itemDiv);
  
  items.forEach(item => {
    const row = SecurityUtils.escaping.createSafeElement('div', { class: 'row' });
    // Note: getRow function must return safe HTML or use escaping
    row.innerHTML = getRow(item);
    itemDiv.appendChild(row);
  });
}
function toCsv(rows) {
  if (!rows.length) return '';
  const headers = Object.keys(rows[0]);
  const esc = (s) => ('"' + String(s).replace(/"/g, '""') + '"');
  return [headers.join(','), ...rows.map(r => headers.map(h => esc(r[h] ?? '')).join(',')).join('\n')].join('\n');
}

// Allowlist UI
async function syncAllowUI(tab) {
  const allowInput = $('#allowInput'); 
  const allowToggle = $('#allowToggle'); 
  const status = $('#allowStatus'); 
  const runBtn = $('#runAll');
  
  const currentOrigin = new URL(tab.url).origin;
  if (!allowInput.value) {
    allowInput.value = currentOrigin;
  }
  
  const set = await getAllowlist();
  const enabled = set.has(currentOrigin);
  allowToggle.checked = enabled;
  status.textContent = enabled ? 'Enabled for this site' : 'Disabled';
  runBtn.disabled = !enabled;
}
async function onToggleChanged() {
  const tab = await getActiveTab();
  const inputValue = SecurityUtils.validation.sanitizeString($('#allowInput').value);
  const inputOrigin = originFrom(inputValue) || new URL(tab.url).origin;
  const set = await getAllowlist();
  
  if ($('#allowToggle').checked) { 
    set.add(inputOrigin); 
  } else { 
    set.delete(inputOrigin); 
  }
  
  await setAllowlist(set); 
  await syncAllowUI(tab);
}
$('#useCurrent')?.addEventListener('click', async () => { const tab = await getActiveTab(); $('#allowInput').value = new URL(tab.url).origin; await syncAllowUI(tab); });
$('#allowToggle')?.addEventListener('change', onToggleChanged);

// Tabs
$$('nav.tabs button').forEach(btn => btn.addEventListener('click', () => {
  $$('.tabs button').forEach(b => b.classList.remove('active')); btn.classList.add('active');
  $$('.tab').forEach(t => t.classList.remove('active')); document.getElementById(btn.dataset.tab).classList.add('active');
}));

async function runAll() {
  const tab = await getActiveTab(); 
  const set = await getAllowlist(); 
  const currentOrigin = new URL(tab.url).origin;
  
  if (!set.has(currentOrigin)) {
    const messageDiv = SecurityUtils.escaping.createSafeElement('div', { class: 'item' });
    const small = SecurityUtils.escaping.createSafeElement('small', { class: 'muted' });
    small.innerHTML = `This site is not enabled. Toggle <b>Enabled</b> above to scan <span class="mono">${SecurityUtils.escaping.escapeHtml(currentOrigin)}</span>.`;
    messageDiv.appendChild(small);
    
    $('#summary').textContent = '';
    $('#summary').appendChild(messageDiv);
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
  $('#score').textContent = score; 
  
  // Safe last scan update
  const lastScanEl = $('#lastScan');
  lastScanEl.textContent = '';
  const small = SecurityUtils.escaping.createSafeElement('small', { class: 'muted' }, `Last scan: ${new Date().toLocaleString()}`);
  lastScanEl.appendChild(small);

  // Dashboard - safe summary creation
  const summaryEl = $('#summary');
  summaryEl.textContent = '';
  const itemDiv = SecurityUtils.escaping.createSafeElement('div', { class: 'item' });
  const kvDiv = SecurityUtils.escaping.createSafeElement('div', { class: 'kv' });
  
  // Add summary items safely
  const summaryItems = [
    ['Missing Headers', findings.headers.missing.length],
    ['Cookie Issues', findings.cookies.issues.length],
    ['Mixed Content', findings.mixed.items.length],
    ['XSS Hints', findings.xss.inline.length + findings.xss.jsHrefs.length + findings.xss.suspiciousReflections.length],
    ['Forms Analyzed', findings.csrf.forms.length]
  ];
  
  summaryItems.forEach(([label, value]) => {
    const labelDiv = SecurityUtils.escaping.createSafeElement('div', {}, label);
    const valueDiv = SecurityUtils.escaping.createSafeElement('div', {}, String(value));
    kvDiv.appendChild(labelDiv);
    kvDiv.appendChild(valueDiv);
  });
  
  itemDiv.appendChild(kvDiv);
  summaryEl.appendChild(itemDiv);

  // XSS tab - clear safely
  const xr = $('#xssResults'); 
  xr.textContent = '';
  renderList(xr, 'Inline event handlers', findings.xss.inline, (n) => `<div class="item"><div><span class="tag">${SecurityUtils.escaping.escapeHtml(n.tag)}</span> <span class="mono">${SecurityUtils.escaping.escapeHtml(n.handlers.join(', '))}</span></div><div class="mono">${SecurityUtils.escaping.escapeHtml(n.snippet)}</div></div>`);
  renderList(xr, 'javascript: links', findings.xss.jsHrefs, (a) => `<div class="item"><span class="tag">${SecurityUtils.escaping.escapeHtml(a.tag)}</span> <span class="mono">${SecurityUtils.escaping.escapeHtml(a.href)}</span></div>`);
  renderList(xr, 'Suspicious reflections', findings.xss.suspiciousReflections, (r) => `<div class="item">Param <b>${SecurityUtils.escaping.escapeHtml(r.key)}</b> reflected near script context <span class="mono">${SecurityUtils.escaping.escapeHtml(r.valueSample)}</span></div>`);

  // CSRF tab - clear safely
  const cr = $('#csrfResults'); 
  cr.textContent = '';
  renderList(cr, 'Forms', findings.csrf.forms, (f) => `<div class="item"><div><b>${SecurityUtils.escaping.escapeHtml(f.method)}</b> → <span class="mono">${SecurityUtils.escaping.escapeHtml(f.action)}</span></div><div>${f.hiddenTokenCount ? '<span class="ok">Token detected</span>' : '<span class="bad">No token</span>'}</div>${(f.tokenIssues||[]).map(i => `<div class="warn">• ${SecurityUtils.escaping.escapeHtml(i.issue)}${i.name? ' ('+SecurityUtils.escaping.escapeHtml(i.name)+')':''}</div>`).join('')}</div>`);

  // Cookies tab - safe table creation
  const ck = $('#cookieResults');
  ck.textContent = '';
  
  const cookieRows = (findings._raw.cookies || []).map(c => ({ 
    Name: c.name, 
    Domain: c.domain, 
    Path: c.path, 
    Secure: c.secure, 
    HttpOnly: c.httpOnly, 
    SameSite: c.sameSite, 
    Session: c.session, 
    Size: c.size 
  }));
  
  const itemDiv = SecurityUtils.escaping.createSafeElement('div', { class: 'item' });
  
  // Create table safely
  const table = SecurityUtils.dom.createTable(['Name', 'Domain', 'Flags', 'SameSite', 'Session', 'Size'], 
    cookieRows.map(r => ({
      Name: r.Name,
      Domain: r.Domain,
      Flags: (r.Secure ? 'Secure ' : '') + (r.HttpOnly ? 'HttpOnly' : ''),
      SameSite: r.SameSite,
      Session: r.Session,
      Size: r.Size
    }))
  );
  
  itemDiv.appendChild(table);
  
  // Add cookie issues safely
  const issuesDiv = SecurityUtils.escaping.createSafeElement('div', { class: 'item' });
  if (findings.cookies.issues && findings.cookies.issues.length > 0) {
    findings.cookies.issues.forEach(issue => {
      const severityClass = issue.severity === 'High' ? 'bad' : 
                           issue.severity === 'Medium' ? 'warn' : 'ok';
      const issueDiv = SecurityUtils.escaping.createSafeElement('div', { class: severityClass },
        `• ${issue.name}: ${issue.issue}`);
      issuesDiv.appendChild(issueDiv);
    });
  } else {
    const noIssues = SecurityUtils.escaping.createSafeElement('small', { class: 'muted' }, 
      'No cookie issues detected.');
    issuesDiv.appendChild(noIssues);
  }
  
  itemDiv.appendChild(issuesDiv);
  ck.appendChild(itemDiv);

  // SSL/HTTPS tab - safe creation
  const sr = $('#sslResults');
  sr.textContent = '';
  
  const sslItemDiv = SecurityUtils.escaping.createSafeElement('div', { class: 'item' });
  
  // Secure context status
  const secureDiv = SecurityUtils.escaping.createSafeElement('div');
  secureDiv.innerHTML = `Secure Context: ${findings.mixed.isSecureContext ? '<span class="ok">Yes</span>' : '<span class="bad">No</span>'}`;
  sslItemDiv.appendChild(secureDiv);
  
  // Mixed content count
  const mixedDiv = SecurityUtils.escaping.createSafeElement('div', {}, 
    `Mixed Content items: ${findings.mixed.items.length}`);
  sslItemDiv.appendChild(mixedDiv);
  
  // Mixed content items (up to 10)
  (findings.mixed.items || []).slice(0, 10).forEach(item => {
    const itemDiv = SecurityUtils.escaping.createSafeElement('div', { class: 'warn mono' },
      `• ${item.tag}[${item.attr}] → ${item.url}`);
    sslItemDiv.appendChild(itemDiv);
  });
  
  // HSTS status
  const hstsDiv = SecurityUtils.escaping.createSafeElement('div', { 
    class: findings.headers.hstsOk ? 'ok' : 'warn' 
  }, `HSTS header: ${findings.headers.hstsOk ? 'Present/looks OK' : 'Missing or incomplete'}`);
  sslItemDiv.appendChild(hstsDiv);
  
  // Note
  const noteDiv = SecurityUtils.escaping.createSafeElement('small', { class: 'muted' },
    'Note: detailed TLS/cipher/cert info requires a remote scanner. Configure in Options if desired.');
  sslItemDiv.appendChild(noteDiv);
  
  sr.appendChild(sslItemDiv);

  // Headers tab - safe creation
  const hr = $('#headerResults');
  hr.textContent = '';
  
  const headerItemDiv = SecurityUtils.escaping.createSafeElement('div', { class: 'item' });
  
  // Present headers
  if (findings.headers.present && findings.headers.present.length > 0) {
    findings.headers.present.forEach(h => {
      const headerDiv = SecurityUtils.escaping.createSafeElement('div', { class: 'ok' });
      headerDiv.innerHTML = `• ${SecurityUtils.escaping.escapeHtml(h.name)}: <span class="mono">${SecurityUtils.escaping.escapeHtml(h.value)}</span>`;
      headerItemDiv.appendChild(headerDiv);
    });
  } else {
    const noHeaders = SecurityUtils.escaping.createSafeElement('small', { class: 'muted' },
      'No security headers detected.');
    headerItemDiv.appendChild(noHeaders);
  }
  
  // Missing headers
  findings.headers.missing.forEach(headerName => {
    const missingDiv = SecurityUtils.escaping.createSafeElement('div', { class: 'warn' });
    missingDiv.innerHTML = `• Missing: <b>${SecurityUtils.escaping.escapeHtml(headerName)}</b> — ${SecurityUtils.escaping.escapeHtml(HEADER_RECS[headerName] || '')}`;
    headerItemDiv.appendChild(missingDiv);
  });
  
  // Header notes/issues
  findings.headers.notes.forEach(note => {
    const noteDiv = SecurityUtils.escaping.createSafeElement('div', { class: 'warn' },
      `• ${note.name}: ${note.issue}`);
    headerItemDiv.appendChild(noteDiv);
  });
  
  hr.appendChild(headerItemDiv);

  // Export with permission request
  $('#exportJson').onclick = async () => { 
    const hasPermission = await SecurityUtils.permissions.requestDownloadPermissions();
    if (!hasPermission) {
      alert('Download permission is required for exporting files.');
      return;
    }
    
    const blob = new Blob([JSON.stringify({ score, ...findings }, null, 2)], { type: 'application/json' }); 
    const url = URL.createObjectURL(blob); 
    chrome.downloads ? chrome.downloads.download({ url, filename: 'security-report.json' }) : window.open(url); 
  };
  
  $('#exportCsv').onclick = async () => { 
    const hasPermission = await SecurityUtils.permissions.requestDownloadPermissions();
    if (!hasPermission) {
      alert('Download permission is required for exporting files.');
      return;
    }
    
    const rows = [ 
      ...findings.cookies.issues.map(i => ({ Type:'Cookie', Name:i.name, Issue:i.issue, Severity:i.severity })), 
      ...findings.headers.missing.map(n => ({ Type:'Header', Name:n, Issue:'Missing', Severity:'High' })), 
      ...findings.headers.notes.map(n => ({ Type:'Header', Name:n.name, Issue:n.issue, Severity:'Medium' })), 
      ...findings.mixed.items.map(m => ({ Type:'MixedContent', Name:`${m.tag}[${m.attr}]`, Issue:m.url, Severity:'High' })) 
    ]; 
    const csv = toCsv(rows); 
    const blob = new Blob([csv], { type: 'text/csv' }); 
    const url = URL.createObjectURL(blob); 
    chrome.downloads ? chrome.downloads.download({ url, filename: 'security-report.csv' }) : window.open(url); 
  };
}

document.getElementById('runAll').addEventListener('click', runAll);

// Init
(async () => {
  const tab = await getActiveTab(); await syncAllowUI(tab);
  const set = await getAllowlist(); const currentOrigin = new URL(tab.url).origin;
  if (set.has(currentOrigin)) runAll();
})();
