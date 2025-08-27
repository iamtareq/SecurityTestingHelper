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

  // Check if webRequest permission is needed for header analysis
  const hasWebRequestPermission = await SecurityUtils.permissions.hasPermission('webRequest', '<all_urls>');
  if (!hasWebRequestPermission) {
    const userWantsHeaders = confirm('To analyze security headers, this extension needs permission to access web request data. Grant permission now?');
    if (userWantsHeaders) {
      const granted = await SecurityUtils.permissions.requestPermissionIfNeeded('webRequest', '<all_urls>');
      if (granted) {
        // Reinitialize the webRequest listener in the background
        await chrome.runtime.sendMessage({ type: 'INIT_WEBREQUEST_LISTENER' });
      }
    }
  }

  const content = await chrome.tabs.sendMessage(tab.id, { type: 'RUN_CONTENT_SCANS' }).catch(() => null);
  const hdr     = await chrome.runtime.sendMessage({ type: 'GET_HEADERS', tabId: tab.id }).catch(() => null);
  const cks     = await chrome.runtime.sendMessage({ type: 'GET_COOKIES', url: tab.url }).catch(() => null);
  const tls     = await chrome.runtime.sendMessage({ type: 'ANALYZE_TLS', url: tab.url }).catch(() => null);

  const findings = {
    xss:     content?.ok ? content.data.xss   : { inline:[], jsHrefs:[], suspiciousReflections:[], enhanced: {}, sqlInjection: [] },
    csrf:    content?.ok ? content.data.csrf  : { forms:[] },
    mixed:   content?.ok ? content.data.mixed : { items:[], isSecureContext:false },
    jwt:     content?.ok ? content.data.jwt   : { pageTokens:[], localStorage:[], sessionStorage:[], totalFound:0 },
    oauth:   content?.ok ? content.data.oauth : { foundParams:[], totalFound:0, inUrl:false, inHash:false },
    session: content?.ok ? content.data.session : { cookieCount:0, sessionStorageKeys:0, localStorageKeys:0, issues:[] },
    headers: hdr?.analysis ?? { present:[], missing:[], notes:[], corsIssues:[], hstsOk:false },
    cookies: cks?.analysis ?? { count:0, issues:[] },
    tls:     tls?.tls ?? { isHttps:false, certificateErrors:[] },
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
    ['SQL Injection', findings.xss.sqlInjection ? findings.xss.sqlInjection.length : 0],
    ['Forms Analyzed', findings.csrf.forms.length],
    ['JWT Tokens Found', findings.jwt.totalFound],
    ['OAuth Parameters', findings.oauth.totalFound],
    ['Session Issues', findings.session.issues.length],
    ['CORS Issues', findings.headers.corsIssues ? findings.headers.corsIssues.length : 0]
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
  
  // Enhanced XSS findings
  if (findings.xss.enhanced && findings.xss.enhanced.reflectedParams && findings.xss.enhanced.reflectedParams.length > 0) {
    const enhancedDiv = SecurityUtils.escaping.createSafeElement('div', { class: 'item' });
    const titleDiv = SecurityUtils.escaping.createSafeElement('h4', {}, 'Enhanced XSS Analysis');
    enhancedDiv.appendChild(titleDiv);
    
    findings.xss.enhanced.reflectedParams.forEach(param => {
      const riskClass = param.riskLevel === 'HIGH' ? 'bad' : param.riskLevel === 'MEDIUM' ? 'warn' : 'ok';
      const paramDiv = SecurityUtils.escaping.createSafeElement('div', { class: riskClass });
      paramDiv.innerHTML = `Parameter <b>${SecurityUtils.escaping.escapeHtml(param.parameter)}</b> reflected in ${param.contexts.join(', ')} context(s) - Risk: ${param.riskLevel}`;
      enhancedDiv.appendChild(paramDiv);
    });
    
    if (findings.xss.enhanced.riskScore > 0) {
      const scoreDiv = SecurityUtils.escaping.createSafeElement('div', { class: 'warn' });
      scoreDiv.textContent = `XSS Risk Score: ${findings.xss.enhanced.riskScore}/100`;
      enhancedDiv.appendChild(scoreDiv);
    }
    
    xr.appendChild(enhancedDiv);
  }
  
  // SQL Injection findings
  if (findings.xss.sqlInjection && findings.xss.sqlInjection.length > 0) {
    renderList(xr, 'SQL Injection Patterns Detected', findings.xss.sqlInjection, (sql) => {
      const patterns = sql.patterns.map(p => `Pattern: ${SecurityUtils.escaping.escapeHtml(p.pattern)}`).join('<br>');
      return `<div class="item bad"><div><b>${SecurityUtils.escaping.escapeHtml(sql.element)}</b> ${sql.name ? '(' + SecurityUtils.escaping.escapeHtml(sql.name) + ')' : ''}</div><div class="mono">${patterns}</div></div>`;
    });
  }

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
  
  // CORS issues
  if (findings.headers.corsIssues && findings.headers.corsIssues.length > 0) {
    const corsTitle = SecurityUtils.escaping.createSafeElement('h4', {}, 'CORS Policy Issues');
    headerItemDiv.appendChild(corsTitle);
    
    findings.headers.corsIssues.forEach(issue => {
      const severityClass = issue.severity === 'HIGH' ? 'bad' : 
                           issue.severity === 'MEDIUM' ? 'warn' : 'ok';
      const corsDiv = SecurityUtils.escaping.createSafeElement('div', { class: severityClass },
        `• ${issue.issue} (${issue.severity})`);
      headerItemDiv.appendChild(corsDiv);
    });
  }
  
  hr.appendChild(headerItemDiv);

  // Auth/Session tab - safe creation
  const ar = $('#authResults');
  ar.textContent = '';
  
  const authItemDiv = SecurityUtils.escaping.createSafeElement('div', { class: 'item' });
  
  // JWT Token Analysis
  const jwtTitle = SecurityUtils.escaping.createSafeElement('h4', {}, 'JWT Token Analysis');
  authItemDiv.appendChild(jwtTitle);
  
  if (findings.jwt.totalFound > 0) {
    const jwtSummary = SecurityUtils.escaping.createSafeElement('div', { class: 'warn' },
      `Found ${findings.jwt.totalFound} JWT token(s) - potential exposure risk`);
    authItemDiv.appendChild(jwtSummary);
    
    if (findings.jwt.pageTokens.length > 0) {
      const pageDiv = SecurityUtils.escaping.createSafeElement('div', { class: 'warn' },
        `• ${findings.jwt.pageTokens.length} token(s) in page content`);
      authItemDiv.appendChild(pageDiv);
    }
    
    if (findings.jwt.localStorage.length > 0) {
      const localDiv = SecurityUtils.escaping.createSafeElement('div', { class: 'warn' },
        `• ${findings.jwt.localStorage.length} token(s) in localStorage`);
      authItemDiv.appendChild(localDiv);
    }
    
    if (findings.jwt.sessionStorage.length > 0) {
      const sessionDiv = SecurityUtils.escaping.createSafeElement('div', { class: 'warn' },
        `• ${findings.jwt.sessionStorage.length} token(s) in sessionStorage`);
      authItemDiv.appendChild(sessionDiv);
    }
  } else {
    const noJwt = SecurityUtils.escaping.createSafeElement('div', { class: 'ok' },
      'No JWT tokens detected');
    authItemDiv.appendChild(noJwt);
  }
  
  // OAuth Flow Analysis
  const oauthTitle = SecurityUtils.escaping.createSafeElement('h4', {}, 'OAuth Flow Security');
  authItemDiv.appendChild(oauthTitle);
  
  if (findings.oauth.totalFound > 0) {
    const oauthWarning = SecurityUtils.escaping.createSafeElement('div', { class: 'bad' },
      `Found ${findings.oauth.totalFound} OAuth parameter(s) in URL - sensitive data exposure!`);
    authItemDiv.appendChild(oauthWarning);
    
    findings.oauth.foundParams.forEach(param => {
      const paramDiv = SecurityUtils.escaping.createSafeElement('div', { class: 'bad' },
        `• ${param.parameter} in ${param.location} (${param.length} chars)`);
      authItemDiv.appendChild(paramDiv);
    });
  } else {
    const noOauth = SecurityUtils.escaping.createSafeElement('div', { class: 'ok' },
      'No OAuth parameters detected in URL');
    authItemDiv.appendChild(noOauth);
  }
  
  // Session Management Analysis
  const sessionTitle = SecurityUtils.escaping.createSafeElement('h4', {}, 'Session Management');
  authItemDiv.appendChild(sessionTitle);
  
  const sessionInfo = SecurityUtils.escaping.createSafeElement('div', {},
    `Cookies: ${findings.session.cookieCount}, localStorage keys: ${findings.session.localStorageKeys}, sessionStorage keys: ${findings.session.sessionStorageKeys}`);
  authItemDiv.appendChild(sessionInfo);
  
  if (findings.session.issues.length > 0) {
    findings.session.issues.forEach(issue => {
      const severityClass = issue.type === 'localStorage' ? 'warn' : 'bad';
      const issueDiv = SecurityUtils.escaping.createSafeElement('div', { class: severityClass },
        `• ${issue.issue} (${issue.key || issue.type})`);
      authItemDiv.appendChild(issueDiv);
    });
  } else {
    const noSessionIssues = SecurityUtils.escaping.createSafeElement('div', { class: 'ok' },
      'No obvious session management issues detected');
    authItemDiv.appendChild(noSessionIssues);
  }
  
  ar.appendChild(authItemDiv);

  // Advanced tab - safe creation
  const advr = $('#advancedResults');
  advr.textContent = '';
  
  const advItemDiv = SecurityUtils.escaping.createSafeElement('div', { class: 'item' });
  
  // TLS/Certificate Analysis
  const tlsTitle = SecurityUtils.escaping.createSafeElement('h4', {}, 'TLS/Certificate Analysis');
  advItemDiv.appendChild(tlsTitle);
  
  const httpsStatus = SecurityUtils.escaping.createSafeElement('div', { 
    class: findings.tls.isHttps ? 'ok' : 'bad'
  }, `HTTPS: ${findings.tls.isHttps ? 'Enabled' : 'Not enabled'}`);
  advItemDiv.appendChild(httpsStatus);
  
  if (findings.tls.certificateErrors && findings.tls.certificateErrors.length > 0) {
    findings.tls.certificateErrors.forEach(error => {
      const errorClass = error.severity === 'HIGH' ? 'bad' : 'warn';
      const errorDiv = SecurityUtils.escaping.createSafeElement('div', { class: errorClass },
        `• ${error.message} (${error.type})`);
      advItemDiv.appendChild(errorDiv);
    });
  }
  
  // Enhanced HSTS Analysis
  if (findings.tls.isHttps) {
    const hstsAdvanced = SecurityUtils.escaping.createSafeElement('div', {},
      `HSTS: ${findings.headers.hstsOk ? 'Present' : 'Missing'}, Subdomains: ${findings.headers.hstsSubdomains ? 'Yes' : 'No'}, Preload: ${findings.headers.hstsPreload ? 'Yes' : 'No'}`);
    advItemDiv.appendChild(hstsAdvanced);
  }
  
  const tlsNote = SecurityUtils.escaping.createSafeElement('small', { class: 'muted' },
    'Note: Detailed certificate chain, TLS version, and cipher analysis require external tools or APIs');
  advItemDiv.appendChild(tlsNote);
  
  advr.appendChild(advItemDiv);

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
