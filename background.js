// Self-contained MV3 service worker (no imports), FLAT layout version
// Import security utilities
importScripts('security-utils.js');

// Utility functions that used to live in security-analyzer.js:
const normalizeHeaders = (headers = []) => {
  const out = {};
  headers.forEach(h => {
    if (!h || !h.name) return;
    out[h.name.toLowerCase()] = (h.value || "").trim();
  });
  return out;
};

const analyzeSecurityHeaders = (hmap = {}) => {
  const present = [];
  const missing = [];
  const comprehensive = [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "referrer-policy",
    "permissions-policy",
    "access-control-allow-origin",
    "access-control-allow-credentials", 
    "access-control-expose-headers",
    "access-control-max-age",
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy", 
    "cross-origin-resource-policy",
    "expect-ct",
    "x-xss-protection"
  ];
  
  comprehensive.forEach(k => { 
    if (hmap[k]) present.push({ name: k, value: hmap[k] }); 
    else missing.push(k); 
  });
  
  const notes = [];
  const corsIssues = [];
  
  // Enhanced header validation
  if (hmap["x-content-type-options"] && hmap["x-content-type-options"].toLowerCase() !== "nosniff") {
    notes.push({ name: "x-content-type-options", issue: "Should be 'nosniff'" });
  }
  if (hmap["x-frame-options"] && !/(deny|sameorigin)/i.test(hmap["x-frame-options"])) {
    notes.push({ name: "x-frame-options", issue: "Use DENY or SAMEORIGIN" });
  }
  if (hmap["content-security-policy"] && /unsafe-inline|unsafe-eval/i.test(hmap["content-security-policy"])) {
    notes.push({ name: "content-security-policy", issue: "Avoid 'unsafe-inline'/'unsafe-eval' if possible" });
  }
  
  // CORS analysis
  const acao = hmap["access-control-allow-origin"];
  const acac = hmap["access-control-allow-credentials"];
  
  if (acao === "*" && acac === "true") {
    corsIssues.push({
      severity: "HIGH",
      issue: "Dangerous CORS config: wildcard origin with credentials allowed"
    });
  }
  if (acao === "*") {
    corsIssues.push({
      severity: "MEDIUM", 
      issue: "CORS allows any origin - review if appropriate"
    });
  }
  if (acac === "true" && !acao) {
    corsIssues.push({
      severity: "LOW",
      issue: "Credentials allowed but no ACAO header set"
    });
  }
  
  // Additional security header checks
  if (hmap["x-xss-protection"] && hmap["x-xss-protection"] !== "0") {
    notes.push({ name: "x-xss-protection", issue: "Consider setting to '0' as it can introduce vulnerabilities" });
  }
  
  if (hmap["expect-ct"] && !/enforce/i.test(hmap["expect-ct"])) {
    notes.push({ name: "expect-ct", issue: "Consider using 'enforce' directive for better security" });
  }
  
  const hsts = hmap["strict-transport-security"] || "";
  const hstsOk = /max-age=\d+/.test(hsts);
  const hstsSubdomains = /includeSubDomains/i.test(hsts);
  const hstsPreload = /preload/i.test(hsts);
  
  return { 
    present, 
    missing, 
    notes, 
    corsIssues,
    hstsOk, 
    hstsSubdomains,
    hstsPreload,
    raw: hmap 
  };
};

const scoreFromFindings = ({ headers = {}, cookies = {}, xss = {}, csrf = {}, mixed = {}, jwt = {}, oauth = {}, session = {} }) => {
  let score = 100;
  const missCount = (headers.missing || []).length;
  score -= Math.min(40, missCount * 3); // Reduced per-header penalty since we check more headers now
  score -= Math.min(25, (cookies.issues || []).length * 3);
  
  // Enhanced XSS scoring
  if (xss.enhanced && xss.enhanced.riskScore) {
    score -= Math.min(20, xss.enhanced.riskScore * 0.2);
  }
  if (xss.vulnerableCount) score -= Math.min(15, xss.vulnerableCount * 5);
  if (xss.sqlInjection && xss.sqlInjection.length) score -= Math.min(15, xss.sqlInjection.length * 8);
  
  if (csrf.issues && csrf.issues.length) score -= Math.min(10, csrf.issues.length * 3);
  if (mixed.items && mixed.items.length) score -= Math.min(10, mixed.items.length * 2);
  
  // New scoring factors
  if (jwt.totalFound > 0) score -= Math.min(10, jwt.totalFound * 3); // JWT exposure risk
  if (oauth.totalFound > 0) score -= Math.min(15, oauth.totalFound * 5); // OAuth param exposure
  if (session.issues && session.issues.length) score -= Math.min(10, session.issues.length * 4);
  
  // CORS issues
  if (headers.corsIssues && headers.corsIssues.length) {
    const corsDeduction = headers.corsIssues.reduce((acc, issue) => {
      return acc + (issue.severity === 'HIGH' ? 15 : issue.severity === 'MEDIUM' ? 10 : 5);
    }, 0);
    score -= Math.min(20, corsDeduction);
  }
  
  return Math.max(0, Math.round(score));
};

const analyzeTlsInfo = (url) => {
  const tlsInfo = {
    isHttps: false,
    protocol: null,
    certificateInfo: null,
    mixedContentRisk: false,
    tlsVersion: null,
    weakCiphers: false,
    certificateErrors: []
  };
  
  try {
    const urlObj = new URL(url);
    tlsInfo.isHttps = urlObj.protocol === 'https:';
    tlsInfo.protocol = urlObj.protocol;
    
    // Note: Full TLS/certificate details require webRequest or external scanning
    // This provides basic analysis based on URL and available browser APIs
    
    if (!tlsInfo.isHttps) {
      tlsInfo.certificateErrors.push({
        type: 'protocol',
        severity: 'HIGH',
        message: 'Site not using HTTPS - all communication unencrypted'
      });
    }
    
    // Check for mixed content risk indicators  
    if (tlsInfo.isHttps) {
      tlsInfo.mixedContentRisk = true; // Will be refined by mixed content scan
    }
    
  } catch (e) {
    tlsInfo.certificateErrors.push({
      type: 'url_parse',
      severity: 'MEDIUM', 
      message: 'Unable to parse URL for TLS analysis'
    });
  }
  
  return tlsInfo;
};

/* ===================== ADDED: allowlist state ===================== */
let allowlist = new Set();

async function loadAllowlist() {
  const res = await chrome.storage.sync.get({ allowlist: [] });
  allowlist = new Set(res.allowlist || []);
}
loadAllowlist();

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'sync' && changes.allowlist) {
    allowlist = new Set(changes.allowlist.newValue || []);
  }
});

function isAllowed(url) {
  try { return allowlist.has(new URL(url).origin); }
  catch { return false; }
}
/* =================== /ADDED: allowlist state ====================== */

// Capture latest response headers per tab (only if allowed)
const tabHeaders = new Map();

// Initialize webRequest listener with permission check
async function initWebRequestListener() {
  const hasPermission = await SecurityUtils.permissions.hasWebRequestPermissions();
  if (!hasPermission) {
    console.warn('WebRequest permission not granted - header capture disabled');
    return;
  }

  chrome.webRequest.onHeadersReceived.addListener(
    (details) => {
      if (details.tabId >= 0 && isAllowed(details.url)) { // <-- gated
        tabHeaders.set(details.tabId, {
          url: details.url,
          time: Date.now(),
          headers: details.responseHeaders || [],
          statusLine: details.statusLine || ""
        });
      }
    },
    { urls: ["<all_urls>"] },
    ["responseHeaders", "extraHeaders"]
  );
}

// Initialize on startup
initWebRequestListener();

async function getCookiesForUrl(url) {
  // Check allowlist and request permissions dynamically
  if (!isAllowed(url)) return [];
  
  // Check cookie permissions (don't request from service worker)
  const origin = new URL(url).origin;
  const hasPermission = await SecurityUtils.permissions.hasPermission('cookies', origin + '/*');
  if (!hasPermission) {
    console.warn('Cookie permission not granted for:', url);
    return [];
  }
  
  try {
    const all = await chrome.cookies.getAll({ url });
    return all.map(c => ({
      name: c.name,
      domain: c.domain,
      path: c.path,
      secure: !!c.secure,
      httpOnly: !!c.httpOnly,
      sameSite: c.sameSite || "unspecified",
      session: !!c.session,
      expirationDate: c.expirationDate || null,
      size: (c.value || "").length
    }));
  } catch (error) {
    console.error('Failed to get cookies:', error);
    return [];
  }
}

function analyzeCookies(list = []) {
  const issues = [];
  for (const ck of list) {
    if (!ck.secure) issues.push({ name: ck.name, issue: "Missing Secure flag", severity: "High" });
    if (!ck.httpOnly) issues.push({ name: ck.name, issue: "Missing HttpOnly flag", severity: "High" });
    const ss = (ck.sameSite || "").toLowerCase();
    if (!ss || ss === "no_restriction" || ss === "unspecified") {
      issues.push({ name: ck.name, issue: "SameSite not set or lax", severity: "Medium" });
    }
    if (ck.session === false && ck.expirationDate && ck.expirationDate > (Date.now()/1000 + 60*60*24*365*2)) {
      issues.push({ name: ck.name, issue: "Very long expiry (>2y)", severity: "Low" });
    }
  }
  return { count: list.length, issues };
}

chrome.runtime.onInstalled.addListener(async () => {
  console.log("Security Testing Helper installed");
  
  // Schedule periodic cleanup
  chrome.alarms.create('cleanup-storage', { 
    delayInMinutes: 1, 
    periodInMinutes: 60 * 24 // Daily cleanup
  });
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === 'cleanup-storage') {
    const cleaned = await SecurityUtils.storage.cleanup();
    console.log(`Storage cleanup completed. Removed ${cleaned} old entries.`);
  }
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      if (msg.type === "GET_HEADERS") {
        const th = tabHeaders.get(msg.tabId);
        const hmap = th ? normalizeHeaders(th.headers) : {};
        const analysis = analyzeSecurityHeaders(hmap); // always compute
        return sendResponse({
          ok: true,
          url: th ? th.url : null,
          headers: hmap,
          analysis
        });
      }

      if (msg.type === "GET_COOKIES") {
        const cookies = await getCookiesForUrl(msg.url); // gated inside
        const analysis = analyzeCookies(cookies);
        return sendResponse({ ok: true, cookies, analysis });
      }

      if (msg.type === "COMPUTE_SCORE") {
        const score = scoreFromFindings(msg.payload || {});
        return sendResponse({ ok: true, score });
      }

      if (msg.type === "SAVE_HISTORY") {
        const key = `history:${Date.now()}`;
        // Use temporary storage for history
        await SecurityUtils.storage.setTemporary(key, msg.data);
        return sendResponse({ ok: true, key });
      }

      if (msg.type === "LIST_HISTORY_KEYS") {
        const all = await chrome.storage.session.get(null);
        const keys = Object.keys(all).filter(k => k.startsWith("history:"));
        return sendResponse({ ok: true, keys: keys.sort().reverse().slice(0, 50) });
      }

      if (msg.type === "GET_HISTORY_ITEM") {
        const item = await SecurityUtils.storage.getTemporary(msg.key);
        return sendResponse({ ok: true, item });
      }

      if (msg.type === "REQUEST_DOWNLOAD_PERMISSION") {
        // Service workers cannot request permissions - this should be handled by popup
        console.warn('Download permission requests should be handled by popup, not service worker');
        return sendResponse({ ok: false, error: 'Permission requests not supported in service worker' });
      }

      if (msg.type === "INIT_WEBREQUEST_LISTENER") {
        await initWebRequestListener();
        return sendResponse({ ok: true });
      }

      if (msg.type === "CLEANUP_STORAGE") {
        const cleaned = await SecurityUtils.storage.cleanup();
        return sendResponse({ ok: true, cleaned });
      }

      if (msg.type === "ANALYZE_TLS") {
        const tlsAnalysis = analyzeTlsInfo(msg.url);
        return sendResponse({ ok: true, tls: tlsAnalysis });
      }

    } catch (e) {
      return sendResponse({ ok: false, error: e?.message || String(e) });
    }
  })();
  return true; // async
});
