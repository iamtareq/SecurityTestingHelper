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
  const want = [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "referrer-policy",
    "permissions-policy"
  ];
  want.forEach(k => { if (hmap[k]) present.push({ name:k, value:hmap[k] }); else missing.push(k); });
  const notes = [];
  if (hmap["x-content-type-options"] && hmap["x-content-type-options"].toLowerCase() !== "nosniff") {
    notes.push({ name: "x-content-type-options", issue: "Should be 'nosniff'" });
  }
  if (hmap["x-frame-options"] && !/(deny|sameorigin)/i.test(hmap["x-frame-options"])) {
    notes.push({ name: "x-frame-options", issue: "Use DENY or SAMEORIGIN" });
  }
  if (hmap["content-security-policy"] && /unsafe-inline|unsafe-eval/i.test(hmap["content-security-policy"])) {
    notes.push({ name: "content-security-policy", issue: "Avoid 'unsafe-inline'/'unsafe-eval' if possible" });
  }
  const hsts = hmap["strict-transport-security"] || "";
  const hstsOk = /max-age=\d+/.test(hsts);
  return { present, missing, notes, hstsOk, raw: hmap };
};

const scoreFromFindings = ({ headers = {}, cookies = {}, xss = {}, csrf = {}, mixed = {} }) => {
  let score = 100;
  const missCount = (headers.missing || []).length;
  score -= Math.min(40, missCount * 6);
  score -= Math.min(25, (cookies.issues || []).length * 3);
  if (xss.vulnerableCount) score -= Math.min(15, xss.vulnerableCount * 5);
  if (csrf.issues && csrf.issues.length) score -= Math.min(10, csrf.issues.length * 3);
  if (mixed.items && mixed.items.length) score -= Math.min(10, mixed.items.length * 2);
  return Math.max(0, Math.round(score));
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
  const hasPermission = await SecurityUtils.permissions.requestWebRequestPermissions();
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
  
  // Request cookie permissions dynamically
  const hasPermission = await SecurityUtils.permissions.requestCookiePermissions(url);
  if (!hasPermission) {
    console.warn('Cookie permission denied for:', url);
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
        const hasPermission = await SecurityUtils.permissions.requestDownloadPermissions();
        return sendResponse({ ok: true, granted: hasPermission });
      }

      if (msg.type === "CLEANUP_STORAGE") {
        const cleaned = await SecurityUtils.storage.cleanup();
        return sendResponse({ ok: true, cleaned });
      }

    } catch (e) {
      return sendResponse({ ok: false, error: e?.message || String(e) });
    }
  })();
  return true; // async
});
