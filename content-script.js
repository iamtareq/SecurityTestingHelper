// Runs in page context to do DOM-oriented checks (XSS heuristics, CSRF presence, mixed content)
(function () {
  const H = window.STH_HELPERS;

  const passiveXssScan = () => {
    const inline = H.scanDomForInlineHandlers();
    const jsHrefs = [...document.querySelectorAll('[href^="javascript:"]')].map(a => ({
      tag: a.tagName.toLowerCase(),
      href: a.getAttribute('href').slice(0, 100) + (a.getAttribute('href').length > 100 ? '…' : '')
    }));

    const qp = new URLSearchParams(location.search);
    const suspiciousReflections = [];
    qp.forEach((val, key) => {
      const needle = val.trim();
      if (!needle) return;
      const html = document.documentElement.innerHTML;
      if (html.includes(`<script>${needle}`) || html.includes(`onload=${needle}`)) {
        suspiciousReflections.push({ key, valueSample: needle.slice(0, 50) });
      }
    });

    return { inline, jsHrefs, suspiciousReflections };
  };

  const csrfScan = () => {
    const { forms } = H.collectForms();
    const details = [];
    for (const f of forms) {
      const hiddenTokens = f.inputs.filter(i => i.isHidden && H.isLikelyCsrfTokenName(i.name));
      const tokenIssues = [];
      hiddenTokens.forEach(t => {
        const entropy = H.shannonEntropy(String(t.valueLength > 0 ? 'x'.repeat(t.valueLength) : '')); // no value sniffing
        if (t.valueLength && t.valueLength < 16) tokenIssues.push({ name: t.name, issue: 'Token length looks short (<16)' });
      });
      if (hiddenTokens.length === 0) tokenIssues.push({ issue: 'No CSRF token hidden field detected' });
      details.push({ method: f.method, action: f.action, hiddenTokenCount: hiddenTokens.length, tokenIssues });
    }
    return { forms: details };
  };

  const mixedContentScan = () => H.findMixedContent();

  const runAll = () => {
    const xss = passiveXssScan();
    const csrf = csrfScan();
    const mixed = mixedContentScan();
    return { xss, csrf, mixed };
  };

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.type === 'RUN_CONTENT_SCANS') {
      try {
        const data = runAll();
        const nodes = [...document.querySelectorAll("*[onload], *[onclick], *[onerror], *[onmouseover], *[onfocus], *[oninput], *[onchange]")];
        H.highlightElements(nodes, '#f97316');
        sendResponse({ ok: true, data });
      } catch (e) {
        sendResponse({ ok: false, error: e?.message || String(e) });
      }
      return true;
    }
  });
})();