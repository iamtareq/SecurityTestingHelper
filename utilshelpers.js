(function () {
  const H = {};

  H.shannonEntropy = (str = "") => {
    const map = new Map();
    for (const ch of str) map.set(ch, (map.get(ch) || 0) + 1);
    let entropy = 0;
    for (const [, count] of map) {
      const p = count / str.length;
      entropy -= p * (Math.log(p) / Math.log(2));
    }
    return Number.isFinite(entropy) ? entropy : 0;
  };

  H.isLikelyCsrfTokenName = (name = "") => /csrf|token|authenticity|xsrf/i.test(name);

  H.collectForms = () => {
    const forms = [...document.forms].map((f, idx) => {
      const inputs = [...f.elements].filter(el => el.name || el.id).map(el => ({
        tag: el.tagName.toLowerCase(),
        type: (el.getAttribute("type") || "").toLowerCase(),
        name: el.name || el.id || "",
        valueLength: (el.value || "").length,
        maxLength: Number(el.getAttribute("maxlength") || 0),
        autocomplete: el.getAttribute("autocomplete"),
        isHidden: el.type === "hidden" || el.tagName.toLowerCase() === "input" && el.getAttribute("type") === "hidden"
      }));
      return {
        index: idx,
        action: f.getAttribute("action") || location.href,
        method: (f.getAttribute("method") || "GET").toUpperCase(),
        inputs,
      };
    });
    return { url: location.href, forms };
  };

  H.scanDomForInlineHandlers = () => {
    const nodes = [...document.querySelectorAll("*[onload], *[onclick], *[onerror], *[onmouseover], *[onfocus], *[oninput], *[onchange]")];
    return nodes.map(n => ({
      tag: n.tagName.toLowerCase(),
      snippet: n.outerHTML.slice(0, 160) + (n.outerHTML.length > 160 ? "…" : ""),
      handlers: [...n.getAttributeNames()].filter(a => a.startsWith("on"))
    }));
  };

  H.findMixedContent = () => {
    if (location.protocol !== "https:") return { isSecureContext: window.isSecureContext, items: [] };
    const attrs = ["src", "href", "data", "poster"];
    const items = [];
    document.querySelectorAll("*").forEach(el => {
      for (const a of attrs) {
        const v = el.getAttribute && el.getAttribute(a);
        if (v && /^http:\/\//i.test(v)) items.push({ tag: el.tagName.toLowerCase(), attr: a, url: v });
      }
    });
    return { isSecureContext: window.isSecureContext, items };
  };

  H.highlightElements = (elements = [], color = "#f97316") => {
    const marks = [];
    elements.forEach(e => {
      if (e && e instanceof Element) {
        const r = document.createElement("div");
        const rect = e.getBoundingClientRect();
        r.style.cssText = `position: fixed; left:${rect.left + window.scrollX}px; top:${rect.top + window.scrollY}px; width:${rect.width}px; height:${rect.height}px; border: 2px solid ${color}; z-index: 2147483647; pointer-events:none; mix-blend-mode: multiply;`;
        document.documentElement.appendChild(r);
        marks.push(r);
      }
    });
    setTimeout(() => marks.forEach(m => m.remove()), 2500);
  };

  window.STH_HELPERS = H;
})();