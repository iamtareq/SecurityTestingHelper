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

  H.scanForSqlInjection = (text = "") => {
    if (!text || typeof text !== 'string') return { found: false, patterns: [] };
    
    // Import patterns from constants
    const patterns = [
      /('|\"|`)\s*(or|and)\s*('|\"|`|[0-9])/gi,
      /(union|select|insert|update|delete|drop|create|alter|exec|execute)/gi,
      /(\bor\b|\band\b)\s*[0-9]*\s*=\s*[0-9]*/gi,
      /(--|#|\/\*|\*\/)/g,
      /waitfor\s+delay/gi,
      /information_schema/gi,
      /@@version/gi
    ];
    
    const foundPatterns = [];
    patterns.forEach((pattern, index) => {
      const matches = text.match(pattern);
      if (matches) {
        foundPatterns.push({
          pattern: pattern.source,
          matches: matches.slice(0, 3) // Limit to first 3 matches
        });
      }
    });
    
    return { found: foundPatterns.length > 0, patterns: foundPatterns };
  };

  H.detectJwtTokens = () => {
    const jwtPattern = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;
    const bearerPattern = /Bearer\s+eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;
    
    const tokens = [];
    const pageText = document.documentElement.innerHTML;
    const localStorageTokens = [];
    const sessionStorageTokens = [];
    
    // Check page content
    let match;
    while ((match = jwtPattern.exec(pageText)) !== null) {
      tokens.push({
        location: 'page_content',
        token: match[0].substring(0, 50) + '...', // Truncate for security
        length: match[0].length
      });
    }
    
    // Check localStorage
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        const value = localStorage.getItem(key);
        if (jwtPattern.test(value)) {
          localStorageTokens.push({
            key: key,
            hasJwt: true,
            length: value.length
          });
        }
      }
    } catch (e) {
      // Access denied to localStorage
    }
    
    // Check sessionStorage  
    try {
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        const value = sessionStorage.getItem(key);
        if (jwtPattern.test(value)) {
          sessionStorageTokens.push({
            key: key,
            hasJwt: true,
            length: value.length
          });
        }
      }
    } catch (e) {
      // Access denied to sessionStorage
    }
    
    return {
      pageTokens: tokens,
      localStorage: localStorageTokens,
      sessionStorage: sessionStorageTokens,
      totalFound: tokens.length + localStorageTokens.length + sessionStorageTokens.length
    };
  };

  H.detectOauthFlows = () => {
    const url = new URL(location.href);
    const searchParams = url.searchParams;
    const hash = url.hash;
    
    const oauthParams = [];
    const sensitiveParams = ['access_token', 'refresh_token', 'authorization_code', 'client_secret', 'state'];
    
    // Check URL parameters
    sensitiveParams.forEach(param => {
      if (searchParams.has(param)) {
        oauthParams.push({
          parameter: param,
          location: 'url_params',
          hasValue: searchParams.get(param).length > 0,
          length: searchParams.get(param).length
        });
      }
    });
    
    // Check hash fragment
    if (hash) {
      const hashParams = new URLSearchParams(hash.substring(1));
      sensitiveParams.forEach(param => {
        if (hashParams.has(param)) {
          oauthParams.push({
            parameter: param,
            location: 'hash_fragment', 
            hasValue: hashParams.get(param).length > 0,
            length: hashParams.get(param).length
          });
        }
      });
    }
    
    return {
      foundParams: oauthParams,
      totalFound: oauthParams.length,
      inUrl: oauthParams.filter(p => p.location === 'url_params').length > 0,
      inHash: oauthParams.filter(p => p.location === 'hash_fragment').length > 0
    };
  };

  H.analyzeSessionManagement = () => {
    const issues = [];
    const sessionInfo = {
      cookieCount: 0,
      sessionStorageKeys: 0,
      localStorageKeys: 0,
      issues: []
    };
    
    // Analyze cookies (basic check since we can't access all cookie details from content script)
    const cookieCount = document.cookie.split(';').filter(c => c.trim().length > 0).length;
    sessionInfo.cookieCount = cookieCount;
    
    // Check for session-related storage
    try {
      sessionInfo.sessionStorageKeys = sessionStorage.length;
      sessionInfo.localStorageKeys = localStorage.length;
      
      // Check for potentially sensitive data in storage
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (/session|token|auth|login|user/i.test(key)) {
          issues.push({
            type: 'localStorage',
            key: key,
            issue: 'Potentially sensitive session data in localStorage'
          });
        }
      }
      
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);  
        if (/password|secret|key/i.test(key)) {
          issues.push({
            type: 'sessionStorage',
            key: key,
            issue: 'Potentially sensitive data in sessionStorage'
          });
        }
      }
    } catch (e) {
      issues.push({
        type: 'storage_access',
        issue: 'Unable to access browser storage'
      });
    }
    
    sessionInfo.issues = issues;
    return sessionInfo;
  };

  H.enhancedXssDetection = () => {
    const findings = {
      reflectedParams: [],
      domBasedSinks: [],
      unsafeDynamicContent: [],
      riskScore: 0
    };
    
    // Check for reflected parameters with enhanced detection
    const qp = new URLSearchParams(location.search);
    const pageContent = document.documentElement.innerHTML.toLowerCase();
    
    qp.forEach((val, key) => {
      if (!val.trim()) return;
      
      const needle = val.trim().toLowerCase();
      const contexts = [];
      
      // Check various contexts where reflection might occur
      if (pageContent.includes(`<script>${needle}`) || pageContent.includes(`<script type="text/javascript">${needle}`)) {
        contexts.push('script_content');
      }
      if (pageContent.includes(`"${needle}"`) && pageContent.includes('javascript:')) {
        contexts.push('javascript_url');
      }
      if (pageContent.includes(`onclick="${needle}`) || pageContent.includes(`onload="${needle}`)) {
        contexts.push('event_handler');
      }
      if (pageContent.includes(`<img src="${needle}"`) || pageContent.includes(`<iframe src="${needle}"`)) {
        contexts.push('src_attribute');
      }
      
      if (contexts.length > 0) {
        findings.reflectedParams.push({
          parameter: key,
          value: val.substring(0, 50),
          contexts: contexts,
          riskLevel: contexts.includes('script_content') ? 'HIGH' : 
                    contexts.includes('event_handler') ? 'MEDIUM' : 'LOW'
        });
      }
    });
    
    // Check for DOM-based XSS sinks
    const domSinks = [
      'innerHTML', 'outerHTML', 'insertAdjacentHTML', 
      'document.write', 'document.writeln', 'eval'
    ];
    
    const scripts = [...document.querySelectorAll('script')];
    scripts.forEach(script => {
      if (script.textContent) {
        domSinks.forEach(sink => {
          if (script.textContent.includes(sink)) {
            findings.domBasedSinks.push({
              sink: sink,
              snippet: script.textContent.substring(0, 100) + '...'
            });
          }
        });
      }
    });
    
    // Calculate risk score
    let risk = 0;
    findings.reflectedParams.forEach(param => {
      risk += param.riskLevel === 'HIGH' ? 30 : param.riskLevel === 'MEDIUM' ? 20 : 10;
    });
    risk += findings.domBasedSinks.length * 15;
    
    findings.riskScore = Math.min(100, risk);
    
    return findings;
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