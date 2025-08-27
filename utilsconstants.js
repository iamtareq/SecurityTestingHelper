export const SEVERITY = {
  LOW: { level: "Low", color: "#16a34a" },
  MEDIUM: { level: "Medium", color: "#f59e0b" },
  HIGH: { level: "High", color: "#f97316" },
  CRITICAL: { level: "Critical", color: "#dc2626" }
};

export const XSS_PAYLOADS = [
  "\\\"'><svg/onload=alert(1)>",
  "<img src=x onerror=alert(1)>",
  "javascript:alert(1)",
  "<script>alert(1)</script>",
  "</textarea><script>alert(1)</script>"
];

export const HEADER_RECS = {
  "content-security-policy": "Add a CSP like `default-src 'self';` and tighten script sources.",
  "x-frame-options": "Add X-Frame-Options: DENY or use frame-ancestors in CSP.",
  "x-content-type-options": "Add X-Content-Type-Options: nosniff.",
  "referrer-policy": "Add Referrer-Policy (e.g., strict-origin-when-cross-origin).",
  "strict-transport-security": "Enable HSTS with includeSubDomains; preload where appropriate.",
  "permissions-policy": "Use Permissions-Policy to restrict powerful features (e.g., geolocation=())."
};
