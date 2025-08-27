export function buildHtmlReport({ score, findings }) {
  return `<!doctype html><html><head><meta charset="utf-8"/><title>Security Report</title>
  <style>body{font:14px/1.4 system-ui;padding:16px} .mono{font-family:ui-monospace,Menlo,Consolas,monospace}</style>
  </head><body>
  <h1>Security Report</h1>
  <div>Score: <b>${score}</b></div>
  <pre class="mono">${JSON.stringify(findings, null, 2)}</pre>
  </body></html>`;
}