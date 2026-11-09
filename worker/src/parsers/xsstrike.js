// XSStrike console parser → Unified Vulnerability Schema.
// XSStrike has no file output; the parser works from the console stream the
// worker captures (consoleText). XSStrike's VULN level uses the [++] prefix
// and GOOD uses [+].
const ANSI = /\x1b\[[0-9;]*[A-Za-z]/g;

export function parseXsstrike({ consoleText, target }) {
  const text = String(consoleText ?? '').replace(ANSI, '');
  const findings = [];
  const seen = new Set();
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line) continue;

    // [++] Vulnerable webpage: <url>   (crawl mode)
    let m = line.match(/\[\+\+\]\s*Vulnerable webpage:\s*(\S+)/);
    if (m) {
      const key = 'vp:' + m[1];
      if (!seen.has(key)) {
        seen.add(key);
        findings.push({
          title: 'Page vulnerable to XSS (crawl) — ' + m[1],
          severity: 'high',
          url: m[1],
          description: 'XSStrike (crawl mode) flagged the following page as vulnerable to XSS.',
          remediation: 'Escape output by context (HTML/attribute/JS/URL) and enforce a CSP.',
          evidence: line.slice(0, 400),
        });
      }
      continue;
    }

    // [++] Vector for <url>: <payload>
    m = line.match(/\[\+\+\]\s*Vector for\s+(.*?):\s*(.+)$/);
    if (m) {
      const key = 'vec:' + m[1] + ':' + m[2];
      if (!seen.has(key)) {
        seen.add(key);
        findings.push({
          title: 'XSS vector confirmed',
          severity: 'high',
          url: m[1] || target,
          description: 'XSStrike confirmed a working XSS vector on the target URL with a filter-evading payload.',
          remediation: 'Escape output per context, validate input, and consider a strict CSP.',
          evidence: 'Payload: ' + m[2].slice(0, 400),
          metadata: { payload: m[2].slice(0, 400) },
        });
      }
      continue;
    }

    // [+] Payload: <vector>  (single-URL scan — payload passed the filters)
    m = line.match(/\[\+\]\s*Payload:\s*(.+)$/);
    if (m) {
      const key = 'pl:' + m[1];
      if (!seen.has(key)) {
        seen.add(key);
        findings.push({
          title: 'XSS payload passed input filters',
          severity: 'high',
          url: target,
          description: 'XSStrike found a payload that survives filtering on the target parameter (single-URL mode).',
          remediation: 'Escape output per context and validate input on the affected parameter.',
          evidence: 'Payload: ' + m[1].slice(0, 400),
          metadata: { payload: m[1].slice(0, 400) },
        });
      }
      continue;
    }

    // [+] Vulnerable component: <name> v<version>  (retireJs)
    m = line.match(/\[\+\]\s*Vulnerable component:\s*(.+?)\s+v([\d.]+)/);
    if (m) {
      const key = 'rc:' + m[1] + m[2];
      if (!seen.has(key)) {
        seen.add(key);
        findings.push({
          title: 'Vulnerable JS component — ' + m[1] + ' v' + m[2],
          severity: 'medium',
          url: target,
          description: 'A third-party script loaded by the page was detected as vulnerable (retire.js).',
          remediation: 'Update or replace the component to a patched release.',
          metadata: { component: m[1], version: m[2] },
        });
      }
      continue;
    }
  }
  if (findings.length === 0) {
    findings.push({
      title: 'No XSS detected by XSStrike',
      severity: 'info',
      url: target,
      description: 'XSStrike finished its analysis with no filter-evading payload on the tested parameters.',
    });
  }
  return findings;
}
