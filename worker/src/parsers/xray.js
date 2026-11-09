import fs from 'node:fs';
import path from 'node:path';

// Parser JSON xray → Unified Vulnerability Schema.
// Skema JSON xray tidak didokumentasikan formal; parser bersifat defensif:
// beberapa bentuk field yang dikenal dicoba secara berurutan.
const SEVERITY_BY_CLASS = [
  { re: /(rce|command|code.?exec|deserial)/i, sev: 'critical' },
  { re: /(sql|sqli|injection)/i, sev: 'high' },
  { re: /(ssrf)/i, sev: 'high' },
  { re: /(weak.?password|brute)/i, sev: 'high' },
  { re: /(xss|csrf|redirect|xinclude|xxe)/i, sev: 'medium' },
  { re: /(info.?leak|path.?trav|crlf|config)/i, sev: 'medium' },
  { re: /(dirsearch|brute.?dir|baseline|info)/i, sev: 'info' },
];

function severityFor(vulnClass) {
  const s = String(vulnClass ?? '');
  for (const rule of SEVERITY_BY_CLASS) {
    if (rule.re.test(s)) return rule.sev;
  }
  return 'medium';
}

export function parseXray({ outDir, target }) {
  const file = path.join(outDir, 'xray.json');
  if (!fs.existsSync(file)) return [];
  let data;
  try {
    data = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return [];
  }
  const items = Array.isArray(data) ? data : Array.isArray(data?.vulns) ? data.vulns : data ? [data] : [];
  const findings = [];
  for (const item of items.slice(0, 500)) {
    const detail = item?.detail ?? {};
    const vulnClass = item?.vuln_class ?? item?.plugin ?? item?.title ?? null;
    findings.push({
      title: 'xray: ' + String(vulnClass ?? 'finding') + (detail?.addr ? ' — ' + detail.addr : ''),
      severity: severityFor(vulnClass),
      url: String(item?.url ?? item?.target ?? detail?.addr ?? target ?? '').slice(0, 2048) || target,
      parameter: detail?.param ? String(detail.param).slice(0, 200) : null,
      description:
        'xray flagged the vulnerability class "' + String(vulnClass ?? 'unknown') +
        '" on the target. Technical details are in the evidence/metadata.',
      remediation: null,
      evidence:
        String(detail?.payload ?? detail?.snippet ?? '').slice(0, 600) || null,
      metadata: {
        vulnClass: vulnClass ?? null,
        addr: detail?.addr ?? null,
        extra: detail?.extra ?? null,
        sessionId: item?.session_id ?? null,
      },
    });
  }
  if (findings.length === 0) {
    findings.push({
      title: 'xray completed the assessment with no findings',
      severity: 'info',
      url: target,
      description: 'No vulnerabilities were confirmed by xray on the target (or the JSON output was empty).',
    });
  }
  return findings;
}
