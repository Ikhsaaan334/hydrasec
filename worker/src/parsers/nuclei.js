import fs from 'node:fs';
import path from 'node:path';

const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);

// Parser JSONL nuclei → Unified Vulnerability Schema
export function parseNuclei({ outDir }) {
  const file = path.join(outDir, 'nuclei.jsonl');
  if (!fs.existsSync(file)) return [];
  const findings = [];
  let text = '';
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch {
    return [];
  }
  for (const line of text.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    let item = null;
    try { item = JSON.parse(t); } catch { continue; }
    const info = item?.info ?? {};
    const cls = info?.classification ?? {};
    const sev = String(info?.severity ?? 'info').toLowerCase();
    findings.push({
      title: String(info?.name ?? item?.['template-id'] ?? 'nuclei finding').slice(0, 300),
      severity: SEVERITIES.has(sev) ? sev : 'info',
      url: String(item?.['matched-at'] ?? item?.host ?? '').slice(0, 2048) || null,
      cwe: cls?.['cwe-id'] ? String(cls['cwe-id']) : null,
      cve: cls?.['cve-id'] ? String(cls['cve-id']) : null,
      cvss: cls?.['cvss-score'] ?? null,
      description: String(info?.description ?? '').slice(0, 2000) ||
        'nuclei template finding (' + String(item?.['template-id'] ?? '') + ').',
      remediation: Array.isArray(info?.reference)
        ? 'Rujukan: ' + info.reference.slice(0, 3).join(', ')
        : null,
      evidence: [
        item?.['matcher-name'] ? 'matcher: ' + item['matcher-name'] : null,
        Array.isArray(item?.['extracted-results']) ? 'extracted: ' + item['extracted-results'].slice(0, 3).join(' | ') : null,
      ].filter(Boolean).join('; ') || null,
      metadata: {
        templateId: item?.['template-id'] ?? null,
        templateUrl: item?.['template-url'] ?? null,
        type: item?.type ?? null,
        tags: info?.tags ?? [],
      },
    });
  }
  return findings;
}
