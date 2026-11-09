import fs from 'node:fs';
import path from 'node:path';

// Parser JSON ffuf → Unified Vulnerability Schema (temuan discovery = info)
export function parseFfuf({ outDir, target }) {
  const file = path.join(outDir, 'ffuf.json');
  if (!fs.existsSync(file)) return [];
  let data;
  try {
    data = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return [];
  }
  const findings = [];
  const results = Array.isArray(data?.results) ? data.results.slice(0, 500) : [];
  for (const r of results) {
    const status = Number(r?.status ?? 0);
    const fuzz = String(r?.input?.FUZZ ?? '').slice(0, 120);
    const url = String(r?.url ?? '').slice(0, 2048);
    let p;
    try { p = new URL(url).pathname; } catch { p = fuzz; }
    let severity = 'info';
    if (status === 401 || status === 403) severity = 'low';
    findings.push({
      title: '[' + status + '] ' + (p || fuzz || '/'),
      severity,
      url,
      description:
        'Endpoint/path discovered by ffuf (' + status + ', ' + String(r?.words ?? 0) + ' words, ' +
        String(r?.length ?? 0) + ' bytes). Check whether it should be publicly exposed.',
      evidence: 'input FUZZ: ' + (fuzz || '(root)'),
      metadata: {
        status,
        length: r?.length ?? null,
        words: r?.words ?? null,
        lines: r?.lines ?? null,
        contentType: r?.['content-type'] ?? null,
        durationMs: r?.duration ?? null,
      },
    });
  }
  if (findings.length === 0) {
    findings.push({
      title: 'ffuf found no paths passing the filter',
      severity: 'info',
      description: 'No common.txt wordlist entry produced a non-404 response on the target.',
    });
  }
  void target;
  return findings;
}
