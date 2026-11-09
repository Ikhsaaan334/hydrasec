import fs from 'node:fs';
import path from 'node:path';

function walk(dir) {
  let out = [];
  let entries = [];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) out = out.concat(walk(full));
    else out.push(full);
  }
  return out;
}

// sqlmap text log parser → Unified Vulnerability Schema
export function parseSqlmap({ outDir, target }) {
  const root = path.join(outDir, 'sqlmap');
  if (!fs.existsSync(root)) return [];
  const findings = [];
  const logFiles = walk(root).filter((f) => f.endsWith('log'));
  for (const file of logFiles) {
    let text = '';
    try {
      text = fs.readFileSync(file, 'utf8');
    } catch {
      continue;
    }
    const lines = text.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const m = line.match(/Parameter\s+'([^']+)'.{0,40}is\s+'([^']+)' injectable/i);
      if (m) {
        findings.push({
          title: 'SQL injection — parameter "' + m[1] + '"',
          severity: 'high',
          url: target,
          parameter: m[1],
          description: 'sqlmap confirmed parameter "' + m[1] + '" is injectable using technique: ' + m[2] + '.',
          remediation: 'Use prepared statements/parameter binding, validate input types, and least-privilege DB accounts.',
          evidence: line.trim().slice(0, 400),
          metadata: { technique: m[2] },
        });
        continue;
      }
      const dbms = line.match(/back-end DBMS(?: is|:)\s*(.+)/i);
      if (dbms && findings.length > 0) {
        const last = findings[findings.length - 1];
        if (!last.metadata) last.metadata = {};
        if (!last.metadata.dbms) {
          last.metadata.dbms = dbms[1].trim();
          last.description += ' Back-end DBMS detected: ' + dbms[1].trim() + '.';
        }
        continue;
      }
      const block = line.match(/^Parameter:\s*(\S+)\s*\((\w+)\)/);
      if (block && !findings.some((f) => f.parameter === block[1] && f.severity === 'high')) {
        const meta = { type: null, payload: null };
        let j = i + 1;
        while (j < lines.length && j <= i + 12) {
          const t = lines[j].match(/Type:\s*(.+)/);
          const pl = lines[j].match(/Payload:\s*(.+)/);
          if (t) meta.type = t[1].trim();
          if (pl) meta.payload = pl[1].trim().slice(0, 400);
          if (/^\s*$/.test(lines[j + 1] ?? '')) break;
          j += 1;
        }
        findings.push({
          title: 'SQL injection — parameter "' + block[1] + '" (' + block[2] + ')',
          severity: 'high',
          url: target,
          parameter: block[1],
          description: 'sqlmap session summary for parameter "' + block[1] + '"' +
            (meta.type ? ' — technique ' + meta.type : '') + '.',
          remediation: 'Use prepared statements/parameter binding and validate input types.',
          evidence: meta.payload ? 'Payload: ' + meta.payload : null,
          metadata: meta,
        });
      }
    }
  }
  if (findings.length === 0) {
    findings.push({
      title: 'No injectable parameters found (at the chosen level/risk)',
      severity: 'info',
      url: target,
      description: 'sqlmap finished testing without finding injectable parameters. Raise level/risk for more aggressive testing.',
    });
  }
  return findings;
}
