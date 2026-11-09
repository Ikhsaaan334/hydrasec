import fs from 'node:fs';
import path from 'node:path';
import { XMLParser } from 'fast-xml-parser';

// nmap XML output parser → Unified Vulnerability Schema.
// fast-xml-parser does not process DTD/external entities — complies with the
// "reject DOCTYPE/ENTITY when parsing untrusted XML" policy.
export function parseNmap({ outDir }) {
  const file = path.join(outDir, 'nmap.xml');
  if (!fs.existsSync(file)) return [];
  const findings = [];
  const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_', parseTagValue: true });
  let doc;
  try {
    doc = parser.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return [];
  }
  const hosts = [].concat(doc?.nmaprun?.host ?? []);
  for (const host of hosts) {
    const addr = [].concat(host?.address ?? [])[0]?.['@_addr'] ?? '';
    const hostname = [].concat(host?.hostnames?.hostname ?? [])[0]?.['@_name'] ?? '';
    const label = hostname || addr || 'host';
    const ports = [].concat(host?.ports?.port ?? []);
    for (const p of ports) {
      if (p?.state?.['@_state'] !== 'open') continue;
      const port = String(p?.['@_portid'] ?? '');
      const proto = String(p?.['@_protocol'] ?? 'tcp');
      const svcName = String(p?.service?.['@_name'] ?? 'unknown');
      const product = [p?.service?.['@_product'], p?.service?.['@_version']].filter(Boolean).join(' ');
      findings.push({
        title: 'Open port ' + port + '/' + proto + ' (' + svcName + (product ? ' — ' + product : '') + ')',
        severity: 'info',
        url: proto + '://' + label + ':' + port,
        description:
          'Port ' + port + '/' + proto + ' is open and answers as a ' + svcName + ' service' +
          (product ? ' version ' + product : '') + '. Attack surface identified by nmap.',
        remediation: 'Confirm this service is meant to be exposed; close or firewall it if not.',
        evidence: String(p?.script?.['@_output'] ?? '').slice(0, 500) || null,
        metadata: { host: label, port, proto, service: svcName },
      });
    }
  }
  if (findings.length === 0) {
    findings.push({
      title: 'No open ports found in the scanned range',
      severity: 'info',
      description: 'nmap completed the scan without finding any open port for the chosen range/options.',
    });
  }
  return findings;
}
