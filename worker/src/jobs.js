// Pembangun argv per-tool. Target yang sampai di sini SUDAH tervalidasi ketat
// di backend (skema http/https, host publik, charset) — dan tetap saja args
// dikirim sebagai array ke Docker (tanpa shell), sehingga tidak ada
// kemungkinan command injection pada lapisan apa pun.
const MIN = 60 * 1000;

export function buildToolInvocation(tool, { target, options, outDir }) {
  switch (tool) {
    case 'nmap':
      return {
        cmd: [
          '-Pn', '-sT', '-sV', '--open', '-T4',
          '-p', String(options.ports || '1-1000'),
          '-oX', outDir + '/nmap.xml',
          target,
        ],
        memoryMb: 384,
        timeoutMs: 12 * MIN,
      };

    case 'nuclei': {
      const cmd = [
        '-t', '/home/scanner/nuclei-templates',
        '-j', '-o', outDir + '/nuclei.jsonl',
        '-nc', '-silent', '-duc',
      ];
      if (options.severity) cmd.push('-s', String(options.severity));
      if (options.tags) cmd.push('-tags', String(options.tags));
      cmd.push('-c', String(options.concurrency || 25));
      cmd.push('-rl', String(options.rateLimit || 150));
      cmd.push(target);
      return { cmd, memoryMb: 768, timeoutMs: 20 * MIN };
    }

    case 'xsstrike': {
      const cmd = ['-u', target, '--skip'];
      if (options.crawl) cmd.push('--crawl', '-l', String(options.level || 2));
      return { cmd, memoryMb: 384, timeoutMs: 12 * MIN };
    }

    case 'xray': {
      // args dikirim sebagai array ke entrypoint (tanpa shell):
      // mode single-URL (--url) atau crawl situs (--basic-crawler),
      // plus whitelist plugin yang sudah divalidasi backend.
      const cmd = [];
      if (options.plugins) cmd.push('--plugins', String(options.plugins));
      if (options.mode === 'crawler') cmd.push('--basic-crawler');
      else cmd.push('--url');
      cmd.push(target);
      cmd.push('--json-output', outDir + '/xray.json');
      return { cmd, memoryMb: 1024, timeoutMs: 30 * MIN };
    }

    case 'sqlmap':
      return {
        cmd: [
          '-u', target,
          '--batch', '--random-agent', '--flush-session',
          '--output-dir', outDir + '/sqlmap',
          '--threads', '4',
          '--level', String(options.level || 1),
          '--risk', String(options.risk || 1),
        ],
        memoryMb: 512,
        timeoutMs: 20 * MIN,
      };

    case 'ffuf': {
      let url = target;
      if (!url.includes('FUZZ')) url = url.replace(/\/?$/, '/') + 'FUZZ';
      const cmd = [
        '-w', '/usr/share/wordlists/common.txt',
        '-u', url,
        '-o', outDir + '/ffuf.json',
        '-of', 'json',
        '-t', String(options.threads || 40),
        '-mc', 'all',
        '-fc', '404',
      ];
      if (options.extensions) cmd.push('-e', String(options.extensions));
      return { cmd, memoryMb: 384, timeoutMs: 12 * MIN };
    }

    default:
      throw new Error('Tool tidak dikenal: ' + tool);
  }
}

// Bind license xray (jika host menyediakan ./data/xray/license)
export function xrayLicenseBinds(fsRootLicensePath) {
  if (!fsRootLicensePath) return [];
  return [fsRootLicensePath + ':/opt/xray/license:ro'];
}
