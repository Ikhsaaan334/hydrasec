import ipaddr from 'ipaddr.js';
import dns from 'node:dns/promises';
import net from 'node:net';
import { config } from './config.js';

// ── Tool catalog & strict option whitelist ───────────────────────────────
export const TOOLS = {
  nmap: {
    label: 'Nmap',
    kind: 'host',
    description: 'Port scanning & attack surface mapping (reconnaissance).',
    options: {
      ports: { type: 'ports', default: '1-1000' },
    },
  },
  nuclei: {
    label: 'Nuclei',
    kind: 'url',
    description: 'Template-based vulnerability scanning (projectdiscovery, free edition).',
    options: {
      severity: { type: 'enum', values: ['info', 'low', 'medium', 'high', 'critical'], default: null },
      tags: { type: 'tags', default: null },
      concurrency: { type: 'int', min: 1, max: 150, default: 25 },
      rateLimit: { type: 'int', min: 10, max: 1000, default: 150 },
    },
  },
  xsstrike: {
    label: 'XSStrike',
    kind: 'url',
    description: 'Detect & exploit Cross-Site Scripting (XSS) flaws.',
    options: {
      crawl: { type: 'bool', default: false },
      level: { type: 'int', min: 1, max: 5, default: 2 },
    },
  },
  xray: {
    label: 'Xray',
    kind: 'url',
    description: 'Deep web security assessment (chaitin, community edition — no license needed).',
    options: {
      mode: { type: 'enum', values: ['url', 'crawler'], default: 'url' },
      plugins: { type: 'plugins', default: null },
    },
  },
  sqlmap: {
    label: 'sqlmap',
    kind: 'url',
    description: 'Detect & exploit SQL injection flaws.',
    options: {
      level: { type: 'int', min: 1, max: 5, default: 1 },
      risk: { type: 'int', min: 1, max: 3, default: 1 },
    },
  },
  ffuf: {
    label: 'ffuf',
    kind: 'url',
    description: 'Directory & parameter fuzzing / discovery.',
    options: {
      extensions: { type: 'wordlist', default: null }, // e.g. "php,html"
      threads: { type: 'int', min: 1, max: 100, default: 40 },
    },
  },
};

export function toolList() {
  return Object.entries(TOOLS).map(([id, t]) => ({
    id,
    label: t.label,
    description: t.description,
    kind: t.kind,
    requiresLicense: Boolean(t.butuhLicense),
    options: Object.entries(t.options).map(([k, v]) => ({ key: k, ...v, default: v.default ?? null })),
  }));
}

// ── SSRF guard: reject localhost/loopback/private/reserved ───────────────
const BLOCKED_RANGES_V4 = [
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
  '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.168.0.0/16', '198.18.0.0/15',
  '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/3', '240.0.0.0/4',
];

function ipIsBlocked(ip) {
  try {
    const parsed = ipaddr.parse(ip);
    const kind = parsed.kind();
    let addr = parsed;
    if (kind === 'ipv6' && parsed.isIPv4MappedAddress()) {
      addr = parsed.toIPv4Address();
    }
    if (addr.kind() === 'ipv4') {
      const range = addr.range();
      if (['loopback', 'private', 'linkLocal', 'reserved', 'uniqueLocal', 'multicast'].includes(range)) {
        return true;
      }
      const bits = addr.toByteArray();
      const inCidr = (cidr) => {
        const [base, plen] = cidr.split('/');
        const b = ipaddr.parse(base).toByteArray();
        const p = parseInt(plen, 10);
        const full = Math.floor(p / 8);
        let same = true;
        for (let i = 0; i < full; i++) if (bits[i] !== b[i]) { same = false; break; }
        if (same && p % 8 !== 0) {
          const mask = 0xff << (8 - (p % 8));
          if ((bits[full] & mask) !== (b[full] & mask)) same = false;
        }
        return same;
      };
      return BLOCKED_RANGES_V4.some(inCidr);
    }
    const range = addr.range();
    return ['loopback', 'linkLocal', 'uniqueLocal', 'reserved', 'special'].includes(range);
  } catch {
    return true; // unparseable → block
  }
}

const BLOCKED_HOSTNAMES = new Set([
  'localhost', 'localhost.localdomain', 'ip6-localhost', 'ip6-loopback',
  'metadata', 'metadata.google.internal', '169.254.169.254',
]);

async function hostIsAllowed(host) {
  const h = String(host || '').trim().toLowerCase();
  if (!h) return { ok: false, reason: 'Host is empty' };
  if (BLOCKED_HOSTNAMES.has(h)) return { ok: false, reason: `Host '${h}' is not allowed` };
  if (h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal')) {
    return { ok: false, reason: `Hostname '${h}' is an internal domain` };
  }
  if (config.allowPrivateTargets) {
    return { ok: true };
  }
  // literal IP?
  if (net.isIP(h)) {
    if (ipIsBlocked(h)) return { ok: false, reason: `IP '${h}' is in a private/loopback/reserved range` };
    return { ok: true };
  }
  // hostname → resolve all records, then check each address
  let addrs;
  try {
    addrs = await dns.lookup(h, { all: true, verbatim: true });
  } catch {
    return { ok: false, reason: `Hostname '${h}' could not be resolved` };
  }
  if (!addrs.length) return { ok: false, reason: `Hostname '${h}' has no address records` };
  for (const a of addrs) {
    if (ipIsBlocked(a.address)) {
      return { ok: false, reason: `Hostname '${h}' resolves to a private/loopback/reserved address` };
    }
  }
  return { ok: true };
}

export async function validateTarget(tool, target) {
  const spec = TOOLS[tool];
  if (!spec) return { ok: false, reason: 'Unknown tool' };
  const raw = String(target ?? '').trim();
  if (!raw || raw.length > 2048) return { ok: false, reason: 'Target is required (max 2048 characters)' };

  if (spec.kind === 'url') {
    let url;
    try {
      url = new URL(raw);
    } catch {
      return { ok: false, reason: 'Target must be a valid http/https URL' };
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return { ok: false, reason: 'Only http/https schemes are allowed' };
    }
    const check = await hostIsAllowed(url.hostname);
    if (!check.ok) return { ok: false, reason: check.reason };
    return { ok: true, normalized: url.origin + url.pathname + url.search };
  }

  // host kind (nmap): hostname or IP — no CIDR/ports/scheme
  if (raw.includes('/') || raw.includes('@') || /:\d+$/.test(raw)) {
    return { ok: false, reason: 'The nmap target must be a single hostname or IP (no CIDR/ports)' };
  }
  if (!/^[a-zA-Z0-9.\-_]{1,253}$/.test(raw)) {
    return { ok: false, reason: 'The nmap target contains invalid characters' };
  }
  const check = await hostIsAllowed(raw);
  if (!check.ok) return { ok: false, reason: check.reason };
  return { ok: true, normalized: raw.toLowerCase() };
}

// ── Per-tool option validation (whitelist, no free-form flags) ───────────
export function validateOptions(tool, options) {
  const spec = TOOLS[tool];
  if (!spec) return { ok: false, reason: 'Unknown tool' };
  const input = options && typeof options === 'object' && !Array.isArray(options) ? options : {};
  const clean = {};
  for (const [key, schema] of Object.entries(spec.options)) {
    const val = input[key];
    if (val === undefined || val === null || val === '') {
      if (schema.default !== null && schema.default !== undefined) clean[key] = schema.default;
      continue;
    }
    switch (schema.type) {
      case 'ports': {
        const s = String(val);
        if (!/^(\d{1,5}(-\d{1,5})?)(,(\d{1,5}(-\d{1,5})?))*$/.test(s)) {
          return { ok: false, reason: 'Invalid ports format (examples: 80,443,8000-8100)' };
        }
        const okRange = s.split(',').every((part) => {
          const [a, b] = part.split('-').map((x) => parseInt(x, 10));
          if (!Number.isInteger(a) || a < 1 || a > 65535) return false;
          if (b === undefined) return true;
          return Number.isInteger(b) && b <= 65535 && a <= b;
        });
        if (!okRange) return { ok: false, reason: 'Ports out of the 1-65535 range' };
        clean[key] = s;
        break;
      }
      case 'enum': {
        if (!schema.values.includes(String(val))) {
          return { ok: false, reason: `Invalid value for ${key}` };
        }
        clean[key] = String(val);
        break;
      }
      case 'bool': {
        clean[key] = val === true || val === 'true';
        break;
      }
      case 'int': {
        const n = Number(val);
        if (!Number.isInteger(n) || n < schema.min || n > schema.max) {
          return { ok: false, reason: `${key} must be an integer between ${schema.min} and ${schema.max}` };
        }
        clean[key] = n;
        break;
      }
      case 'wordlist': {
        const s = String(val);
        if (!/^[a-zA-Z0-9]{1,5}(,[a-zA-Z0-9]{1,5})*$/.test(s)) {
          return { ok: false, reason: 'extensions must be comma-separated extensions (e.g. php,html)' };
        }
        clean[key] = s;
        break;
      }
      case 'plugins': {
        // Whitelist modul deteksi xray (Community) — token tidak pernah diteruskan mentah
        const allowed = new Set([
          'xss', 'sqldet', 'cmd-injection', 'dirscan', 'path-traversal', 'xxe', 'phantasm',
          'upload', 'brute-force', 'jsonp', 'ssrf', 'baseline', 'redirect', 'crlf-injection', 'xstream',
        ]);
        const parts = String(val).split(',').map((p) => p.trim().toLowerCase()).filter(Boolean);
        if (parts.length === 0) break;
        if (parts.length > 8) return { ok: false, reason: 'Too many plugins selected (max 8)' };
        const unknown = parts.find((p) => !allowed.has(p));
        if (unknown) return { ok: false, reason: 'Unknown xray plugin: ' + unknown };
        clean[key] = parts.join(',');
        break;
      }
      case 'tags': {
        // Tag template nuclei (mis. cve,xss,tech) — charset ketat, maks 8 tag
        const parts = String(val).split(',').map((p) => p.trim().toLowerCase()).filter(Boolean);
        if (parts.length === 0) break;
        if (parts.length > 8) return { ok: false, reason: 'Too many tags (max 8)' };
        if (parts.some((t) => !/^[a-z0-9][a-z0-9-]{0,30}$/.test(t))) {
          return { ok: false, reason: 'Invalid tag name (use letters, numbers, dashes)' };
        }
        clean[key] = parts.join(',');
        break;
      }
      default:
        break; // unknown options are ignored (never forwarded to the CLI)
    }
  }
  return { ok: true, options: clean };
}

export async function validateScanInput({ tool, target, options }) {
  if (!TOOLS[tool]) return { ok: false, reason: `Unknown tool '${tool}'` };
  const t = await validateTarget(tool, target); // async: resolve DNS untuk SSRF guard
  if (!t.ok) return t;
  const o = validateOptions(tool, options);
  if (!o.ok) return o;
  return { ok: true, target: t.normalized, options: o.options };
}

// Strict whitelist sanitizer: only a safe email charset passes (breaks taint
// before any network flow; other characters are dropped, not escaped).
const EMAIL_SAFE_CHARS = /[a-z0-9.@+_%-]/;
export function strictNormalizeEmail(raw) {
  let out = '';
  for (const ch of String(raw ?? '').toLowerCase()) {
    if (EMAIL_SAFE_CHARS.test(ch)) out += ch;
  }
  return out.slice(0, 254);
}

// ── Unique username (handle shown on the leaderboard) ────────────────────
const USERNAME_RE = /^[a-z0-9]([a-z0-9._-]{1,22})[a-z0-9]$/;
const RESERVED_USERNAMES = new Set([
  'admin', 'administrator', 'root', 'system', 'hydrasec', 'moderator',
  'support', 'security', 'null', 'undefined', 'official',
]);

export function validateUsername(raw) {
  const username = String(raw ?? '').trim().toLowerCase();
  if (username.length < 3 || username.length > 24) {
    return { ok: false, reason: 'Username must be 3-24 characters' };
  }
  if (!USERNAME_RE.test(username)) {
    return {
      ok: false,
      reason: 'Use lowercase letters, numbers, dots, dashes or underscores — starting and ending with a letter or number',
    };
  }
  if (RESERVED_USERNAMES.has(username)) {
    return { ok: false, reason: 'That username is reserved' };
  }
  return { ok: true, username };
}
