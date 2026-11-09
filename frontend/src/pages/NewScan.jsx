import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api.js';

const TOOL_ICONS = {
  nmap: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
      <circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="4" /><path d="M12 3v2M12 19v2M3 12h2M19 12h2" />
    </svg>
  ),
  nuclei: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
      <path d="M13 2L4 14h6l-1 8 9-12h-6l1-8z" />
    </svg>
  ),
  xsstrike: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
      <path d="M8 9l-4 3 4 3M16 9l4 3-4 3" />
    </svg>
  ),
  xray: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
      <circle cx="11" cy="11" r="7" /><path d="M21 21l-4-4" />
    </svg>
  ),
  sqlmap: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
      <ellipse cx="12" cy="5" rx="8" ry="3" /><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5" /><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3" />
    </svg>
  ),
  ffuf: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
      <path d="M4 4h16v6H4zM4 14h9v6H4zM17 14h3v6h-3" />
    </svg>
  ),
};

const PLACEHOLDERS = {
  nmap: 'scanme.nmap.org',
  nuclei: 'https://target.example.com',
  xsstrike: 'https://target.example.com/page.php?q=1',
  xray: 'https://target.example.com',
  sqlmap: 'https://target.example.com/item.php?id=1',
  ffuf: 'https://target.example.com/FUZZ',
};

export default function NewScan() {
  const navigate = useNavigate();
  const [tools, setTools] = useState([]);
  const [selected, setSelected] = useState('nmap');
  const [target, setTarget] = useState('');
  const [opts, setOpts] = useState({});
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [allowPrivate, setAllowPrivate] = useState(false);

  useEffect(() => {
    api('/scans/tools')
      .then((d) => {
        setTools(d.tools ?? []);
        setAllowPrivate(Boolean(d.allowPrivateTargets));
      })
      .catch((err) => setError(err.message));
  }, []);

  const tool = tools.find((t) => t.id === selected);

  function setOpt(key, value) {
    setOpts((o) => ({ ...o, [key]: value }));
  }

  async function launch(e) {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      const options = { ...opts };
      // plugins dikumpulkan sebagai array checkbox → kirim sebagai string CSV
      if (Array.isArray(options.plugins)) {
        options.plugins = options.plugins.join(',') || undefined;
      }
      const data = await api('/scans', {
        method: 'POST',
        body: { tool: selected, target: target.trim(), options },
      });
      navigate('/scans/' + data.scan.id);
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>New scan</h1>
          <p>Pick a tool, set a target, and the job is queued to the worker — the queue keeps the host safe even under burst load.</p>
        </div>
      </div>

      <div className="tools-grid">
        {tools.map((t) => (
          <button
            key={t.id}
            type="button"
            className={'tool-card' + (t.id === selected ? ' selected' : '')}
            onClick={() => { setSelected(t.id); setOpts({}); setError(''); }}
            aria-pressed={t.id === selected}
          >
            <div className="tool-head">
              <span className="tool-icon">{TOOL_ICONS[t.id] ?? '◆'}</span>
              <span className="tool-name">{t.label}</span>
            </div>
            <p className="tool-desc">{t.description}</p>
            <span className="tool-check" aria-hidden="true">✓</span>
          </button>
        ))}
      </div>

      <form className="card mt-24" onSubmit={launch} style={{ maxWidth: 720 }}>
        <div className="field">
          <label htmlFor="target">Target {tool?.kind === 'host' ? '(public hostname / IP)' : '(http/https URL)'}</label>
          <input
            id="target"
            className="input"
            required
            placeholder={PLACEHOLDERS[selected] ?? 'https://target.example.com'}
            value={target}
            onChange={(e) => setTarget(e.target.value)}
          />
          <p className="field-hint">
            {allowPrivate
              ? 'Lab mode: private/localhost targets are allowed (ALLOW_PRIVATE_TARGETS=true).'
              : 'SSRF guard active: localhost and private/loopback addresses are rejected. To scan a local lab, set ALLOW_PRIVATE_TARGETS=true in .env.'}
          </p>
        </div>

        {selected === 'nmap' && (
          <div className="field mt-16">
            <label htmlFor="ports">Ports</label>
            <input
              id="ports"
              className="input"
              placeholder="1-1000"
              value={opts.ports ?? ''}
              onChange={(e) => setOpt('ports', e.target.value)}
            />
            <p className="field-hint">Examples: 80,443 or 1-65535. Defaults to 1-1000.</p>
          </div>
        )}

        {selected === 'nuclei' && (
          <>
            <div className="field mt-16">
              <label htmlFor="sev">Template severity filter</label>
              <select id="sev" className="input" value={opts.severity ?? ''} onChange={(e) => setOpt('severity', e.target.value || null)}>
                <option value="">All</option>
                <option value="critical">critical</option>
                <option value="high">high</option>
                <option value="medium">medium</option>
                <option value="low">low</option>
                <option value="info">info</option>
              </select>
            </div>
            <div className="field mt-16">
              <label htmlFor="tags">Template tags filter (optional)</label>
              <input
                id="tags" className="input" placeholder="cve,xss,tech"
                value={opts.tags ?? ''}
                onChange={(e) => setOpt('tags', e.target.value || undefined)}
              />
              <p className="field-hint">Comma-separated tags — e.g. <code>cve</code> for CVE templates only, <code>tech</code> for quick tech detection.</p>
            </div>
            <div className="mt-16" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
              <div className="field">
                <label htmlFor="conc">Concurrency (1-150)</label>
                <input id="conc" type="number" min="1" max="150" className="input" value={opts.concurrency ?? 25} onChange={(e) => setOpt('concurrency', Number(e.target.value))} />
              </div>
              <div className="field">
                <label htmlFor="rl">Rate limit (req/s, 10-1000)</label>
                <input id="rl" type="number" min="10" max="1000" className="input" value={opts.rateLimit ?? 150} onChange={(e) => setOpt('rateLimit', Number(e.target.value))} />
              </div>
            </div>
            <p className="field-hint mt-8">
              Lower concurrency &amp; rate limit for fragile targets — prevents hammering your own website.
            </p>
          </>
        )}

        {selected === 'xsstrike' && (
          <>
            <div className="field mt-16" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <input
                id="crawl"
                type="checkbox"
                checked={Boolean(opts.crawl)}
                onChange={(e) => setOpt('crawl', e.target.checked)}
                style={{ width: 16, height: 16 }}
              />
              <label htmlFor="crawl" style={{ margin: 0 }}>Crawl mode (explore the site, slower)</label>
            </div>
            {Boolean(opts.crawl) && (
              <div className="field mt-8">
                <label htmlFor="level">Crawl depth</label>
                <input
                  id="level" type="number" min="1" max="5" className="input"
                  value={opts.level ?? 2}
                  onChange={(e) => setOpt('level', Number(e.target.value))}
                />
              </div>
            )}
          </>
        )}

        {selected === 'sqlmap' && (
          <div className="mt-16" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
            <div className="field">
              <label htmlFor="lvl">Level (1-5)</label>
              <input id="lvl" type="number" min="1" max="5" className="input" value={opts.level ?? 1} onChange={(e) => setOpt('level', Number(e.target.value))} />
            </div>
            <div className="field">
              <label htmlFor="risk">Risk (1-3)</label>
              <input id="risk" type="number" min="1" max="3" className="input" value={opts.risk ?? 1} onChange={(e) => setOpt('risk', Number(e.target.value))} />
            </div>
          </div>
        )}

        {selected === 'ffuf' && (
          <>
            <div className="field mt-16">
              <label htmlFor="ext">Extra extensions</label>
              <input id="ext" className="input" placeholder="php,html" value={opts.extensions ?? ''} onChange={(e) => setOpt('extensions', e.target.value || undefined)} />
              <p className="field-hint">The common.txt wordlist is baked into the tool image.</p>
            </div>
            <div className="field mt-16">
              <label htmlFor="threads">Threads</label>
              <input id="threads" type="number" min="1" max="100" className="input" value={opts.threads ?? 40} onChange={(e) => setOpt('threads', Number(e.target.value))} />
            </div>
          </>
        )}

        {selected === 'xray' && (
          <>
            <div className="field mt-16">
              <label htmlFor="xmode">Scan mode</label>
              <select id="xmode" className="input" value={opts.mode ?? 'url'} onChange={(e) => setOpt('mode', e.target.value)}>
                <option value="url">Single URL — scan the exact URL and its parameters (fast)</option>
                <option value="crawler">Basic crawler — crawl the site&apos;s links first, then scan (slower, wider coverage)</option>
              </select>
            </div>
            <div className="field mt-16">
              <label>Plugin modules (optional — leave empty for all 14 modules)</label>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8 }}>
                {['xss', 'sqldet', 'cmd-injection', 'dirscan', 'path-traversal', 'xxe', 'phantasm', 'upload', 'brute-force', 'jsonp', 'ssrf', 'baseline', 'redirect', 'crlf-injection', 'xstream'].map((p) => {
                  const checked = Array.isArray(opts.plugins) && opts.plugins.includes(p);
                  return (
                    <label key={p} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, color: 'var(--text-mut)', cursor: 'pointer' }}>
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={(e) => {
                          const cur = Array.isArray(opts.plugins) ? [...opts.plugins] : [];
                          setOpt('plugins', e.target.checked ? [...cur, p] : cur.filter((x) => x !== p));
                        }}
                        style={{ width: 15, height: 15 }}
                      />
                      {p}
                    </label>
                  );
                })}
              </div>
              <p className="field-hint">xss · sqldet · dirscan · ssrf · dsb. — modul deteksi resmi xray Community.</p>
            </div>
            <p className="field-hint mt-8">
              Community edition 1.9.11 — runs without a license. Crawler mode sends hundreds of
              benign probe requests across the site and reports confirmed vulnerabilities.
            </p>
          </>
        )}

        {error && <p className="field-error">{error}</p>}
        <button type="submit" className="btn btn-primary mt-24" disabled={busy || !target.trim()}>
          {busy ? <span className="spinner" /> : 'Start scan'}
        </button>
      </form>
    </>
  );
}
