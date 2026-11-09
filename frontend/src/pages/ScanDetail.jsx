import { useEffect, useMemo, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api } from '../api.js';
import { connectScanSocket } from '../ws.js';
import Terminal from '../components/Terminal.jsx';
import { SeverityBadge, StatusChip, formatDuration, formatDate } from '../components/ui.jsx';

const ACTIVE = new Set(['queued', 'running', 'parsing']);

export default function ScanDetail() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [findings, setFindings] = useState([]);
  const [chunks, setChunks] = useState([]);
  const [error, setError] = useState('');
  const [sevFilter, setSevFilter] = useState('all');
  const [cancelling, setCancelling] = useState(false);
  const [exporting, setExporting] = useState(false);

  // Unduh via fetch ber-header Authorization lalu simpan sebagai Blob —
  // link <a href> biasa tidak bisa membawa token, penyebab "Token missing".
  async function exportJson() {
    setExporting(true);
    try {
      const data = await api('/scans/' + id + '/export');
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'hydrasec-scan-' + id + '.json';
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err.message);
    } finally {
      setExporting(false);
    }
  }

  useEffect(() => {
    let alive = true;
    let sock = null;
    api('/scans/' + id)
      .then((d) => {
        if (!alive) return;
        setScan(d.scan);
        setFindings(d.findings ?? []);
        // Attach the WS only for the terminal stream (live log & status).
        sock = connectScanSocket(id, {
          onLog: (data) => alive && setChunks((c) => [...c, data]),
          onStatus: (msg) => {
            if (!alive) return;
            setScan((s) => (s ? { ...s, status: msg.status, exitCode: msg.exitCode ?? s.exitCode, error: msg.error ?? s.error } : s));
            if (msg.status === 'completed' || msg.status === 'failed' || msg.status === 'timeout' || msg.status === 'cancelled') {
              api('/scans/' + id)
                .then((d2) => alive && (setScan(d2.scan), setFindings(d2.findings ?? [])))
                .catch(() => {});
            }
          },
          onError: (msg) => alive && setError(msg.message ?? 'WebSocket error'),
          onClose: () => {},
        });
      })
      .catch((err) => alive && setError(err.message));
    return () => { alive = false; sock?.close(); };
  }, [id]);

  const shownFindings = useMemo(() => {
    if (sevFilter === 'all') return findings;
    return findings.filter((f) => f.severity === sevFilter);
  }, [findings, sevFilter]);

  async function cancelScan() {
    setCancelling(true);
    try {
      await api('/scans/' + id + '/cancel', { method: 'POST' });
    } catch (err) {
      setError(err.message);
    } finally {
      setCancelling(false);
    }
  }

  if (error && !scan) return <div className="empty">{error}</div>;
  if (!scan) return <div className="empty" style={{ paddingTop: 100 }}><span className="spinner" /></div>;

  const isActive = ACTIVE.has(scan.status);

  return (
    <>
      <div className="page-head">
        <div>
          <p className="mono" style={{ fontSize: 13 }}>
            <Link to="/scans">History</Link> / {scan.id.slice(0, 8)}
          </p>
          <h1>
            <span className="mono">{scan.tool}</span> — {scan.target}
          </h1>
          <p>
            <StatusChip status={scan.status} />
            <span className="mut" style={{ marginLeft: 12 }}>
              {scan.durationMs != null ? 'Duration ' + formatDuration(scan.durationMs) : 'Running…'}
              {' · '}Queued {formatDate(scan.queuedAt)}
            </span>
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          {isActive && (
            <button type="button" className="btn btn-danger-ghost" onClick={cancelScan} disabled={cancelling}>
              {cancelling ? <span className="spinner" /> : 'Cancel scan'}
            </button>
          )}
          {scan.status === 'completed' && (
            <button type="button" className="btn btn-ghost" onClick={exportJson} disabled={exporting}>
              {exporting ? <span className="spinner" /> : 'Export JSON'}
            </button>
          )}
        </div>
      </div>

      {scan.error && <div className="card" style={{ borderColor: 'rgba(248,113,113,.4)' }}><p className="field-error" style={{ marginTop: 0 }}>{scan.error}</p></div>}

      <Terminal chunks={chunks} status={scan.status} />

      <div className="card mt-24">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
          <h2>Findings ({findings.length})</h2>
          <select className="input" style={{ width: 200 }} value={sevFilter} onChange={(e) => setSevFilter(e.target.value)} aria-label="Severity filter">
            <option value="all">All severities</option>
            <option value="critical">critical</option>
            <option value="high">high</option>
            <option value="medium">medium</option>
            <option value="low">low</option>
            <option value="info">info</option>
          </select>
        </div>
        <div className="table-wrap mt-16">
          {shownFindings.length === 0 ? (
            <div className="empty">
              {scan.status === 'completed' ? 'No findings for this filter.' : 'Findings appear once the scan finishes parsing.'}
            </div>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th style={{ width: 90 }}>Severity</th>
                  <th>Finding</th>
                  <th style={{ width: 320 }}>Location</th>
                </tr>
              </thead>
              <tbody>
                {shownFindings.map((f) => (
                  <tr key={f.id}>
                    <td><SeverityBadge severity={f.severity} /></td>
                    <td>
                      <strong>{f.title}</strong>
                      {f.description && <p className="mut" style={{ fontSize: 13, marginTop: 4 }}>{f.description}</p>}
                      {f.evidence && (
                        <p className="mono dim" style={{ fontSize: 12, marginTop: 6, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                          {f.evidence}
                        </p>
                      )}
                      {(f.cve || f.cwe) && (
                        <p className="mono" style={{ fontSize: 12, marginTop: 6, color: 'var(--sev-low)' }}>
                          {[f.cve, f.cwe].filter(Boolean).join(' · ')}
                        </p>
                      )}
                    </td>
                    <td className="mono" style={{ fontSize: 12.5, wordBreak: 'break-all' }}>{f.url ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </>
  );
}
