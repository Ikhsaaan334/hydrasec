import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api.js';
import { StatusChip, formatDate, formatDuration } from '../components/ui.jsx';

const TOOL_IDS = ['nmap', 'nuclei', 'xsstrike', 'xray', 'sqlmap', 'ffuf'];
const STATUSES = ['queued', 'running', 'parsing', 'completed', 'failed', 'timeout', 'cancelled'];

export default function History() {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [tool, setTool] = useState('');
  const [status, setStatus] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const pageSize = 20;

  useEffect(() => {
    let alive = true;
    setLoading(true);
    const qs = new URLSearchParams({ page: String(page), pageSize: String(pageSize) });
    if (tool) qs.set('tool', tool);
    if (status) qs.set('status', status);
    api('/scans?' + qs.toString())
      .then((d) => {
        if (!alive) return;
        setItems(d.items ?? []);
        setTotal(d.total ?? 0);
      })
      .catch((err) => alive && setError(err.message))
      .finally(() => alive && setLoading(false));
    return () => { alive = false; };
  }, [page, tool, status]);

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Scan history</h1>
          <p>{total} scans on your account.</p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <select className="input" style={{ width: 150 }} value={tool} onChange={(e) => { setTool(e.target.value); setPage(1); }} aria-label="Tool filter">
            <option value="">All tools</option>
            {TOOL_IDS.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          <select className="input" style={{ width: 160 }} value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }} aria-label="Status filter">
            <option value="">All statuses</option>
            {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
      </div>

      {error && <div className="empty">{error}</div>}
      <div className="card">
        {loading ? (
          <div className="empty"><span className="spinner" /></div>
        ) : items.length === 0 ? (
          <div className="empty">No matching scans.</div>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Tool</th>
                  <th>Target</th>
                  <th>Status</th>
                  <th>Duration</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {items.map((s) => (
                  <tr key={s.id}>
                    <td className="mono">{s.tool}</td>
                    <td>
                      <Link className="row-link mono" to={'/scans/' + s.id}>
                        {s.target.length > 70 ? s.target.slice(0, 70) + '…' : s.target}
                      </Link>
                    </td>
                    <td><StatusChip status={s.status} /></td>
                    <td className="mut">{formatDuration(s.durationMs)}</td>
                    <td className="mut">{formatDate(s.queuedAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {totalPages > 1 && (
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 16 }}>
            <button type="button" className="btn btn-ghost btn-sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
              Previous
            </button>
            <span className="mut" style={{ alignSelf: 'center' }}>Page {page}/{totalPages}</span>
            <button type="button" className="btn btn-ghost btn-sm" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>
              Next
            </button>
          </div>
        )}
      </div>
    </>
  );
}
