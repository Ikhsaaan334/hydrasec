import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api.js';
import { useAuth } from '../auth.jsx';
import { StatCard, Bars, StatusChip, formatDate } from '../components/ui.jsx';

export default function Dashboard() {
  const { user } = useAuth();
  const [stats, setStats] = useState(null);
  const [recent, setRecent] = useState([]);
  const [error, setError] = useState('');

  useEffect(() => {
    let alive = true;
    Promise.all([api('/stats'), api('/scans?pageSize=6')])
      .then(([s, r]) => {
        if (!alive) return;
        setStats(s);
        setRecent(r.items ?? []);
      })
      .catch((err) => alive && setError(err.message));
    return () => { alive = false; };
  }, []);

  if (error) return <div className="empty">{error}</div>;
  if (!stats) {
    return <div className="empty" style={{ paddingTop: 100 }}><span className="spinner" /></div>;
  }

  const byTool = (stats.global.byTool ?? []).map((r) => ({ label: r.tool, value: r.scans }));
  const mySev = stats.me.bySeverity ?? [];
  const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Dashboard</h1>
          <p>Scanning activity overview — aggregated across all users and yours.</p>
        </div>
        <Link to="/scan/new" className="btn btn-primary">Start new scan</Link>
      </div>

      <div className="stats-grid">
        <StatCard value={stats.global.totalScans} label="Total scans — all users" accent />
        <StatCard value={stats.me.totalScans} label="My total scans" />
        <StatCard value={stats.global.totalVulns} label="Total vulnerability findings" />
        <StatCard value={stats.global.totalUsers} label="Registered users" />
      </div>

      <div className="two-col mt-24">
        <div className="card">
          <h2>Scans per tool — all users</h2>
          <div className="mt-16">
            <Bars items={byTool} />
          </div>
        </div>
        <div className="card">
          <h2>My findings by severity</h2>
          <div className="mt-16" style={{ display: 'flex', flexWrap: 'wrap', gap: 10 }}>
            {sevOrder.map((sev) => {
              const found = mySev.find((r) => r.severity === sev);
              const n = found ? found.total : 0;
              return (
                <span key={sev} className={'badge-sev badge-sev-' + sev} style={{ fontSize: 13, padding: '6px 14px' }}>
                  {sev} · {n}
                </span>
              );
            })}
          </div>
          <p className="field-hint mt-16">
            Accumulated across your entire scan history on the six orchestrated tools.
          </p>
        </div>
      </div>

      <div className="card mt-24">
        <h2>Leaderboard — total scans by user</h2>
        <div className="table-wrap mt-16">
          {(stats.leaderboard ?? []).length === 0 ? (
            <div className="empty">No scans yet — be the first on the board.</div>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th style={{ width: 70 }}>Rank</th>
                  <th>User</th>
                  <th style={{ width: 140 }}>Total scans</th>
                </tr>
              </thead>
              <tbody>
                {(stats.leaderboard ?? []).map((row, i) => (
                  <tr key={row.username} style={row.username === user?.username ? { background: 'rgba(74,222,128,.06)' } : undefined}>
                    <td className="mono">{i === 0 ? '🥇' : i === 1 ? '🥈' : i === 2 ? '🥉' : '#' + (i + 1)}</td>
                    <td>
                      <strong>{row.username}</strong>
                      {row.username === user?.username && <span className="chip" style={{ marginLeft: 8 }}>you</span>}
                    </td>
                    <td className="mono">{row.scans}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      <div className="card mt-24">
        <h2>Recent scans</h2>
        <div className="table-wrap mt-16">
          {recent.length === 0 ? (
            <div className="empty">No scans yet — start from the New Scan page.</div>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Tool</th>
                  <th>Target</th>
                  <th>Status</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {recent.map((s) => (
                  <tr key={s.id}>
                    <td className="mono">{s.tool}</td>
                    <td>
                      <Link className="row-link mono" to={'/scans/' + s.id}>
                        {s.target.length > 60 ? s.target.slice(0, 60) + '…' : s.target}
                      </Link>
                    </td>
                    <td><StatusChip status={s.status} /></td>
                    <td className="mut">{formatDate(s.queuedAt)}</td>
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
