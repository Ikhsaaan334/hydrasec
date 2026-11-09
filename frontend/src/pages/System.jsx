import { useEffect, useState } from 'react';
import { api } from '../api.js';

const LABEL = {
  database: 'PostgreSQL (primary-database)',
  redis: 'Redis (task-broker)',
  worker: 'Worker engine (background-worker)',
  prometheus: 'Prometheus (system-monitor)',
};

const DOT_CLASS = { up: 'up', down: 'down' };

async function promQuery(query) {
  const res = await fetch('/prometheus/api/v1/query?query=' + encodeURIComponent(query));
  const body = await res.json();
  if (body?.status !== 'success') throw new Error('Prometheus query failed');
  return body.data?.result ?? [];
}

function metricName(name) {
  // cAdvisor stores container names with a leading "/" — tidy them for display
  return String(name ?? '').replace(/^\/?(docker\/)?/, '').replace(/^hydrasec-/, '');
}

export default function System() {
  const [health, setHealth] = useState(null);
  const [containers, setContainers] = useState([]);
  const [error, setError] = useState('');

  useEffect(() => {
    let alive = true;
    async function tick() {
      try {
        const h = await api('/health');
        if (!alive) return;
        setHealth(h);
        setError('');
        // Per-container CPU & RAM for the HydraSec compose project via the Prometheus HTTP API
        const cpuQ = 'sum by (name) (rate(container_cpu_usage_seconds_total{container_label_com_docker_compose_project="hydrasec"}[1m]))';
        const memQ = 'container_memory_usage_bytes{container_label_com_docker_compose_project="hydrasec"}';
        const [cpu, mem] = await Promise.all([promQuery(cpuQ), promQuery(memQ)]);
        if (!alive) return;
        const map = new Map();
        for (const r of cpu) {
          const n = metricName(r.metric?.name);
          map.set(n, { name: n, cpu: Number(r.value?.[1] ?? 0), mem: 0 });
        }
        for (const r of mem) {
          const n = metricName(r.metric?.name);
          const row = map.get(n) ?? { name: n, cpu: 0, mem: 0 };
          row.mem = Number(r.value?.[1] ?? 0);
          map.set(n, row);
        }
        setContainers([...map.values()].filter((c) => c.name).sort((a, b) => a.name.localeCompare(b.name)));
      } catch (err) {
        if (alive) setError(err.message);
      }
    }
    tick();
    const t = setInterval(tick, 5000);
    return () => { alive = false; clearInterval(t); };
  }, []);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>System monitor</h1>
          <p>Service health (Prometheus + cAdvisor) and container telemetry — refreshed every 5 seconds.</p>
        </div>
      </div>

      {error && <div className="empty">{error}</div>}

      <div className="sys-grid">
        <div className="card">
          <h2>Service health</h2>
          {!health ? (
            <div className="empty"><span className="spinner" /></div>
          ) : (
            <>
              {Object.entries(health.services ?? {}).map(([k, v]) => (
                <div className="svc-row" key={k}>
                  <span>
                    <span className={'svc-dot ' + (DOT_CLASS[v] ?? 'unknown')} />
                    {LABEL[k] ?? k}
                  </span>
                  <span className="chip">{v}</span>
                </div>
              ))}
              {health.queue && (
                <p className="field-hint mt-16">
                  BullMQ queue — waiting: {health.queue.waiting}, active: {health.queue.active},
                  completed: {health.queue.completed}, failed: {health.queue.failed}
                </p>
              )}
            </>
          )}
        </div>

        <div className="card">
          <h2>Prometheus targets</h2>
          {!health?.prometheusTargets ? (
            <div className="empty">Target data not available yet (Prometheus may still be starting).</div>
          ) : (
            health.prometheusTargets.map((t) => (
              <div className="svc-row" key={t.job + t.instance}>
                <span>
                  <span className={'svc-dot ' + (DOT_CLASS[t.health] ?? 'unknown')} />
                  <span className="mono">{t.job}</span> <span className="dim">({t.instance})</span>
                </span>
                <span className="chip">{t.health}</span>
              </div>
            ))
          )}
        </div>
      </div>

      <div className="card mt-24">
        <h2>Container telemetry</h2>
        {containers.length === 0 ? (
          <div className="empty">No container metrics yet (cAdvisor needs about a minute after startup).</div>
        ) : (
          <div className="table-wrap mt-16">
            <table className="table">
              <thead>
                <tr>
                  <th>Container</th>
                  <th>CPU (cores)</th>
                  <th>RAM (MB)</th>
                </tr>
              </thead>
              <tbody>
                {containers.map((c) => (
                  <tr key={c.name}>
                    <td className="mono">{c.name}</td>
                    <td className="mono">{c.cpu.toFixed(3)}</td>
                    <td className="mono">{(c.mem / 1048576).toFixed(1)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="field-hint mt-16">
          Source: <a href="/prometheus/targets" target="_blank" rel="noreferrer">/prometheus/targets</a> —
          exposed through the gateway for this local demo only.
        </p>
      </div>
    </>
  );
}
