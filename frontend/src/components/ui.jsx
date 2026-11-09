const ORDER = ['critical', 'high', 'medium', 'low', 'info'];

export function SeverityBadge({ severity }) {
  const s = ORDER.includes(severity) ? severity : 'info';
  return <span className={'badge-sev badge-sev-' + s}>{s}</span>;
}

const STATUS_LABEL = {
  queued: 'queued',
  running: 'running',
  parsing: 'parsing',
  completed: 'completed',
  failed: 'failed',
  timeout: 'timeout',
  cancelled: 'cancelled',
};

export function StatusChip({ status }) {
  const s = STATUS_LABEL[status] ? status : 'queued';
  return <span className={'chip chip-status-' + s}>{STATUS_LABEL[s]}</span>;
}

export function StatCard({ value, label, accent }) {
  return (
    <div className="card card-hover">
      <div className="stat-num" style={accent ? { color: 'var(--accent)' } : undefined}>
        {value}
      </div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

export function Bars({ items }) {
  const max = Math.max(1, ...items.map((i) => i.value));
  if (!items.length) return <div className="empty">No data yet.</div>;
  return (
    <div className="bars">
      {items.map((it) => (
        <div className="bar-row" key={it.label}>
          <span className="bar-label">{it.label}</span>
          <div className="bar-track">
            <div className="bar-fill" style={{ width: Math.round((it.value / max) * 100) + '%' }} />
          </div>
          <span className="bar-num">{it.value}</span>
        </div>
      ))}
    </div>
  );
}

export function formatDuration(ms) {
  if (ms === null || ms === undefined) return '—';
  if (ms < 1000) return ms + ' ms';
  const s = Math.round(ms / 1000);
  if (s < 60) return s + ' s';
  const m = Math.floor(s / 60);
  return m + ' m ' + (s % 60) + ' s';
}

export function formatDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' });
}
