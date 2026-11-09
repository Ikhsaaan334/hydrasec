import pg from 'pg';
import { config } from './config.js';
import { logger } from './logger.js';

export const pool = new pg.Pool({
  connectionString: config.databaseUrl,
  max: 8,
  idleTimeoutMillis: 30000,
});

pool.on('error', (err) => logger.error('pg pool error', { err: err.message }));

// Semua statement SQL di file ini konstanta string; setiap nilai terikat parameter.
export async function markScanRunning(id, containerId) {
  const { rows } = await pool.query(
    `UPDATE scans
        SET status = 'running', container_id = $2, started_at = now()
      WHERE id = $1
      RETURNING *`,
    [id, containerId ?? null]
  );
  return rows[0] ?? null;
}

export async function setScanStatus(id, status) {
  const { rows } = await pool.query(
    'UPDATE scans SET status = $2 WHERE id = $1 RETURNING *',
    [id, status]
  );
  return rows[0] ?? null;
}

// status akhir: completed | failed | timeout | cancelled — durasi dihitung SQL-side
export async function finishScan(id, status, error, exitCode) {
  const { rows } = await pool.query(
    `UPDATE scans
        SET status = $2,
            error = $3,
            exit_code = $4,
            finished_at = now(),
            duration_ms = CASE
              WHEN started_at IS NULL THEN NULL
              ELSE GREATEST(0, EXTRACT(EPOCH FROM (now() - started_at)) * 1000)::int
            END
      WHERE id = $1
      RETURNING *`,
    [id, status, error ?? null, Number.isInteger(exitCode) ? exitCode : null]
  );
  return rows[0] ?? null;
}

export async function addFindings(scanId, tool, findings) {
  if (!Array.isArray(findings) || findings.length === 0) return 0;
  let inserted = 0;
  for (const f of findings.slice(0, 500)) {
    await pool.query(
      `INSERT INTO vulnerabilities
        (scan_id, tool, title, severity, url, parameter, cwe, cve, cvss, description, remediation, evidence, metadata, detected_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
      [
        scanId,
        tool,
        String(f.title ?? 'Finding').slice(0, 500),
        String(f.severity ?? 'info'),
        f.url ? String(f.url).slice(0, 2048) : null,
        f.parameter ? String(f.parameter).slice(0, 200) : null,
        f.cwe ? String(f.cwe).slice(0, 40) : null,
        f.cve ? String(f.cve).slice(0, 40) : null,
        Number.isFinite(Number(f.cvss)) && f.cvss !== null && f.cvss !== '' ? Number(f.cvss) : null,
        f.description ? String(f.description).slice(0, 8000) : null,
        f.remediation ? String(f.remediation).slice(0, 4000) : null,
        f.evidence ? String(f.evidence).slice(0, 8000) : null,
        JSON.stringify(f.metadata ?? {}),
        new Date(),
      ]
    );
    inserted += 1;
  }
  return inserted;
}

// Tandai scan yang menggantung saat worker restart
export async function failStaleScans() {
  const { rowCount } = await pool.query(
    `UPDATE scans
        SET status = 'failed',
            error = 'cancelled: the worker restarted while the scan was running',
            finished_at = now()
      WHERE status IN ('running', 'parsing')`
  );
  return rowCount ?? 0;
}
