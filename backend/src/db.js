import pg from 'pg';
import { config } from './config.js';
import { logger } from './logger.js';

export const pool = new pg.Pool({
  connectionString: config.databaseUrl,
  max: 10,
  idleTimeoutMillis: 30000,
});

pool.on('error', (err) => logger.error('pg pool error', { err: err.message }));

// ── users ────────────────────────────────────────────────────────────────
export async function findUserByEmail(email) {
  const { rows } = await pool.query(
    'SELECT id, email, username, name, created_at AS "createdAt", last_login_at AS "lastLoginAt" FROM users WHERE email = $1',
    [email]
  );
  return rows[0] ?? null;
}

export async function createUser(email, username) {
  const { rows } = await pool.query(
    'INSERT INTO users (email, username) VALUES ($1, $2) RETURNING id, email, username, created_at AS "createdAt"',
    [email, username]
  );
  return rows[0];
}

export async function touchLogin(id) {
  const { rows } = await pool.query(
    `UPDATE users
        SET last_login_at = now()
      WHERE id = $1
      RETURNING id, email, username, name, created_at AS "createdAt", last_login_at AS "lastLoginAt"`,
    [id]
  );
  return rows[0] ?? null;
}

export async function usernameTaken(username) {
  const { rows } = await pool.query(
    'SELECT 1 FROM users WHERE username = $1',
    [username]
  );
  return rows.length > 0;
}

// ── pending_users (email tervalidasi OTP, menunggu username unik) ────────
export async function pendingUpsert(emailDigest, email, expiresAt) {
  const { rows } = await pool.query(
    `INSERT INTO pending_users (email_digest, email, expires_at)
     VALUES ($1, $2, $3)
     ON CONFLICT (email_digest)
     DO UPDATE SET email = EXCLUDED.email, expires_at = EXCLUDED.expires_at`,
    [emailDigest, email, expiresAt]
  );
  return rows[0] ?? null;
}

export async function pendingGet(emailDigest) {
  const { rows } = await pool.query(
    'SELECT email_digest, email FROM pending_users WHERE email_digest = $1 AND expires_at > now()',
    [emailDigest]
  );
  return rows[0] ?? null;
}

export async function pendingDelete(emailDigest) {
  await pool.query('DELETE FROM pending_users WHERE email_digest = $1', [emailDigest]);
}

export async function pendingPurgeExpired() {
  const { rowCount } = await pool.query('DELETE FROM pending_users WHERE expires_at < now()');
  return rowCount ?? 0;
}

// ── scans ────────────────────────────────────────────────────────────────
export async function createScan({ id, userId, tool, target, options }) {
  const { rows } = await pool.query(
    'INSERT INTO scans (id, user_id, tool, target, options) VALUES ($1, $2, $3, $4, $5) RETURNING *',
    [id, userId, tool, target, JSON.stringify(options ?? {})]
  );
  return rows[0];
}

export async function getScan(id) {
  const { rows } = await pool.query('SELECT * FROM scans WHERE id = $1', [id]);
  return rows[0] ?? null;
}

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

export async function listScans({ userId, tool, status, limit, offset }) {
  // Filter opsional lewat NULL-check di dalam SQL; statement tetap literal statis.
  const { rows } = await pool.query(
    `SELECT * FROM scans
      WHERE user_id = $1
        AND ($2::text IS NULL OR tool = $2)
        AND ($3::text IS NULL OR status = $3)
      ORDER BY queued_at DESC
      LIMIT $4 OFFSET $5`,
    [userId, tool ?? null, status ?? null, limit, offset]
  );
  const totals = await pool.query(
    `SELECT count(*)::int AS total FROM scans
      WHERE user_id = $1
        AND ($2::text IS NULL OR tool = $2)
        AND ($3::text IS NULL OR status = $3)`,
    [userId, tool ?? null, status ?? null]
  );
  return { items: rows, total: totals.rows[0]?.total ?? 0 };
}

export async function ownsScan(id, userId) {
  const { rows } = await pool.query(
    'SELECT 1 FROM scans WHERE id = $1 AND user_id = $2',
    [id, userId]
  );
  return rows.length > 0;
}

// ── vulnerabilities (Unified Vulnerability Schema) ───────────────────────
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

export async function findingsForScan(scanId) {
  const { rows } = await pool.query(
    `SELECT id, tool, title, severity, url, parameter, cwe, cve, cvss, description, remediation, evidence, metadata, detected_at
       FROM vulnerabilities WHERE scan_id = $1 ORDER BY
         CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
         id`,
    [scanId]
  );
  return rows;
}

// ── stats ────────────────────────────────────────────────────────────────
export async function globalStats() {
  const scans = await pool.query('SELECT count(*)::int AS total FROM scans');
  const users = await pool.query('SELECT count(*)::int AS total FROM users');
  const vulns = await pool.query('SELECT count(*)::int AS total FROM vulnerabilities');
  const byTool = await pool.query(
    'SELECT tool, count(*)::int AS scans FROM scans GROUP BY tool ORDER BY scans DESC'
  );
  const bySeverity = await pool.query(
    'SELECT severity, count(*)::int AS total FROM vulnerabilities GROUP BY severity'
  );
  return {
    totalScans: scans.rows[0]?.total ?? 0,
    totalUsers: users.rows[0]?.total ?? 0,
    totalVulns: vulns.rows[0]?.total ?? 0,
    byTool: byTool.rows,
    bySeverity: bySeverity.rows,
  };
}

// ── leaderboard (username, bukan email) ──────────────────────────────────
export async function leaderboard(limit) {
  const { rows } = await pool.query(
    `SELECT u.username, count(s.id)::int AS scans
       FROM users u JOIN scans s ON s.user_id = u.id
      GROUP BY u.username
      ORDER BY scans DESC, u.username ASC
      LIMIT $1`,
    [limit]
  );
  return rows;
}

export async function userStats(userId) {
  const scans = await pool.query(
    'SELECT count(*)::int AS total FROM scans WHERE user_id = $1',
    [userId]
  );
  const byTool = await pool.query(
    'SELECT tool, count(*)::int AS scans FROM scans WHERE user_id = $1 GROUP BY tool ORDER BY scans DESC',
    [userId]
  );
  const bySeverity = await pool.query(
    `SELECT v.severity, count(*)::int AS total
       FROM vulnerabilities v JOIN scans s ON s.id = v.scan_id
      WHERE s.user_id = $1 GROUP BY v.severity`,
    [userId]
  );
  const byStatus = await pool.query(
    'SELECT status, count(*)::int AS total FROM scans WHERE user_id = $1 GROUP BY status',
    [userId]
  );
  return {
    totalScans: scans.rows[0]?.total ?? 0,
    byTool: byTool.rows,
    bySeverity: bySeverity.rows,
    byStatus: byStatus.rows,
  };
}

// ── OTP (kode tersimpan sebagai hash di PostgreSQL, bukan Redis) ─────────
export async function otpGetRow(emailDigest) {
  const { rows } = await pool.query(
    'SELECT email_digest, code_hash, attempts, last_request_at, expires_at FROM otps WHERE email_digest = $1',
    [emailDigest]
  );
  return rows[0] ?? null;
}

export async function otpUpsert(emailDigest, codeHash, expiresAt) {
  const { rows } = await pool.query(
    `INSERT INTO otps (email_digest, code_hash, attempts, last_request_at, expires_at)
     VALUES ($1, $2, 0, now(), $3)
     ON CONFLICT (email_digest)
     DO UPDATE SET code_hash = EXCLUDED.code_hash,
                   attempts = 0,
                   last_request_at = now(),
                   expires_at = EXCLUDED.expires_at`,
    [emailDigest, codeHash, expiresAt]
  );
  return rows[0] ?? null;
}

export async function otpBumpAttempts(emailDigest) {
  const { rows } = await pool.query(
    'UPDATE otps SET attempts = attempts + 1 WHERE email_digest = $1 RETURNING attempts',
    [emailDigest]
  );
  return rows[0]?.attempts ?? null;
}

export async function otpDelete(emailDigest) {
  await pool.query('DELETE FROM otps WHERE email_digest = $1', [emailDigest]);
}

// hapus OTP kedaluwarsa (dipanggil berkala dari index.js)
export async function otpPurgeExpired() {
  const { rowCount } = await pool.query('DELETE FROM otps WHERE expires_at < now()');
  return rowCount ?? 0;
}
