-- HydraSec — skema awal PostgreSQL (dipasang otomatis oleh image postgres resmi)

CREATE TABLE IF NOT EXISTS users (
  id            BIGSERIAL PRIMARY KEY,
  email         TEXT        NOT NULL UNIQUE,
  username      TEXT        NOT NULL UNIQUE,
  name          TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_login_at TIMESTAMPTZ
);

-- Pendaftaran yang menunggu pemilihan username unik
-- (email sudah tervalidasi OTP, akun belum dibuat)
CREATE TABLE IF NOT EXISTS pending_users (
  email_digest TEXT        PRIMARY KEY,  -- sha256(email) hex
  email        TEXT        NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at   TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pending_users_expires ON pending_users (expires_at);

CREATE TABLE IF NOT EXISTS scans (
  id          UUID        PRIMARY KEY,
  user_id     BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tool        TEXT        NOT NULL,
  target      TEXT        NOT NULL,
  options     JSONB       NOT NULL DEFAULT '{}'::jsonb,
  status      TEXT        NOT NULL DEFAULT 'queued'
              CHECK (status IN ('queued','running','parsing','completed','failed','timeout','cancelled')),
  error       TEXT,
  container_id TEXT,
  exit_code   INTEGER,
  events_channel TEXT     NOT NULL DEFAULT gen_random_uuid()::text,
  queued_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  started_at  TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  duration_ms INTEGER
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
  id          BIGSERIAL PRIMARY KEY,
  scan_id     UUID        NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  tool        TEXT        NOT NULL,
  title       TEXT        NOT NULL,
  severity    TEXT        NOT NULL
              CHECK (severity IN ('critical','high','medium','low','info')),
  url         TEXT,
  parameter   TEXT,
  cwe         TEXT,
  cve         TEXT,
  cvss        NUMERIC(4,1),
  description TEXT,
  remediation TEXT,
  evidence    TEXT,
  metadata    JSONB       NOT NULL DEFAULT '{}'::jsonb,
  detected_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_scans_user    ON scans (user_id, queued_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_tool    ON scans (tool);
CREATE INDEX IF NOT EXISTS idx_scans_status  ON scans (status);
CREATE INDEX IF NOT EXISTS idx_vulns_scan    ON vulnerabilities (scan_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities (severity);

-- OTP: kode disimpan sebagai hash + kedaluwarsa di database (bukan Redis)
CREATE TABLE IF NOT EXISTS otps (
  email_digest    TEXT        PRIMARY KEY,  -- sha256(email) hex
  code_hash       TEXT        NOT NULL,     -- sha256(code) hex
  attempts        INTEGER     NOT NULL DEFAULT 0,
  last_request_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at      TIMESTAMPTZ NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Bersih-bersih berkala (dipanggil backend secara periodik)
CREATE INDEX IF NOT EXISTS idx_otps_expires ON otps (expires_at);
