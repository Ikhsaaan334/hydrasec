const num = (v, d) => {
  const n = parseInt(v ?? '', 10);
  return Number.isFinite(n) && n > 0 ? n : d;
};

export const config = {
  port: num(process.env.PORT, 3001),
  databaseUrl: process.env.DATABASE_URL || '',
  redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
  jwtSecret: process.env.JWT_SECRET || 'dev-only-secret-change-me-in-production',
  jwtTtl: process.env.JWT_TTL || '7d',
  smtpUrl: process.env.SMTP_URL || '',
  mailFrom: process.env.MAIL_FROM || 'HydraSec <no-reply@hydrasec.local>',
  otpTtlSeconds: num(process.env.OTP_TTL_SECONDS, 300),
  otpLength: num(process.env.OTP_LENGTH, 6),
  otpMaxAttempts: num(process.env.OTP_MAX_ATTEMPTS, 5),
  otpCooldownSeconds: num(process.env.OTP_RESEND_COOLDOWN, 60),
  allowPrivateTargets: process.env.ALLOW_PRIVATE_TARGETS === 'true',
  scanQueue: process.env.SCAN_QUEUE || 'scans',
  prometheusUrl: process.env.PROMETHEUS_URL || 'http://prometheus:9090/prometheus',
  version: '1.0.0',
};

if (config.jwtSecret.startsWith('dev-only')) {
  console.warn('[hydrasec] JWT_SECRET memakai nilai dev default — jangan dipakai di produksi.');
}
