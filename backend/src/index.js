import http from 'node:http';
import express from 'express';
import { config } from './config.js';
import { logger } from './logger.js';
import { pool } from './db.js';
import { redis, redisClose } from './redis.js';
import { httpRequests, metricsHandler } from './metrics.js';
import { otpPurgeExpired, pendingPurgeExpired } from './db.js';
import { startMailWorker } from './mailer.js';
import { authRouter } from './routes/auth.js';
import { scansRouter } from './routes/scans.js';
import { statsRouter } from './routes/stats.js';
import { healthRouter } from './routes/health.js';
import { attachWsGateway } from './ws/gateway.js';
import { authRequired } from './middleware/auth.js';

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '64kb' }));

// security headers ringan
app.use((req, res, nextFn) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy', "default-src 'none'");
  nextFn();
});

// metrik + request log
app.use((req, res, nextFn) => {
  const start = process.hrtime.bigint();
  res.on('finish', () => {
    const route = req.route?.path ? (req.baseUrl || '') + req.route.path : 'unmatched';
    httpRequests.inc({ method: req.method, route, code: res.statusCode });
    if (req.path.startsWith('/api/')) {
      logger.info('http', { method: req.method, path: req.path, code: res.statusCode, ms: Number(process.hrtime.bigint() - start) / 1e6 });
    }
  });
  nextFn();
});

app.get('/metrics', metricsHandler);
app.use('/api/auth', authRouter);
app.use('/api/scans', scansRouter);
app.use('/api/stats', statsRouter);
app.use('/api/health', healthRouter);

// GET /api/me — profil user login
app.get('/api/me', authRequired, async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, email, username, name, created_at AS "createdAt" FROM users WHERE id = $1',
      [req.user.id]
    );
    return res.json({ user: rows[0] ?? null });
  } catch (err) { return next(err); }
});

// 404 + error handler
app.use((req, res) => res.status(404).json({ error: 'Endpoint not found' }));
app.use((err, req, res, nextFn) => {
  logger.error('unhandled api error', { err: err.message, path: req.path });
  res.status(err.statusCode || err.status || 500).json({ error: 'Internal server error' });
});

const server = http.createServer(app);
attachWsGateway(server);

server.listen(config.port, () => {
  logger.info('backend API running', { port: config.port, version: config.version });
});

// consumer outbox email (kirim OTP async + retry)
startMailWorker();

// bersihkan OTP & pendaftaran kedaluwarsa tiap 10 menit
setInterval(() => {
  otpPurgeExpired().catch((err) => logger.warn('otp purge failed', { err: err.message }));
  pendingPurgeExpired().catch((err) => logger.warn('pending purge failed', { err: err.message }));
}, 10 * 60 * 1000);

async function shutdown() {
  logger.info('shutdown...');
  try { await new Promise((r) => server.close(r)); } catch { /* noop */ }
  try { await pool.end(); } catch { /* noop */ }
  redisClose();
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
