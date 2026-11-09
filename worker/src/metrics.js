import http from 'node:http';
import client from 'prom-client';
import { logger } from './logger.js';

export const registry = new client.Registry();
client.collectDefaultMetrics({ register: registry, prefix: 'hydrasec_' });

export const scansProcessed = new client.Counter({
  name: 'hydrasec_worker_scans_processed_total',
  help: 'Scan yang selesai diproses worker',
  labelNames: ['tool', 'status'],
  registers: [registry],
});

export const activeJobs = new client.Gauge({
  name: 'hydrasec_worker_active_jobs',
  help: 'Kontainer tool yang sedang berjalan',
  registers: [registry],
});

export const containerSeconds = new client.Histogram({
  name: 'hydrasec_worker_container_duration_seconds',
  help: 'Durasi eksekusi kontainer tool',
  labelNames: ['tool'],
  registers: [registry],
  buckets: [1, 5, 15, 60, 300, 900, 1800],
});

export function startMetricsServer(port) {
  const server = http.createServer(async (req, res) => {
    if (req.url === '/metrics') {
      res.setHeader('Content-Type', registry.contentType);
      res.end(await registry.metrics());
      return;
    }
    res.statusCode = 404;
    res.end();
  });
  server.listen(port, () => logger.info('metrics server listen', { port }));
  return server;
}
