import client from 'prom-client';

export const registry = new client.Registry();
client.collectDefaultMetrics({ register: registry, prefix: 'hydrasec_' });

export const httpRequests = new client.Counter({
  name: 'hydrasec_http_requests_total',
  help: 'Total HTTP requests handled by the backend API',
  labelNames: ['method', 'route', 'code'],
  registers: [registry],
});

export const scansQueued = new client.Counter({
  name: 'hydrasec_scans_queued_total',
  help: 'Total scans enqueued, by tool',
  labelNames: ['tool'],
  registers: [registry],
});

export const wsActive = new client.Gauge({
  name: 'hydrasec_ws_connections',
  help: 'Currently open WebSocket connections',
  registers: [registry],
});

export async function metricsHandler(req, res) {
  try {
    res.set('Content-Type', registry.contentType);
    res.end(await registry.metrics());
  } catch (err) {
    res.status(500).end(`# metrics error: ${err.message}`);
  }
}
