import { Router } from 'express';
import { pool } from '../db.js';
import { redis } from '../redis.js';
import { scanQueue } from '../queue.js';
import { WORKER_HEARTBEAT_KEY } from '../keys.js';
import { config } from '../config.js';

export const healthRouter = Router();

// GET /api/health — liveness + status dependensi (db/redis/worker/prometheus)
healthRouter.get('/', async (req, res) => {
  const result = {
    status: 'ok',
    version: config.version,
    uptimeSec: Math.round(process.uptime()),
    services: {},
    queue: null,
    prometheusTargets: null,
  };

  let coreOk = true;

  try {
    await pool.query('SELECT 1');
    result.services.database = 'up';
  } catch {
    result.services.database = 'down';
    coreOk = false;
  }

  try {
    const pong = await redis.ping();
    result.services.redis = pong === 'PONG' ? 'up' : 'down';
    if (pong !== 'PONG') coreOk = false;
  } catch {
    result.services.redis = 'down';
    coreOk = false;
  }

  try {
    const hb = await redis.get(WORKER_HEARTBEAT_KEY);
    result.services.worker = hb ? 'up' : 'down';
  } catch {
    result.services.worker = 'unknown';
  }

  try {
    const counts = await scanQueue.getJobCounts();
    result.queue = {
      waiting: counts.waiting ?? 0,
      active: counts.active ?? 0,
      completed: counts.completed ?? 0,
      failed: counts.failed ?? 0,
    };
  } catch {
    result.queue = null;
  }

  try {
    const resp = await fetch(config.prometheusUrl + '/api/v1/query?query=up', {
      signal: AbortSignal.timeout(2500),
    });
    const body = await resp.json();
    if (body?.status === 'success') {
      result.prometheusTargets = (body.data?.result ?? []).map((r) => ({
        job: r.metric?.job ?? '?',
        instance: r.metric?.instance ?? '?',
        health: Number(r.value?.[1]) === 1 ? 'up' : 'down',
      }));
    }
  } catch {
    result.prometheusTargets = null; // prometheus down tidak menjatuhkan health
  }

  const allDown =
    result.services.worker === 'down' &&
    !result.prometheusTargets;
  if (allDown) result.status = 'degraded';
  else if (!coreOk) result.status = 'degraded';

  return res.status(coreOk ? 200 : 503).json(result);
});
