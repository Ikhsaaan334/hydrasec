import Redis from 'ioredis';
import { config } from './config.js';
import { logger } from './logger.js';

// Klien utama (perintah biasa)
export const redis = new Redis(config.redisUrl, {
  lazyConnect: false,
  maxRetriesPerRequest: 3,
});

redis.on('error', (err) => logger.warn('redis error', { err: err.message }));

export async function redisClose() {
  try { redis.disconnect(); } catch { /* noop */ }
}
