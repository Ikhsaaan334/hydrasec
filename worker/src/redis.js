import Redis from 'ioredis';
import { config } from './config.js';
import { logger } from './logger.js';

// Klien perintah umum (publish, list ops, heartbeat)
export const redis = new Redis(config.redisUrl, { maxRetriesPerRequest: 3 });
redis.on('error', (err) => logger.warn('redis error', { err: err.message }));

// Koneksi BullMQ mensyaratkan maxRetriesPerRequest: null
export const bullConnection = new Redis(config.redisUrl, { maxRetriesPerRequest: null });
bullConnection.on('error', (err) => logger.warn('bullmq redis error', { err: err.message }));
