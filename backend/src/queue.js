import { Queue } from 'bullmq';
import Redis from 'ioredis';
import { config } from './config.js';

// BullMQ mensyaratkan maxRetriesPerRequest: null untuk koneksinya
const connection = new Redis(config.redisUrl, { maxRetriesPerRequest: null });

export const scanQueue = new Queue(config.scanQueue, {
  connection,
  defaultJobOptions: {
    attempts: 1,
    removeOnComplete: { age: 3600, count: 1000 },
    removeOnFail: { age: 3600, count: 1000 },
  },
});
