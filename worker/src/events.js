import { redis } from './redis.js';
import { EVENTS_CHANNEL, LOGS_KEY, LOG_BUFFER_MAX, LOG_TTL_SECONDS } from './keys.js';

// Publikasikan event status ke kanal scan (dikonsumsi gateway WS backend)
export async function publishEvent(eventsChannel, payload) {
  try {
    await redis.publish(EVENTS_CHANNEL(eventsChannel), JSON.stringify(payload));
  } catch (err) {
    // jangan biarkan kegagalan pub gagal menghentikan pipeline scan
  }
}

// Tulis chunk log ke buffer replay (list) lalu broadcast live.
export async function appendLog(eventsChannel, chunk) {
  const text = typeof chunk === 'string' ? chunk : chunk.toString('utf8');
  const listKey = LOGS_KEY(eventsChannel);
  try {
    await redis
      .multi()
      .rpush(listKey, text)
      .ltrim(listKey, -LOG_BUFFER_MAX, -1)
      .expire(listKey, LOG_TTL_SECONDS)
      .exec();
  } catch {
    // buffer best-effort
  }
  await publishEvent(eventsChannel, { type: 'log', data: text });
}
