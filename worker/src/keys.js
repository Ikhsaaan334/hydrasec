// Nama kanal/key Redis untuk event & buffer log scan.
// Suffix berasal dari kolom events_channel tabel scans (server-side) atau
// dari payload job BullMQ (server-side) — bukan dari input user.
export const EVENTS_CHANNEL = (channel) => 'scan:events:' + channel;
export const LOGS_KEY = (channel) => 'scan:logs:' + channel;
export const CONTROL_CHANNEL = (channel) => 'scan:control:' + channel;
export const WORKER_HEARTBEAT_KEY = 'worker:heartbeat';
export const LOG_BUFFER_MAX = 4000; // jumlah chunk log yang di-buffer untuk replay
export const LOG_TTL_SECONDS = 3 * 24 * 3600;
