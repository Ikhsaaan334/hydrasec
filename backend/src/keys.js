// Nama kanal Redis untuk event/log scan. Suffix-nya berasal dari kolom
// events_channel di tabel scans (di-generate server-side saat INSERT) —
// bukan dari input user — sehingga tidak ada data tak tepercaya dalam key.
export const EVENTS_CHANNEL = (channel) => 'scan:events:' + channel;
export const LOGS_KEY = (channel) => 'scan:logs:' + channel;
export const CONTROL_CHANNEL = (channel) => 'scan:control:' + channel;
export const WORKER_HEARTBEAT_KEY = 'worker:heartbeat';
