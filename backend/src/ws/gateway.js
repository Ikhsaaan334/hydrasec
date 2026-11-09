import { WebSocketServer } from 'ws';
import jwt from 'jsonwebtoken';
import { config } from '../config.js';
import { redis } from '../redis.js';
import { ownsScan, getScan } from '../db.js';
import { EVENTS_CHANNEL, LOGS_KEY } from '../keys.js';
import { wsActive } from '../metrics.js';
import { logger } from '../logger.js';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Gateway WebSocket: autentikasi JWT, subscribe ke kanal event Redis,
// dan replay buffer log (agar refresh halaman tetap melihat riwayat terminal).
export function attachWsGateway(server) {
  const wss = new WebSocketServer({ server, path: '/ws' });

  // Satu koneksi subscriber Redis dipakai bersama semua klien
  const subConn = redis.duplicate();
  subConn.on('error', (err) => logger.warn('ws redis sub error', { err: err.message }));

  const channelRefs = new Map(); // channel -> Set<ws>

  subConn.on('message', (channel, message) => {
    const clients = channelRefs.get(channel);
    if (!clients) return;
    for (const ws of clients) {
      if (ws.readyState === ws.OPEN) ws.send(message);
    }
  });

  const ensureSubscribed = (channel) => {
    if (!channelRefs.has(channel)) {
      channelRefs.set(channel, new Set());
      subConn.subscribe(channel);
    }
  };

  const releaseChannelIfIdle = (channel) => {
    const clients = channelRefs.get(channel);
    if (clients && clients.size === 0) {
      channelRefs.delete(channel);
      subConn.unsubscribe(channel);
    }
  };

  wss.on('connection', (ws, req) => {
    // Autentikasi: ?token=<jwt>
    try {
      const u = new URL(req.url, 'http://internal');
      const token = u.searchParams.get('token') || '';
      const payload = jwt.verify(token, config.jwtSecret);
      if (!payload?.sub) throw new Error('token tanpa sub');
      ws.hydraUser = { id: Number(payload.sub) };
    } catch {
      ws.close(4001, 'unauthorized');
      return;
    }

    wsActive.inc();
    ws.hydraSubs = new Set(); // daftar scanId

    ws.on('close', () => {
      wsActive.dec();
      for (const scanId of ws.hydraSubs) {
        const scan = ws.hydraChannels?.get(scanId);
        if (!scan) continue;
        const clients = channelRefs.get(scan);
        if (clients) {
          clients.delete(ws);
          releaseChannelIfIdle(scan);
        }
      }
    });

    ws.on('message', async (buf) => {
      let msg = null;
      try { msg = JSON.parse(buf.toString()); } catch { return; }
      if (!msg || msg.type !== 'subscribe' || typeof msg.scanId !== 'string') return;
      const scanId = msg.scanId;
        if (!UUID_RE.test(scanId)) {
          ws.send(JSON.stringify({ type: 'error', scanId, message: 'Invalid scan id format' }));
          return;
        }
      try {
        if (!(await ownsScan(scanId, ws.hydraUser.id))) {
          ws.send(JSON.stringify({ type: 'error', scanId, message: 'Scan not found' }));
          return;
        }
        const scan = await getScan(scanId);
        if (!scan) {
          ws.send(JSON.stringify({ type: 'error', scanId, message: 'Scan not found' }));
          return;
        }
        const channel = EVENTS_CHANNEL(scan.events_channel);
        if (!ws.hydraChannels) ws.hydraChannels = new Map();
        ws.hydraChannels.set(scanId, channel);
        ws.hydraSubs.add(scanId);
        ensureSubscribed(channel);
        channelRefs.get(channel).add(ws);

        // Replay buffer log agar terminal terisi riwayat penuh
        const chunks = await redis.lrange(LOGS_KEY(scan.events_channel), 0, -1);
        for (const chunk of chunks) {
          ws.send(JSON.stringify({ type: 'log', scanId, data: chunk }));
        }
        ws.send(JSON.stringify({
          type: 'status',
          scanId,
          status: scan.status,
          exitCode: scan.exit_code ?? null,
          error: scan.error ?? null,
        }));
        ws.send(JSON.stringify({ type: 'subscribed', scanId }));
      } catch (err) {
        logger.warn('ws subscribe failed', { err: err.message });
        ws.send(JSON.stringify({ type: 'error', scanId, message: 'Subscribe failed' }));
      }
    });
  });

  // heartbeat: matikan koneksi mati
  const interval = setInterval(() => {
    for (const ws of wss.clients) {
      if (ws.isAlive === false) { ws.terminate(); continue; }
      ws.isAlive = false;
      ws.ping();
    }
  }, 30000);
  wss.on('close', () => clearInterval(interval));
  wss.on('connection', (ws) => {
    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; });
  });

  return wss;
}
