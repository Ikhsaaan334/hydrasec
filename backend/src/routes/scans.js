import { Router } from 'express';
import crypto from 'node:crypto';
import { authRequired } from '../middleware/auth.js';
import { validateScanInput, toolList } from '../validators.js';
import { createScan, getScan, listScans, setScanStatus, ownsScan, findingsForScan } from '../db.js';
import { scanQueue } from '../queue.js';
import { redis } from '../redis.js';
import { EVENTS_CHANNEL, CONTROL_CHANNEL } from '../keys.js';
import { scansQueued } from '../metrics.js';
import { config } from '../config.js';

export const scansRouter = Router();

scansRouter.use(authRequired);

export function serializeScan(scan) {
  if (!scan) return null;
  return {
    id: scan.id,
    tool: scan.tool,
    target: scan.target,
    status: scan.status,
    error: scan.error ?? null,
    exitCode: scan.exit_code ?? null,
    options: scan.options ?? {},
    queuedAt: scan.queued_at,
    startedAt: scan.started_at,
    finishedAt: scan.finished_at,
    durationMs: scan.duration_ms,
  };
}

const TERMINAL_STATUSES = new Set(['completed', 'failed', 'timeout', 'cancelled']);
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// GET /api/scans/tools — katalog tool untuk UI
scansRouter.get('/tools', (req, res) => {
  res.json({ tools: toolList(), allowPrivateTargets: config.allowPrivateTargets });
});

// POST /api/scans — validasi → simpan → enqueue ke Redis/BullMQ
scansRouter.post('/', async (req, res, next) => {
  try {
    const body = req.body ?? {};
    const v = await validateScanInput({ tool: body.tool, target: body.target, options: body.options });
    if (!v.ok) {
      return res.status(400).json({ error: v.reason });
    }

    const id = crypto.randomUUID();
    const scan = await createScan({
      id,
      userId: req.user.id,
      tool: body.tool,
      target: v.target,
      options: v.options,
    });

    await scanQueue.add(
      'scan',
      {
        scanId: id,
        eventsChannel: scan.events_channel, // suffix kanal dari DB, bukan input user
        tool: body.tool,
        target: v.target,
        options: v.options,
        userId: req.user.id,
      },
      { jobId: id }
    );
    scansQueued.inc({ tool: body.tool });

    return res.status(201).json({ scan: serializeScan(scan) });
  } catch (err) { return next(err); }
});

// GET /api/scans?tool=&status=&page=&pageSize=
scansRouter.get('/', async (req, res, next) => {
  try {
    const page = Math.max(1, Math.min(1000, parseInt(String(req.query.page || '1'), 10) || 1));
    const pageSize = Math.max(1, Math.min(100, parseInt(String(req.query.pageSize || '20'), 10) || 20));
    const tool = typeof req.query.tool === 'string' && TOOLS_KEYS.has(req.query.tool) ? req.query.tool : null;
    const status = typeof req.query.status === 'string' && STATUSES.has(req.query.status) ? req.query.status : null;

    const { items, total } = await listScans({
      userId: req.user.id,
      tool,
      status,
      limit: pageSize,
      offset: (page - 1) * pageSize,
    });
    return res.json({ items: items.map(serializeScan), total, page, pageSize });
  } catch (err) { return next(err); }
});

const TOOLS_KEYS = new Set(Object.keys({
  nmap: 1, nuclei: 1, xsstrike: 1, xray: 1, sqlmap: 1, ffuf: 1,
}));
const STATUSES = new Set(['queued', 'running', 'parsing', 'completed', 'failed', 'timeout', 'cancelled']);

// GET /api/scans/:id — detail + findings (hanya milik sendiri)
scansRouter.get('/:id', async (req, res, next) => {
  try {
    const id = String(req.params.id || '');
    if (!UUID_RE.test(id)) return res.status(400).json({ error: 'Invalid scan id format' });
    if (!(await ownsScan(id, req.user.id))) return res.status(404).json({ error: 'Scan not found' });
    const scan = await getScan(id);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    const findings = await findingsForScan(id);
    return res.json({ scan: serializeScan(scan), findings });
  } catch (err) { return next(err); }
});

// POST /api/scans/:id/cancel
scansRouter.post('/:id/cancel', async (req, res, next) => {
  try {
    const id = String(req.params.id || '');
    if (!UUID_RE.test(id)) return res.status(400).json({ error: 'Invalid scan id format' });
    if (!(await ownsScan(id, req.user.id))) return res.status(404).json({ error: 'Scan not found' });
    const scan = await getScan(id);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    if (TERMINAL_STATUSES.has(scan.status)) {
      return res.status(409).json({ error: 'Scan already in a final state (' + scan.status + ')' });
    }

    if (scan.status === 'queued') {
      const job = await scanQueue.getJob(id);
      if (job) { try { await job.remove(); } catch { /* mungkin sudah jalan */ } }
      const updated = await setScanStatus(id, 'cancelled');
      await redis.publish(
        EVENTS_CHANNEL(scan.events_channel),
        JSON.stringify({ type: 'status', scanId: id, status: 'cancelled' })
      );
      return res.json({ ok: true, scan: serializeScan(updated) });
    }

    // running/parsing → minta worker membunuh kontainer via kanal kontrol
    await redis.publish(
      CONTROL_CHANNEL(scan.events_channel),
      JSON.stringify({ action: 'cancel', scanId: id })
    );
    return res.status(202).json({ ok: true, message: 'Cancellation request sent to the worker' });
  } catch (err) { return next(err); }
});

// GET /api/scans/:id/export — unduh temuan ter-normalisasi (JSON)
scansRouter.get('/:id/export', async (req, res, next) => {
  try {
    const id = String(req.params.id || '');
    if (!UUID_RE.test(id)) return res.status(400).json({ error: 'Invalid scan id format' });
    if (!(await ownsScan(id, req.user.id))) return res.status(404).json({ error: 'Scan not found' });
    const scan = await getScan(id);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    const findings = await findingsForScan(id);
    res.set('Content-Disposition', 'attachment; filename="hydrasec-scan-' + id + '.json"');
    return res.json({ scan: serializeScan(scan), findings, exportedAt: new Date().toISOString(), schema: 'hydrasec.unified.v1' });
  } catch (err) { return next(err); }
});
