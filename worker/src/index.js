import { Worker } from 'bullmq';
import { config } from './config.js';
import { logger } from './logger.js';
import { redis, bullConnection } from './redis.js';
import {
  markScanRunning, finishScan, addFindings, failStaleScans, setScanStatus,
} from './db.js';
import { publishEvent, appendLog } from './events.js';
import { runScanContainer, sweepOrphanToolContainers, ensureVolumeRoot } from './runner.js';
import { parseResults } from './parsers/index.js';
import { CONTROL_CHANNEL } from './keys.js';
import {
  registry, scansProcessed, activeJobs, containerSeconds, startMetricsServer,
} from './metrics.js';

// ── kanal kontrol (cancel) ───────────────────────────────────────────────
const controlHandlers = new Map();
const controlSub = redis.duplicate();
controlSub.on('error', (err) => logger.warn('control sub error', { err: err.message }));
controlSub.on('message', (channel, message) => {
  const handler = controlHandlers.get(channel);
  if (handler) handler(message);
});
const controlSubscribed = new Set();

function controlSubscribe(channel, handler) {
  controlHandlers.set(channel, handler);
  if (!controlSubscribed.has(channel)) {
    controlSub.subscribe(channel);
    controlSubscribed.add(channel);
  }
  return () => {
    controlHandlers.delete(channel);
  };
}

// ── processor BullMQ ─────────────────────────────────────────────────────
async function processScan(job) {
  const { scanId, eventsChannel, tool, target, options } = job.data;
  const timer = containerSeconds.startTimer({ tool });
  activeJobs.inc();
  logger.info('processing scan', { scanId, tool, target });

  try {
    await publishEvent(eventsChannel, { type: 'status', scanId, status: 'running' });

    const result = await runScanContainer({
      scanId,
      eventsChannel,
      tool,
      target,
      options: options ?? {},
      controlSubscribe,
      onCreated: (containerId) => markScanRunning(scanId, containerId),
    });

    await appendTerminalSummary(eventsChannel, scanId, result);

    if (result.cancelled) {
      const row = await finishScan(scanId, 'cancelled', 'cancelled by user', result.exitCode);
      await publishEvent(eventsChannel, { type: 'status', scanId, status: 'cancelled', exitCode: result.exitCode });
      scansProcessed.inc({ tool, status: 'cancelled' });
      return { status: row?.status ?? 'cancelled' };
    }

    if (result.timedOut) {
      const row = await finishScan(scanId, 'timeout', 'exceeded the tool execution time limit', result.exitCode);
      await publishEvent(eventsChannel, { type: 'status', scanId, status: 'timeout', exitCode: result.exitCode });
      scansProcessed.inc({ tool, status: 'timeout' });
      return { status: row?.status ?? 'timeout' };
    }

    if (result.exitCode !== 0) {
      const row = await finishScan(
        scanId,
        'failed',
        'Tool exited with code ' + result.exitCode + ' (check the terminal for details)',
        result.exitCode
      );
      await publishEvent(eventsChannel, { type: 'status', scanId, status: 'failed', exitCode: result.exitCode });
      scansProcessed.inc({ tool, status: 'failed' });
      return { status: row?.status ?? 'failed' };
    }

    // sukses → parsing output mentah ke Unified Vulnerability Schema
    await publishEvent(eventsChannel, { type: 'status', scanId, status: 'parsing' });
    await setScanStatus(scanId, 'parsing');
    const findings = parseResults(tool, { outDir: result.outDir, consoleText: result.consoleText, target });
    const inserted = await addFindings(scanId, tool, findings);
    const bySeverity = countBySeverity(findings);
    const row = await finishScan(scanId, 'completed', null, result.exitCode);
    await publishEvent(eventsChannel, {
      type: 'status',
      scanId,
      status: 'completed',
      exitCode: 0,
      findings: inserted,
      bySeverity,
    });
    scansProcessed.inc({ tool, status: 'completed' });
    logger.info('scan completed', { scanId, tool, findings: inserted });
    return { status: 'completed', findings: inserted };
  } catch (err) {
    logger.error('scan failed', { scanId, tool, err: err.message });
    try {
      await finishScan(scanId, 'failed', String(err.message || 'worker error').slice(0, 500), null);
      await publishEvent(eventsChannel, { type: 'status', scanId, status: 'failed', error: String(err.message || '') });
    } catch (dbErr) {
      logger.error('failed to mark scan as failed', { scanId, err: dbErr.message });
    }
    scansProcessed.inc({ tool, status: 'failed' });
    return { status: 'failed' };
  } finally {
    activeJobs.dec();
    timer();
  }
}

function countBySeverity(findings) {
  const acc = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    const s = String(f.severity ?? 'info');
    if (s in acc) acc[s] += 1;
  }
  return acc;
}

async function appendTerminalSummary(eventsChannel, scanId, result) {
  const lines = [];
  lines.push('');
  lines.push('────[ HydraSec ]────────────────────────────');
  if (result.cancelled) lines.push('Scan cancelled by user.');
  else if (result.timedOut) lines.push('Scan stopped: execution time limit exceeded.');
  else lines.push('Tool process finished with exit code ' + result.exitCode + '.');
  lines.push('Results normalized by the Unified Vulnerability Parser.');
  lines.push('────────────────────────────────────────────');
  for (const line of lines) {
    await appendLog(eventsChannel, line + '\n');
  }
}

// ── bootstrap ────────────────────────────────────────────────────────────
async function main() {
  logger.info('worker starting', { concurrency: config.concurrency, queue: config.scanQueue });
  await ensureVolumeRoot();
  const swept = await sweepOrphanToolContainers();
  if (swept > 0) {
    const stale = await failStaleScans();
    logger.info('stale scans marked failed', { stale });
  }

  const worker = new Worker(config.scanQueue, processScan, {
    connection: bullConnection,
    concurrency: config.concurrency,
    lockDuration: 60_000,
  });
  worker.on('error', (err) => logger.warn('worker error', { err: err.message }));
  worker.on('stalled', (jobId) => logger.warn('job stalled', { jobId }));

  const metricsServer = startMetricsServer(config.metricsPort);

  // heartbeat untuk /api/health
  const beat = () => redis
    .set('worker:heartbeat', String(Date.now()), 'EX', 15)
    .catch(() => {});
  beat();
  setInterval(beat, 5000);

  async function shutdown() {
    logger.info('worker shutting down...');
    try { await worker.close(); } catch { /* noop */ }
    try { metricsServer.close(); } catch { /* noop */ }
    try { await redis.quit(); } catch { /* noop */ }
    try { await bullConnection.quit(); } catch { /* noop */ }
    try { controlSub.disconnect(); } catch { /* noop */ }
    process.exit(0);
  }
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch((err) => {
  logger.error('worker failed to start', { err: err.message });
  process.exit(1);
});
