import nodemailer from 'nodemailer';
import Redis from 'ioredis';
import { config } from './config.js';
import { logger } from './logger.js';

const transport = config.smtpUrl ? nodemailer.createTransport(config.smtpUrl) : null;

// ── Guard penerima email (anti header-injection) ─────────────────────────
const EMAIL_RE = /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,251}\.[A-Za-z]{2,15}$/;
const SMTP_FORBIDDEN = /[\r\n\u0000\u0001-\u001f\u007f]/;

export function assertRecipientSafe(email) {
  const raw = String(email ?? '');
  if (!EMAIL_RE.test(raw)) {
    throw new Error('Recipient rejected: invalid email format');
  }
  if (SMTP_FORBIDDEN.test(raw)) {
    throw new Error('Recipient rejected: control characters detected');
  }
  const domain = raw.slice(raw.lastIndexOf('@') + 1).toLowerCase();
  if (domain === 'localhost' || domain === 'hydrasec.local') {
    throw new Error('Recipient rejected: internal domain');
  }
  return raw;
}

// ── Outbox async: API hanya men-enqueue, consumer terpisah yang mengirim ──
const OUTBOX_KEY = 'mail:outbox';
const PROCESSING_KEY = 'mail:processing';
const MAX_ATTEMPTS = 3;

const outboxClient = new Redis(config.redisUrl, { maxRetriesPerRequest: null, enableOfflineQueue: false });
outboxClient.on('error', (err) => logger.warn('mail outbox redis error', { err: err.message }));

export async function enqueueOtpEmail(email, code, ttlSeconds) {
  const recipient = assertRecipientSafe(email);
  const payload = JSON.stringify({
    kind: 'otp',
    to: recipient,
    code: String(code),
    ttlSeconds: Number(ttlSeconds) || 300,
    attempts: 0,
    queuedAt: Date.now(),
  });
  await outboxClient.lpush(OUTBOX_KEY, payload);
  logger.info('OTP enqueued to mail outbox', { to: recipient });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function buildMail(job) {
  const ttlMinutes = Math.max(1, Math.round(job.ttlSeconds / 60));
  const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const code = esc(job.code);
  const mins = esc(ttlMinutes);
  const html = `<!doctype html>
<html><body style="margin:0;background:#0a0f0d;font-family:Arial,Helvetica,sans-serif;">
  <div style="max-width:520px;margin:0 auto;padding:32px 24px;">
    <div style="background:#101816;border:1px solid #1d2a26;border-radius:10px;padding:28px;">
      <p style="margin:0 0 6px;color:#4ade80;font-size:13px;letter-spacing:2px;text-transform:uppercase;">HydraSec</p>
      <h1 style="margin:0 0 16px;color:#f2f7f5;font-size:20px;">Your access code</h1>
      <div style="background:#0a0f0d;border:1px solid #24332e;border-radius:8px;padding:18px;text-align:center;">
        <span style="font-size:34px;letter-spacing:10px;color:#4ade80;font-family:Consolas,monospace;font-weight:700;">${code}</span>
      </div>
      <p style="margin:18px 0 0;color:#8ba39b;font-size:13px;line-height:1.6;">
        Valid for ${mins} minutes. Do not share this code with anyone.
        If you did not request it, ignore this email.
      </p>
    </div>
  </div>
</body></html>`;
  return {
    from: config.mailFrom,
    to: job.to,
    subject: `HydraSec access code: ${job.code}`,
    text: `Your HydraSec access code: ${job.code}\n\nValid for ${ttlMinutes} minutes. Do not share this code with anyone.`,
    html,
  };
}

export function startMailWorker() {
  const client = new Redis(config.redisUrl, { maxRetriesPerRequest: null });
  client.on('error', (err) => logger.warn('mail worker redis error', { err: err.message }));

  async function deliver(job) {
    if (!transport) {
      logger.warn('SMTP not configured — OTP printed to backend logs', { to: job.to, code: job.code });
      return;
    }
    await transport.sendMail(buildMail(job));
    logger.info('OTP email sent', { to: job.to });
  }

  (async () => {
    logger.info('mail outbox worker running', { transport: transport ? 'smtp' : 'console' });
    for (;;) {
      let raw = null;
      try {
        raw = await client.brpoplpush(OUTBOX_KEY, PROCESSING_KEY, 5);
      } catch (err) {
        logger.warn('mail outbox pop failed', { err: err.message });
        await sleep(2000);
        continue;
      }
      if (!raw) continue;
      let job = null;
      try { job = JSON.parse(raw); } catch {
        await client.lrem(PROCESSING_KEY, 1, raw).catch(() => {});
        continue;
      }
      try {
        await deliver(job);
        await client.lrem(PROCESSING_KEY, 1, raw).catch(() => {});
      } catch (err) {
        job.attempts = (job.attempts || 0) + 1;
        logger.warn('OTP email send failed', { to: job.to, attempt: job.attempts, err: err.message });
        await client.lrem(PROCESSING_KEY, 1, raw).catch(() => {});
        if (job.attempts < MAX_ATTEMPTS) {
          await client.lpush(OUTBOX_KEY, JSON.stringify(job));
        } else {
          logger.error('OTP email dropped after repeated failures', { to: job.to });
        }
      }
    }
  })().catch((err) => logger.error('mail worker loop stopped', { err: err.message }));
}
