import { Router } from 'express';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { config } from '../config.js';
import {
  findUserByEmail, createUser, touchLogin,
  otpGetRow, otpUpsert, otpBumpAttempts, otpDelete,
  pendingUpsert, pendingGet, pendingDelete, usernameTaken,
} from '../db.js';
import { enqueueOtpEmail } from '../mailer.js';
import { strictNormalizeEmail, validateUsername } from '../validators.js';
import { logger } from '../logger.js';
import { rateLimit } from '../middleware/rateLimit.js';

export const authRouter = Router();

const EMAIL_RE = /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,251}\.[A-Za-z]{2,15}$/;
const sha256hex = (s) => crypto.createHash('sha256').update(String(s), 'utf8').digest('hex');
// Timing-safe compare of two equal-length hex strings (digests).
const timingSafeEqualHex = (a, b) => {
  const ha = Buffer.from(String(a), 'utf8');
  const hb = Buffer.from(String(b), 'utf8');
  return ha.length === hb.length && crypto.timingSafeEqual(ha, hb);
};
const REG_TOKEN_TTL_SECONDS = 15 * 60;

// POST /api/auth/request-otp
authRouter.post('/request-otp', rateLimit({ windowMs: 60_000, max: 10, keyBy: 'ip' }), async (req, res, next) => {
  try {
    const rawEmail = String(req.body?.email ?? '');
    const email = strictNormalizeEmail(rawEmail);
    if (!EMAIL_RE.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
    const digest = sha256hex(email);

    const row = await otpGetRow(digest);
    if (row) {
      const elapsed = (Date.now() - new Date(row.last_request_at).getTime()) / 1000;
      if (elapsed < config.otpCooldownSeconds) {
        const wait = Math.ceil(config.otpCooldownSeconds - elapsed);
        return res.status(429).json({ error: `Code already sent — try again in ${wait} seconds` });
      }
    }

    const code = String(crypto.randomInt(0, 10 ** config.otpLength)).padStart(config.otpLength, '0');
    const codeHash = sha256hex(code);
    const expiresAt = new Date(Date.now() + config.otpTtlSeconds * 1000);
    await otpUpsert(digest, codeHash, expiresAt);

    try {
      // Non-blocking: email fisik dikirim oleh consumer outbox (mailer.startMailWorker).
      await enqueueOtpEmail(email, code, config.otpTtlSeconds);
    } catch (mailErr) {
      await otpDelete(digest);
      logger.warn('OTP scheduling rejected', { err: mailErr.message });
      return res.status(400).json({ error: 'Email not allowed' });
    }

    return res.json({
      ok: true,
      delivery: 'queued',
      ttlSeconds: config.otpTtlSeconds,
      cooldownSeconds: config.otpCooldownSeconds,
      hint: 'Check your email inbox — or the MailPit inbox at http://localhost:8025.',
    });
  } catch (err) { return next(err); }
});

// POST /api/auth/verify
// • email sudah terdaftar → langsung login (JWT sesi).
// • email baru       → akun BELUM dibuat; simpan pending registration dan
//   terbitkan regToken agar user memilih username unik (POST /auth/complete).
authRouter.post('/verify', rateLimit({ windowMs: 60_000, max: 20, keyBy: 'ip' }), async (req, res, next) => {
  try {
    const rawEmail = String(req.body?.email ?? '');
    const email = strictNormalizeEmail(rawEmail);
    const code = String(req.body?.code ?? '').trim();
    if (!EMAIL_RE.test(email)) return res.status(400).json({ error: 'Invalid email format' });
    if (!/^\d{4,8}$/.test(code)) return res.status(400).json({ error: 'Invalid code format' });
    const digest = sha256hex(email);

    const row = await otpGetRow(digest);
    if (!row) {
      return res.status(400).json({ error: 'Code not found or expired — request a new one' });
    }

    const attempts = await otpBumpAttempts(digest);
    if (attempts > config.otpMaxAttempts) {
      await otpDelete(digest);
      return res.status(429).json({ error: 'Too many wrong attempts — request a new code' });
    }

    if (!timingSafeEqualHex(row.code_hash, sha256hex(code))) {
      return res.status(400).json({ error: 'Wrong code' });
    }

    await otpDelete(digest);

    const existing = await findUserByEmail(email);
    if (existing) {
      const user = await touchLogin(existing.id);
      const token = jwt.sign({ sub: String(user.id) }, config.jwtSecret, { expiresIn: config.jwtTtl });
      logger.info('auth success', { isNewUser: false, userId: user.id });
      return res.json({
        token,
        isNewUser: false,
        user: { id: user.id, email: user.email, username: user.username },
      });
    }

    // email baru → pending registration menunggu username unik
    const regExpiresAt = new Date(Date.now() + REG_TOKEN_TTL_SECONDS * 1000);
    await pendingUpsert(digest, email, regExpiresAt);
    const regToken = jwt.sign(
      { sub: digest, typ: 'reg' },
      config.jwtSecret,
      { expiresIn: REG_TOKEN_TTL_SECONDS }
    );
    logger.info('pending registration created', { userId: null });
    return res.json({
      pending: true,
      regToken,
      next: 'username',
      ttlSeconds: REG_TOKEN_TTL_SECONDS,
    });
  } catch (err) { return next(err); }
});

// POST /api/auth/complete — finalisasi pendaftaran dengan username unik
authRouter.post('/complete', rateLimit({ windowMs: 60_000, max: 30, keyBy: 'ip' }), async (req, res, next) => {
  try {
    const header = String(req.headers.authorization || '');
    const match = header.match(/^Bearer\s+(.+)$/i);
    if (!match) return res.status(401).json({ error: 'Registration token missing' });

    let payload;
    try {
      payload = jwt.verify(match[1], config.jwtSecret);
    } catch {
      return res.status(401).json({ error: 'Registration session expired — please sign in again' });
    }
    if (payload?.typ !== 'reg' || typeof payload.sub !== 'string') {
      return res.status(403).json({ error: 'Invalid registration token' });
    }
    const digest = payload.sub;

    const v = validateUsername(req.body?.username);
    if (!v.ok) return res.status(400).json({ error: v.reason });

    const pending = await pendingGet(digest);
    if (!pending) {
      return res.status(400).json({ error: 'Registration session expired — please sign in again' });
    }

    if (await usernameTaken(v.username)) {
      return res.status(409).json({ error: 'Username already taken — pick another one' });
    }

    const user = await createUser(pending.email, v.username);
    await pendingDelete(digest);

    const token = jwt.sign({ sub: String(user.id) }, config.jwtSecret, { expiresIn: config.jwtTtl });
    logger.info('auth success', { isNewUser: true, userId: user.id });
    return res.json({
      token,
      isNewUser: true,
      user: { id: user.id, email: user.email, username: user.username },
    });
  } catch (err) { return next(err); }
});

// GET /api/auth/username-available?u= — cek ketersediaan username (publik, rate-limited)
authRouter.get('/username-available', rateLimit({ windowMs: 60_000, max: 60, keyBy: 'ip' }), async (req, res, next) => {
  try {
    const v = validateUsername(req.query?.u);
    if (!v.ok) return res.json({ available: false, reason: v.reason });
    const taken = await usernameTaken(v.username);
    return res.json({ available: !taken, reason: taken ? 'Username already taken' : null });
  } catch (err) { return next(err); }
});
