// Rate limiter fixed-window sederhana di memori (cukup untuk deploy lokal single-instance)
const buckets = new Map();

function keyOf(req, keyBy) {
  if (keyBy === 'email' && typeof req.body?.email === 'string') return `email:${req.body.email.toLowerCase()}`;
  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket?.remoteAddress || '?';
  return `ip:${ip}`;
}

export function rateLimit({ windowMs = 60_000, max = 120, keyBy = 'ip' } = {}) {
  return (req, res, next) => {
    const now = Date.now();
    const key = `${keyOf(req, keyBy)}:${Math.floor(now / windowMs)}`;
    const entry = buckets.get(key) ?? { count: 0 };
    entry.count += 1;
    buckets.set(key, entry);
    if (buckets.size > 10_000) {
      for (const k of buckets.keys()) { buckets.delete(k); break; }
    }
    const remaining = Math.max(0, max - entry.count);
    res.setHeader('X-RateLimit-Limit', String(max));
    res.setHeader('X-RateLimit-Remaining', String(remaining));
    if (entry.count > max) {
      return res.status(429).json({ error: 'Too many requests — try again shortly' });
    }
    return next();
  };
}
