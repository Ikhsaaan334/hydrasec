import jwt from 'jsonwebtoken';
import { config } from '../config.js';

export function authRequired(req, res, next) {
  const header = String(req.headers.authorization || '');
  const match = header.match(/^Bearer\s+(.+)$/i);
  const token = match ? match[1] : null;
  if (!token) return res.status(401).json({ error: 'Token missing' });
  try {
    const payload = jwt.verify(token, config.jwtSecret);
    if (!payload?.sub) throw new Error('payload tanpa sub');
    req.user = { id: Number(payload.sub), email: String(payload.email || '') };
    return next();
  } catch {
    return res.status(401).json({ error: 'Token invalid or expired' });
  }
}
