import { Router } from 'express';
import { authRequired } from '../middleware/auth.js';
import { globalStats, userStats, leaderboard } from '../db.js';

export const statsRouter = Router();

statsRouter.use(authRequired);

// GET /api/stats — agregat global (semua user) + milik sendiri + leaderboard
statsRouter.get('/', async (req, res, next) => {
  try {
    const [global, mine, board] = await Promise.all([
      globalStats(),
      userStats(req.user.id),
      leaderboard(10),
    ]);
    return res.json({ global, me: mine, leaderboard: board });
  } catch (err) { return next(err); }
});
