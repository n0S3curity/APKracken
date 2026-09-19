import { Router } from 'express';

import { configuredModelProviders } from '../lib/modelProviders.js';

const router = Router();

// GET /api/model-providers — provider IDs with usable credentials only.
router.get('/', async (req, res, next) => {
  try {
    res.json({ providers: await configuredModelProviders() });
  } catch (e) {
    next(e);
  }
});

export default router;
