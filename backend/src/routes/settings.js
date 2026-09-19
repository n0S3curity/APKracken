import { Router } from 'express';

import { readRuntimeSettings, updateRuntimeSettings } from '../lib/runtimeSettings.js';

const router = Router();

router.get('/', async (req, res, next) => {
  try {
    res.json(await readRuntimeSettings());
  } catch (error) {
    next(error);
  }
});

router.patch('/', async (req, res, next) => {
  try {
    res.json(await updateRuntimeSettings(req.body));
  } catch (error) {
    next(error);
  }
});

export default router;
