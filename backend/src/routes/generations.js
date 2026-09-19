import { Router } from 'express';

import { prisma } from '../db.js';
import { assertModelSelectionAvailable } from '../lib/modelSelection.js';
import { serializeGeneration } from '../lib/serialize.js';
import { validateGeneration } from '../lib/validation.js';

export function createGenerationsRouter({
  prismaClient = prisma,
  ensureModelSelection = assertModelSelectionAvailable,
} = {}) {
  const router = Router();

  // POST /api/generations - enqueue a natural-language draft request.
  router.post('/', async (req, res, next) => {
    try {
      const valid = validateGeneration(req.body);
      await ensureModelSelection(valid);
      const generation = await prismaClient.generation.create({
        data: {
          kind: valid.kind,
          request: valid.request,
          model: valid.model,
          modelProvider: valid.modelProvider,
          harness: valid.harness,
          thinkingEffort: valid.thinkingEffort,
          status: 'pending',
        },
      });
      res.set('Cache-Control', 'no-store').status(202).json(serializeGeneration(generation));
    } catch (error) {
      next(error);
    }
  });

  // GET /api/generations/:id - poll engine-owned execution state and a validated draft.
  router.get('/:id', async (req, res, next) => {
    try {
      const generation = await prismaClient.generation.findUnique({ where: { id: BigInt(req.params.id) } });
      if (!generation) return res.status(404).json({ error: 'Generation not found.' });
      res.set('Cache-Control', 'no-store').json(serializeGeneration(generation));
    } catch (error) {
      next(error);
    }
  });

  return router;
}

export default createGenerationsRouter();
