import fs from 'node:fs';
import { prisma } from '../db.js';
import { STEP_RESULTS_TABLE, VULNERABILITIES_TABLE } from './constants.js';

export const DEFAULT_WORKFLOWS = JSON.parse(
  fs.readFileSync(new URL('./defaultWorkflowSeeds.json', import.meta.url), 'utf8')
);

export const DEFAULT_WORKFLOW_NAMES = DEFAULT_WORKFLOWS.map((workflow) => workflow.name);

export function isDefaultWorkflowName(name) {
  return DEFAULT_WORKFLOW_NAMES.includes(name);
}

// The ordered step definitions of a seed, flattened the same way they are created below so
// an existing workflow's stepIds line up positionally with the seed.
function seedSteps(workflow) {
  const maxDepth = Math.max(...workflow.levels.map((l) => l.depth));
  const out = [];
  for (const level of workflow.levels) {
    const isLastStep = level.isLastStep ?? level.depth === maxDepth;
    for (const step of level.steps) {
      out.push({
        content: step.content,
        outputFormat: JSON.stringify(level.outputFormat),
        name: step.name,
        depth: level.depth,
        multiOutput: level.multiOutput,
        consumesAll: level.consumeAll ?? false,
        isLastStep,
        outputTable: level.outputTable || (isLastStep ? VULNERABILITIES_TABLE : STEP_RESULTS_TABLE),
      });
    }
  }
  return out;
}

async function refreshSeededSteps(tx, workflow, stepIds) {
  const steps = seedSteps(workflow);
  if (steps.length !== stepIds.length) return; // shape changed; leave it to a fresh seed
  for (let i = 0; i < steps.length; i += 1) {
    await tx.step.update({ where: { id: stepIds[i] }, data: steps[i] });
  }
}

export async function ensureDefaultWorkflows(client = prisma) {
  return client.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext('open-kritt-default-workflows'))`;

    const installed = [];
    for (const workflow of DEFAULT_WORKFLOWS) {
      const existing = await tx.workflow.findFirst({
        where: { name: workflow.name },
        orderBy: { insertedAt: 'asc' },
        select: { id: true, stepIds: true },
      });
      if (existing?.stepIds?.length) {
        const stepCount = await tx.step.count({ where: { id: { in: existing.stepIds } } });
        if (stepCount === existing.stepIds.length) {
          // Refresh the seeded steps in place instead of leaving an older build's copy alone.
          // The prompt and output schema are the accuracy contract — the engine grounds
          // code_evidence against the snapshot and gates false-positive checks on
          // severity_score — so a stale seed silently disables that machinery.
          await refreshSeededSteps(tx, workflow, existing.stepIds);
          continue;
        }
      }

      const stepIds = [];
      for (const level of workflow.levels) {
        const maxDepth = Math.max(...workflow.levels.map((l) => l.depth));
        const isLastStep = level.isLastStep ?? level.depth === maxDepth;
        for (const step of level.steps) {
          const created = await tx.step.create({
            data: {
              content: step.content,
              outputFormat: JSON.stringify(level.outputFormat),
              name: step.name,
              depth: level.depth,
              multiOutput: level.multiOutput,
              consumesAll: level.consumeAll ?? false,
              isLastStep,
              outputTable: level.outputTable || (isLastStep ? VULNERABILITIES_TABLE : STEP_RESULTS_TABLE),
            },
          });
          stepIds.push(created.id);
        }
      }

      const data = { name: workflow.name, description: workflow.description, stepIds, extra: workflow.extra || [] };
      const saved = existing
        ? await tx.workflow.update({ where: { id: existing.id }, data })
        : await tx.workflow.create({ data });
      installed.push(saved.name);
    }

    return installed;
  });
}
