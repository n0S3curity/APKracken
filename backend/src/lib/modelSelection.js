import { prisma } from '../db.js';
import { modelCatalogEntry } from './modelCatalog.js';
import { isModelProviderConfigured } from './modelProviders.js';
import { ValidationError } from './validation.js';

async function findCatalog(provider) {
  return prisma.modelCatalog.findUnique({ where: { provider } });
}

export async function assertModelSelectionAvailable(
  { modelProvider, model, thinkingEffort },
  { providerConfigured = isModelProviderConfigured, getCatalog = findCatalog } = {}
) {
  if (!(await providerConfigured(modelProvider))) {
    throw new ValidationError([{ field: 'model_provider', message: 'The selected model provider is not configured.' }]);
  }

  // OpenRouter accepts free-text model IDs; the local provider has a fixed
  // single-model catalog with no thinking-effort control — nothing to validate.
  if (modelProvider === 'openrouter' || modelProvider === 'local') return;

  const catalog = modelCatalogEntry(modelProvider, await getCatalog(modelProvider));
  if (catalog.status !== 'ready') {
    throw new ValidationError([
      { field: 'model', message: `The ${modelProvider} model catalog is not available yet.` },
    ]);
  }

  const selectedModel = catalog.models.find((candidate) => candidate.id === model);
  if (!selectedModel) {
    throw new ValidationError([
      { field: 'model', message: `Model "${model}" is not available for provider "${modelProvider}".` },
    ]);
  }

  if (thinkingEffort && !selectedModel.thinkingEfforts.includes(thinkingEffort)) {
    throw new ValidationError([
      {
        field: 'thinking_effort',
        message: `Thinking effort "${thinkingEffort}" is not available for model "${model}".`,
      },
    ]);
  }
}
