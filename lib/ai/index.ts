import { createAzureOpenAiProvider } from "@/lib/ai/providers/azure-openai";
import { createBedrockProvider } from "@/lib/ai/providers/bedrock";
import { getAiSettings, mergeAiSettings } from "@/lib/ai/settings";
import type { AiCompletionRequest, AiCompletionResult, AiProvider, AiSettings, AiSettingsInput } from "@/lib/ai/types";

export { aiAgentIds, aiAgentLabels, getAiSettings, redactAiSettings, saveAiSettings } from "@/lib/ai/settings";
export type { AiAgentId, AiProviderId, AiSettings, AiSettingsInput, AiSettingsView } from "@/lib/ai/types";

/** Hot-swap point: the tenant's saved provider decides which engine drives every agent. */
export function resolveAiProvider(settings: AiSettings): AiProvider {
  return settings.provider === "aws-bedrock"
    ? createBedrockProvider(settings.bedrock)
    : createAzureOpenAiProvider(settings.azure);
}

export async function completeWithTenantAi(tenantId: string, request: AiCompletionRequest): Promise<AiCompletionResult> {
  const settings = await getAiSettings(tenantId);
  if (!settings.enabled) throw new Error("AI engine is disabled for this tenant.");
  return resolveAiProvider(settings).complete(request);
}

/**
 * Test the connection with unsaved form values merged over stored settings,
 * so analysts can validate credentials before saving.
 */
export async function testAiConnection(tenantId: string, input: AiSettingsInput): Promise<{ provider: string; model: string; latencyMs: number }> {
  const merged = mergeAiSettings(await getAiSettings(tenantId), input);
  const provider = resolveAiProvider(merged);
  const result = await provider.complete({
    messages: [
      { role: "system", content: "You are the Tawny-SOC AI engine connectivity check." },
      { role: "user", content: "Reply with the single word: ready" },
    ],
    maxTokens: 20,
  });
  return { provider: provider.label, model: result.model, latencyMs: result.latencyMs };
}
