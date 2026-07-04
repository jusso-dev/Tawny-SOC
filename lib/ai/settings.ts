import { getSocSettingRecord, recordAuditLog, saveSocSetting, type SocActor } from "@/lib/store";
import type { AiAgentId, AiProviderId, AiSettings, AiSettingsInput, AiSettingsView } from "@/lib/ai/types";

export const AI_SETTING_KEY = "ai";

export const aiAgentIds: AiAgentId[] = ["triage", "enrichment", "case-writer"];

export const aiAgentLabels: Record<AiAgentId, string> = {
  triage: "Triage agent",
  enrichment: "Threat intel enrichment agent",
  "case-writer": "Case writing agent",
};

export const aiSettingsDefaults: AiSettings = {
  enabled: false,
  provider: "azure-openai",
  azure: {
    endpoint: "",
    deployment: "",
    apiVersion: "2024-10-21",
    apiKey: "",
  },
  bedrock: {
    region: "ap-southeast-2",
    modelId: "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
    accessKeyId: "",
    secretAccessKey: "",
    sessionToken: "",
  },
  agents: { triage: true, enrichment: true, "case-writer": true },
};

export function parseAiProviderId(value: unknown): AiProviderId {
  return value === "aws-bedrock" ? "aws-bedrock" : "azure-openai";
}

function str(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value.trim() : fallback;
}

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

export function normalizeAiSettings(raw: Record<string, unknown>): AiSettings {
  const azure = record(raw.azure);
  const bedrock = record(raw.bedrock);
  const agents = record(raw.agents);
  return {
    enabled: raw.enabled === true,
    provider: parseAiProviderId(raw.provider),
    azure: {
      endpoint: str(azure.endpoint),
      deployment: str(azure.deployment),
      apiVersion: str(azure.apiVersion) || aiSettingsDefaults.azure.apiVersion,
      apiKey: str(azure.apiKey),
    },
    bedrock: {
      region: str(bedrock.region) || aiSettingsDefaults.bedrock.region,
      modelId: str(bedrock.modelId) || aiSettingsDefaults.bedrock.modelId,
      accessKeyId: str(bedrock.accessKeyId),
      secretAccessKey: str(bedrock.secretAccessKey),
      sessionToken: str(bedrock.sessionToken),
    },
    agents: {
      triage: agents.triage !== false,
      enrichment: agents.enrichment !== false,
      "case-writer": agents["case-writer"] !== false,
    },
  };
}

export function redactAiSettings(settings: AiSettings): AiSettingsView {
  const { azure, bedrock, ...rest } = settings;
  const { apiKey, ...azureRest } = azure;
  const { secretAccessKey, sessionToken, ...bedrockRest } = bedrock;
  void sessionToken;
  return {
    ...rest,
    azure: { ...azureRest, apiKeyConfigured: apiKey.length > 0 },
    bedrock: { ...bedrockRest, secretConfigured: secretAccessKey.length > 0 },
  };
}

export async function getAiSettings(tenantId: string): Promise<AiSettings> {
  return normalizeAiSettings(await getSocSettingRecord(tenantId, AI_SETTING_KEY));
}

/**
 * Merge form input over stored settings. Blank secrets keep the stored value,
 * matching the integration-channel credential convention.
 */
export function mergeAiSettings(existing: AiSettings, input: AiSettingsInput): AiSettings {
  return {
    enabled: input.enabled,
    provider: input.provider,
    azure: {
      endpoint: str(input.azure.endpoint),
      deployment: str(input.azure.deployment),
      apiVersion: str(input.azure.apiVersion) || aiSettingsDefaults.azure.apiVersion,
      apiKey: str(input.azure.apiKey) || existing.azure.apiKey,
    },
    bedrock: {
      region: str(input.bedrock.region) || aiSettingsDefaults.bedrock.region,
      modelId: str(input.bedrock.modelId) || aiSettingsDefaults.bedrock.modelId,
      accessKeyId: str(input.bedrock.accessKeyId),
      secretAccessKey: str(input.bedrock.secretAccessKey) || existing.bedrock.secretAccessKey,
      sessionToken: str(input.bedrock.sessionToken) || existing.bedrock.sessionToken,
    },
    agents: {
      triage: input.agents.triage !== false,
      enrichment: input.agents.enrichment !== false,
      "case-writer": input.agents["case-writer"] !== false,
    },
  };
}

export async function saveAiSettings(tenantId: string, input: AiSettingsInput, actor?: SocActor): Promise<AiSettings> {
  const merged = mergeAiSettings(await getAiSettings(tenantId), input);
  await saveSocSetting(tenantId, AI_SETTING_KEY, merged as unknown as Record<string, unknown>);
  await recordAuditLog({
    tenantId,
    actor,
    action: "ai.settings.update",
    resourceType: "ai-engine",
    resourceId: merged.provider,
    detail: `AI engine ${merged.enabled ? "enabled" : "disabled"} on ${merged.provider}.`,
  }).catch(() => undefined);
  return merged;
}
