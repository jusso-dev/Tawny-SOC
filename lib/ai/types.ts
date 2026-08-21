export type AiProviderId = "azure-openai" | "aws-bedrock";

export type AiAgentId = "detect" | "triage" | "hunt" | "respond";

export type AzureOpenAiConfig = {
  endpoint: string;
  deployment: string;
  apiVersion: string;
  apiKey: string;
};

export type BedrockConfig = {
  region: string;
  modelId: string;
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
};

export type AiSettings = {
  enabled: boolean;
  provider: AiProviderId;
  azure: AzureOpenAiConfig;
  bedrock: BedrockConfig;
  agents: Record<AiAgentId, boolean>;
};

export type AiSettingsView = Omit<AiSettings, "azure" | "bedrock"> & {
  azure: Omit<AzureOpenAiConfig, "apiKey"> & { apiKeyConfigured: boolean };
  bedrock: Omit<BedrockConfig, "secretAccessKey" | "sessionToken"> & { secretConfigured: boolean };
};

export type AiSettingsInput = {
  enabled: boolean;
  provider: AiProviderId;
  azure: Partial<AzureOpenAiConfig>;
  bedrock: Partial<BedrockConfig>;
  agents: Partial<Record<AiAgentId, boolean>>;
};

export type AiChatMessage = {
  role: "system" | "user" | "assistant";
  content: string;
};

export type AiCompletionRequest = {
  messages: AiChatMessage[];
  maxTokens?: number;
  temperature?: number;
  jsonResponse?: boolean;
};

export type AiCompletionResult = {
  text: string;
  provider: AiProviderId;
  model: string;
  inputTokens?: number;
  outputTokens?: number;
  latencyMs: number;
};

export type AiProvider = {
  id: AiProviderId;
  label: string;
  complete: (request: AiCompletionRequest) => Promise<AiCompletionResult>;
};

export type AgentRunMeta = {
  engine: "ai" | "deterministic";
  provider?: AiProviderId;
  model?: string;
  latencyMs?: number;
  note?: string;
};
