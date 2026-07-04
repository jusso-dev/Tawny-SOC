import type { AiProvider, AzureOpenAiConfig } from "@/lib/ai/types";

type AzureChatResponse = {
  model?: string;
  choices?: Array<{ message?: { content?: string | null } }>;
  usage?: { prompt_tokens?: number; completion_tokens?: number };
};

export function createAzureOpenAiProvider(config: AzureOpenAiConfig, timeoutMs = 60_000): AiProvider {
  return {
    id: "azure-openai",
    label: "Azure OpenAI",
    async complete(request) {
      if (!config.endpoint || !config.deployment) throw new Error("Azure OpenAI endpoint and deployment are required.");
      if (!config.apiKey) throw new Error("Azure OpenAI API key is not configured.");

      const url = `${config.endpoint.replace(/\/+$/, "")}/openai/deployments/${encodeURIComponent(config.deployment)}/chat/completions?api-version=${encodeURIComponent(config.apiVersion)}`;
      const started = Date.now();
      const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", "api-key": config.apiKey },
        body: JSON.stringify({
          messages: request.messages,
          max_completion_tokens: request.maxTokens ?? 1024,
          ...(request.temperature !== undefined ? { temperature: request.temperature } : {}),
          ...(request.jsonResponse ? { response_format: { type: "json_object" } } : {}),
        }),
        signal: AbortSignal.timeout(timeoutMs),
      });

      if (!res.ok) {
        const detail = await res.text().catch(() => "");
        throw new Error(`Azure OpenAI returned HTTP ${res.status}${detail ? `: ${detail.slice(0, 300)}` : ""}`);
      }

      const body = await res.json() as AzureChatResponse;
      const text = body.choices?.[0]?.message?.content ?? "";
      if (!text) throw new Error("Azure OpenAI returned an empty completion.");

      return {
        text,
        provider: "azure-openai" as const,
        model: body.model ?? config.deployment,
        inputTokens: body.usage?.prompt_tokens,
        outputTokens: body.usage?.completion_tokens,
        latencyMs: Date.now() - started,
      };
    },
  };
}
