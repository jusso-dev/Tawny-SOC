import { afterEach, describe, expect, it, vi } from "vitest";
import { resolveAiProvider } from "../lib/ai";
import { buildCaseWriterPrompt, deterministicCaseDraft, runCaseWriterAgent } from "../lib/ai/agents/case-writer";
import { deterministicEnrichment } from "../lib/ai/agents/enrichment";
import { extractJsonObject, UNTRUSTED_DATA_GUARDRAIL } from "../lib/ai/agents/shared";
import { buildTriagePrompt, deterministicTriage, runTriageAgent } from "../lib/ai/agents/triage";
import { createAzureOpenAiProvider } from "../lib/ai/providers/azure-openai";
import { createBedrockProvider, rfc3986Encode, signAwsRequest } from "../lib/ai/providers/bedrock";
import { aiSettingsDefaults, mergeAiSettings, normalizeAiSettings, redactAiSettings } from "../lib/ai/settings";
import type { AiSettings } from "../lib/ai/types";
import type { Playbook, SocAlert, ThreatIntelMatch } from "../lib/types";

const alert: SocAlert = {
  id: "alert-1",
  source: "tawny",
  kind: "alert",
  title: "Encoded PowerShell command",
  severity: "high",
  status: "open",
  timestamp: "2026-07-01T00:00:00.000Z",
  tenantId: "tenant-a",
  hostname: "win-lab-01",
  payload: { alert: { command_line: "powershell -enc AAAA" } },
  matchedRules: ["tawny-sigma-ps-encoded-command"],
  mitreTechniques: ["T1059.001"],
  confidence: 0.81,
  aiSummary: "Encoded PowerShell command on win-lab-01.",
  recommendedPlaybook: "incident-response",
  tiMatches: [],
};

const playbooks: Playbook[] = [
  { id: "incident-response", name: "Incident response", description: "", severity: "high", agents: [], triggers: [], phases: [] },
  { id: "threat-hunt", name: "Threat hunt", description: "", severity: "low", agents: [], triggers: [], phases: [] },
];

const indicator: ThreatIntelMatch = {
  id: "ioc-1",
  type: "ip",
  value: "203.0.113.7",
  sourceFeed: "URLhaus",
  confidence: 88,
  tags: ["c2"],
  firstSeen: "2026-06-01T00:00:00.000Z",
  lastSeen: "2026-07-01T00:00:00.000Z",
};

function configuredSettings(provider: AiSettings["provider"]): AiSettings {
  return {
    ...aiSettingsDefaults,
    enabled: true,
    provider,
    azure: { endpoint: "https://soc.openai.azure.com", deployment: "gpt-4o", apiVersion: "2024-10-21", apiKey: "azure-key" },
    bedrock: { region: "ap-southeast-2", modelId: "us.anthropic.claude-sonnet-4-5-20250929-v1:0", accessKeyId: "AKIDEXAMPLE", secretAccessKey: "bedrock-secret-value", sessionToken: "" },
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("extractJsonObject", () => {
  it("parses a bare JSON object", () => {
    expect(extractJsonObject('{"verdict":"escalate"}')).toEqual({ verdict: "escalate" });
  });

  it("parses fenced JSON with surrounding prose", () => {
    const text = 'Here you go:\n```json\n{"summary":"ok"}\n```\nDone.';
    expect(extractJsonObject(text)).toEqual({ summary: "ok" });
  });

  it("parses JSON embedded in prose without fences", () => {
    expect(extractJsonObject('The result is {"a":1} as requested.')).toEqual({ a: 1 });
  });

  it("rejects responses without a JSON object", () => {
    expect(() => extractJsonObject("no json here")).toThrow();
  });
});

describe("AI settings", () => {
  it("normalizes empty records to safe defaults", () => {
    const settings = normalizeAiSettings({});
    expect(settings.enabled).toBe(false);
    expect(settings.provider).toBe("azure-openai");
    expect(settings.agents).toEqual({ triage: true, enrichment: true, "case-writer": true });
  });

  it("redacts secrets and reports configured state", () => {
    const view = redactAiSettings(configuredSettings("azure-openai"));
    expect(JSON.stringify(view)).not.toContain("azure-key");
    expect(JSON.stringify(view)).not.toContain("bedrock-secret-value");
    expect(view.azure.apiKeyConfigured).toBe(true);
    expect(view.bedrock.secretConfigured).toBe(true);
  });

  it("keeps stored secrets when input secrets are blank", () => {
    const existing = configuredSettings("azure-openai");
    const merged = mergeAiSettings(existing, {
      enabled: true,
      provider: "aws-bedrock",
      azure: { endpoint: existing.azure.endpoint, deployment: existing.azure.deployment, apiVersion: "", apiKey: "" },
      bedrock: { region: "us-east-1", modelId: "amazon.nova-pro-v1:0", accessKeyId: "AKIDNEW", secretAccessKey: "", sessionToken: "" },
      agents: {},
    });
    expect(merged.provider).toBe("aws-bedrock");
    expect(merged.azure.apiKey).toBe("azure-key");
    expect(merged.bedrock.secretAccessKey).toBe("bedrock-secret-value");
    expect(merged.bedrock.modelId).toBe("amazon.nova-pro-v1:0");
  });

  it("hot-swaps the provider from settings", () => {
    expect(resolveAiProvider(configuredSettings("azure-openai")).id).toBe("azure-openai");
    expect(resolveAiProvider(configuredSettings("aws-bedrock")).id).toBe("aws-bedrock");
  });
});

describe("AWS SigV4 signer", () => {
  it("matches the AWS documentation reference signature", () => {
    const headers = signAwsRequest({
      method: "GET",
      host: "iam.amazonaws.com",
      canonicalUri: "/",
      canonicalQuery: "Action=ListUsers&Version=2010-05-08",
      headers: { "content-type": "application/x-www-form-urlencoded; charset=utf-8" },
      payload: "",
      region: "us-east-1",
      service: "iam",
      accessKeyId: "AKIDEXAMPLE",
      secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
      date: new Date("2015-08-30T12:36:00.000Z"),
    });
    expect(headers.authorization).toBe(
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, " +
      "SignedHeaders=content-type;host;x-amz-date, " +
      "Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7",
    );
  });

  it("adds the security token header for temporary credentials", () => {
    const headers = signAwsRequest({
      method: "POST",
      host: "bedrock-runtime.us-east-1.amazonaws.com",
      canonicalUri: "/model/test/converse",
      canonicalQuery: "",
      headers: { "content-type": "application/json" },
      payload: "{}",
      region: "us-east-1",
      service: "bedrock",
      accessKeyId: "AKIDEXAMPLE",
      secretAccessKey: "secret",
      sessionToken: "token-123",
      date: new Date("2026-07-04T00:00:00.000Z"),
    });
    expect(headers["x-amz-security-token"]).toBe("token-123");
    expect(headers.authorization).toContain("x-amz-security-token");
  });

  it("percent-encodes model id characters for the request path", () => {
    expect(rfc3986Encode("us.anthropic.claude-sonnet-4-5-20250929-v1:0")).toBe("us.anthropic.claude-sonnet-4-5-20250929-v1%3A0");
  });
});

describe("Azure OpenAI provider", () => {
  it("calls the deployment endpoint and parses the completion", async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({
      model: "gpt-4o",
      choices: [{ message: { content: '{"ok":true}' } }],
      usage: { prompt_tokens: 100, completion_tokens: 20 },
    }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    const provider = createAzureOpenAiProvider(configuredSettings("azure-openai").azure);
    const result = await provider.complete({ messages: [{ role: "user", content: "hi" }], jsonResponse: true });

    expect(result.text).toBe('{"ok":true}');
    expect(result.model).toBe("gpt-4o");
    expect(result.outputTokens).toBe(20);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://soc.openai.azure.com/openai/deployments/gpt-4o/chat/completions?api-version=2024-10-21");
    expect((init.headers as Record<string, string>)["api-key"]).toBe("azure-key");
    expect(JSON.parse(String(init.body)).response_format).toEqual({ type: "json_object" });
  });

  it("fails clearly when the key is missing", async () => {
    const provider = createAzureOpenAiProvider({ endpoint: "https://x", deployment: "d", apiVersion: "2024-10-21", apiKey: "" });
    await expect(provider.complete({ messages: [{ role: "user", content: "hi" }] })).rejects.toThrow(/API key/);
  });
});

describe("AWS Bedrock provider", () => {
  it("signs the Converse call and parses the completion", async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({
      output: { message: { content: [{ text: '{"ok":true}' }] } },
      usage: { inputTokens: 90, outputTokens: 15 },
    }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    const provider = createBedrockProvider(configuredSettings("aws-bedrock").bedrock);
    const result = await provider.complete({
      messages: [
        { role: "system", content: "system prompt" },
        { role: "user", content: "hi" },
      ],
    });

    expect(result.text).toBe('{"ok":true}');
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://bedrock-runtime.ap-southeast-2.amazonaws.com/model/us.anthropic.claude-sonnet-4-5-20250929-v1%3A0/converse");
    const headers = init.headers as Record<string, string>;
    expect(headers.authorization).toMatch(/^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\//);
    const body = JSON.parse(String(init.body));
    expect(body.system).toEqual([{ text: "system prompt" }]);
    expect(body.messages).toEqual([{ role: "user", content: [{ text: "hi" }] }]);
  });

  it("fails clearly when credentials are missing", async () => {
    const provider = createBedrockProvider({ region: "us-east-1", modelId: "m", accessKeyId: "", secretAccessKey: "", sessionToken: "" });
    await expect(provider.complete({ messages: [{ role: "user", content: "hi" }] })).rejects.toThrow(/credentials/);
  });
});

describe("agent prompts", () => {
  it("carries the untrusted-data guardrail in every agent prompt", () => {
    const triage = buildTriagePrompt({ alert, matchedRules: [], playbooks });
    const caseDraft = buildCaseWriterPrompt({
      incident: {
        id: "inc-1", tenantId: "tenant-a", number: "SOC-1", title: "Case", severity: "high", priority: "P2",
        status: "open", tags: [], tlp: "amber", pap: "amber", classification: "undetermined", mitreTechniques: [],
        observables: [], linkedHosts: [], linkedAlertIds: [], kelpieSyncStatus: "not_synced",
        createdAt: "2026-07-01T00:00:00.000Z", updatedAt: "2026-07-01T00:00:00.000Z", timeline: [], tasks: [], comments: [],
      },
      linkedAlerts: [alert],
    });
    expect(triage[0].content).toContain(UNTRUSTED_DATA_GUARDRAIL);
    expect(caseDraft[0].content).toContain(UNTRUSTED_DATA_GUARDRAIL);
  });
});

describe("deterministic fallbacks", () => {
  it("escalates high severity alerts without AI", () => {
    const result = deterministicTriage({ alert, matchedRules: [], playbooks });
    expect(result.verdict).toBe("escalate");
    expect(result.meta.engine).toBe("deterministic");
  });

  it("summarizes threat intel matches and builds hunt pivots without AI", () => {
    const result = deterministicEnrichment({ alert, indicators: [indicator] });
    expect(result.indicators[0].risk).toBe("high");
    expect(result.huntQueries).toContain("host:win-lab-01");
    expect(result.huntQueries).toContain("ip:203.0.113.7");
  });

  it("falls back to deterministic triage when AI is disabled", async () => {
    // No tenant AI settings exist in the test environment, so the agent
    // must degrade to the deterministic path without any network calls.
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const result = await runTriageAgent("tenant-a", { alert, matchedRules: [], playbooks });
    expect(result.meta.engine).toBe("deterministic");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("falls back to a deterministic case draft when AI is disabled", async () => {
    const input = {
      incident: {
        id: "inc-1", tenantId: "tenant-a", number: "SOC-7", title: "Credential theft", severity: "critical" as const,
        priority: "P1" as const, status: "investigating" as const, tags: [], tlp: "amber" as const, pap: "amber" as const,
        classification: "true_positive" as const, mitreTechniques: ["T1003"], observables: [], linkedHosts: ["win-lab-01"],
        linkedAlertIds: ["alert-1"], kelpieSyncStatus: "not_synced" as const, createdAt: "2026-07-01T00:00:00.000Z",
        updatedAt: "2026-07-01T00:00:00.000Z", timeline: [], tasks: [], comments: [],
      },
      linkedAlerts: [alert],
    };
    const result = await runCaseWriterAgent("tenant-a", input);
    expect(result.meta.engine).toBe("deterministic");
    expect(result).toMatchObject(deterministicCaseDraft(input, "AI engine unavailable; deterministic draft applied."));
  });
});
