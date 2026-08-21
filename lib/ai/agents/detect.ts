import { asConfidence, asString, asStringList, runAgentJson, UNTRUSTED_DATA_GUARDRAIL } from "@/lib/ai/agents/shared";
import type { AgentRunMeta } from "@/lib/ai/types";
import type { SigmaRule, SocAlert, SocEvent } from "@/lib/types";

export type DetectAgentResult = {
  summary: string;
  confidence: number;
  signalIds: string[];
  attackChain: string[];
  correlations: string[];
  meta: AgentRunMeta;
};

type DetectInput = {
  alert: SocAlert;
  related: SocEvent[];
  matchedRules: SigmaRule[];
};

export function deterministicDetect(input: DetectInput, note?: string): DetectAgentResult {
  const sameHost = input.related.filter((event) => event.hostname && event.hostname === input.alert.hostname);
  const techniques = [...new Set([input.alert, ...sameHost].flatMap((event) => event.mitreTechniques))];
  return {
    summary: sameHost.length
      ? `Fused ${sameHost.length + 1} signals on ${input.alert.hostname ?? "an unknown host"}; ${techniques.length} ATT&CK techniques form the current attack chain.`
      : "No related retained signals were found; this alert remains a single-signal detection.",
    confidence: Math.min(0.99, input.alert.confidence + Math.min(0.15, sameHost.length * 0.03)),
    signalIds: [input.alert.id, ...sameHost.slice(0, 8).map((event) => event.id)],
    attackChain: techniques,
    correlations: sameHost.slice(0, 5).map((event) => `${event.title} on ${event.hostname ?? "unknown host"}`),
    meta: { engine: "deterministic", note },
  };
}

export async function runDetectAgent(tenantId: string, input: DetectInput): Promise<DetectAgentResult> {
  const fallback = deterministicDetect(input);
  const run = await runAgentJson(tenantId, "detect", [
    {
      role: "system",
      content:
        "You are Tawny-SOC Detect. Fuse related endpoint and identity signals into one concise attack chain. Cite only supplied signal IDs. " +
        UNTRUSTED_DATA_GUARDRAIL +
        ' Return JSON only: {"summary":string,"confidence":0-1,"signalIds":string[],"attackChain":string[],"correlations":string[]}.',
    },
    {
      role: "user",
      content: JSON.stringify({
        focusAlert: input.alert,
        relatedSignals: input.related.slice(0, 30),
        matchedRules: input.matchedRules.map((rule) => ({ id: rule.id, title: rule.title, mitreTechniques: rule.mitreTechniques })),
      }),
    },
  ]);
  if (!run) return deterministicDetect(input, "AI engine unavailable; deterministic signal fusion applied.");
  return {
    summary: asString(run.data.summary, fallback.summary),
    confidence: asConfidence(run.data.confidence, fallback.confidence),
    signalIds: asStringList(run.data.signalIds, fallback.signalIds).filter((id) => fallback.signalIds.includes(id)),
    attackChain: asStringList(run.data.attackChain, fallback.attackChain),
    correlations: asStringList(run.data.correlations, fallback.correlations),
    meta: run.meta,
  };
}
