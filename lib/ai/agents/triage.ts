import { asConfidence, asString, asStringList, runAgentJson, UNTRUSTED_DATA_GUARDRAIL } from "@/lib/ai/agents/shared";
import type { AgentRunMeta } from "@/lib/ai/types";
import type { Playbook, SigmaRule, SocAlert } from "@/lib/types";

export type TriageVerdict = "escalate" | "investigate" | "monitor" | "likely_benign";

export type TriageAgentResult = {
  verdict: TriageVerdict;
  confidence: number;
  summary: string;
  rationale: string[];
  recommendedActions: string[];
  suggestedPlaybook: string;
  mitreTechniques: string[];
  meta: AgentRunMeta;
};

export type TriageAgentInput = {
  alert: SocAlert;
  matchedRules: SigmaRule[];
  playbooks: Playbook[];
};

const verdicts: TriageVerdict[] = ["escalate", "investigate", "monitor", "likely_benign"];

function parseVerdict(value: unknown, fallback: TriageVerdict): TriageVerdict {
  return verdicts.includes(value as TriageVerdict) ? value as TriageVerdict : fallback;
}

export function buildTriagePrompt(input: TriageAgentInput) {
  const { alert, matchedRules, playbooks } = input;
  const context = {
    alert: {
      title: alert.title,
      severity: alert.severity,
      status: alert.status,
      confidence: alert.confidence,
      host: alert.hostname ?? null,
      user: alert.user ?? null,
      process: alert.process ?? null,
      commandLine: alert.commandLine || null,
      externalIps: alert.externalIps ?? [],
      eventType: alert.eventType ?? null,
      mitreTechniques: alert.mitreTechniques,
      timestamp: alert.timestamp,
      payload: alert.payload,
    },
    matchedDetections: matchedRules.map((rule) => ({
      id: rule.id,
      title: rule.title,
      severity: rule.severity,
      description: rule.description,
      falsePositives: rule.falsePositives,
      mitreTechniques: rule.mitreTechniques,
    })),
    threatIntelMatches: (alert.tiMatches ?? []).map((ioc) => ({
      type: ioc.type,
      value: ioc.value,
      sourceFeed: ioc.sourceFeed,
      confidence: ioc.confidence,
      tags: ioc.tags,
    })),
    availablePlaybooks: playbooks.map((playbook) => ({ id: playbook.id, name: playbook.name, severity: playbook.severity })),
  };

  return [
    {
      role: "system" as const,
      content:
        "You are the Tier-1 triage agent inside Tawny-SOC. Assess the alert like a senior SOC analyst: weigh the detection " +
        "quality, false-positive notes, host/user/process context, and threat intel hits. Be decisive and concrete. " +
        UNTRUSTED_DATA_GUARDRAIL +
        ' Respond with a single JSON object only: {"verdict": "escalate"|"investigate"|"monitor"|"likely_benign", ' +
        '"confidence": 0-1, "summary": string (2-3 sentences), "rationale": string[], "recommendedActions": string[] (3-5 concrete analyst steps), ' +
        '"suggestedPlaybook": string (one of the available playbook ids), "mitreTechniques": string[]}',
    },
    { role: "user" as const, content: JSON.stringify(context) },
  ];
}

export function deterministicTriage(input: TriageAgentInput, note?: string): TriageAgentResult {
  const { alert, matchedRules } = input;
  const highSeverity = alert.severity === "critical" || alert.severity === "high";
  return {
    verdict: highSeverity ? "escalate" : matchedRules.length ? "investigate" : "monitor",
    confidence: alert.confidence,
    summary: alert.aiSummary,
    rationale: matchedRules.map((rule) => `Matched ${rule.title} (${rule.severity}).`),
    recommendedActions: [
      "Pivot on host and telemetry ID in Tawny",
      "Review matching Sigma source and false-positive notes",
      "Run the recommended playbook before containment",
    ],
    suggestedPlaybook: alert.recommendedPlaybook,
    mitreTechniques: alert.mitreTechniques,
    meta: { engine: "deterministic", note },
  };
}

export async function runTriageAgent(tenantId: string, input: TriageAgentInput): Promise<TriageAgentResult> {
  const run = await runAgentJson(tenantId, "triage", buildTriagePrompt(input));
  if (!run) return deterministicTriage(input, "AI engine unavailable; deterministic triage applied.");

  const fallback = deterministicTriage(input);
  const playbookIds = new Set(input.playbooks.map((playbook) => playbook.id));
  const suggested = asString(run.data.suggestedPlaybook, fallback.suggestedPlaybook);
  return {
    verdict: parseVerdict(run.data.verdict, fallback.verdict),
    confidence: asConfidence(run.data.confidence, fallback.confidence),
    summary: asString(run.data.summary, fallback.summary),
    rationale: asStringList(run.data.rationale, fallback.rationale),
    recommendedActions: asStringList(run.data.recommendedActions, fallback.recommendedActions),
    suggestedPlaybook: playbookIds.has(suggested) ? suggested : fallback.suggestedPlaybook,
    mitreTechniques: asStringList(run.data.mitreTechniques, fallback.mitreTechniques),
    meta: run.meta,
  };
}
