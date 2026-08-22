import { asConfidence, asString, asStringList, runAgentJson, UNTRUSTED_DATA_GUARDRAIL } from "@/lib/ai/agents/shared";
import { socAgentById, type SocAgentId } from "@/lib/ai/agents/catalog";
import type { AgentRunMeta, AiChatMessage } from "@/lib/ai/types";
import type { AgentWorkflowPhase } from "@/lib/agent-workflows";
import type { SigmaRule, SocAlert, SocEvent, ThreatIntelMatch } from "@/lib/types";

export type SpecialistResult = {
  summary: string;
  confidence: number;
  evidence: string[];
  actions: string[];
  handoff: string[];
  meta: AgentRunMeta;
};

export type SpecialistInput = {
  alert: SocAlert;
  relatedSignals: SocEvent[];
  matchedRules: SigmaRule[];
  indicators: ThreatIntelMatch[];
  priorSteps: Array<{ agent: string; summary: string; evidence: string[]; actions: string[] }>;
};

export function deterministicSpecialist(agentId: SocAgentId, phase: AgentWorkflowPhase, input: SpecialistInput, note?: string): SpecialistResult {
  const profile = socAgentById[agentId];
  const related = input.relatedSignals.filter((signal) => signal.hostname && signal.hostname === input.alert.hostname).slice(0, 6);
  const evidence = [...new Set([
    input.alert.id,
    ...related.map((signal) => signal.id),
    ...input.matchedRules.map((rule) => rule.id),
    ...input.indicators.slice(0, 5).map((indicator) => `${indicator.type}:${indicator.value}`),
    ...input.priorSteps.slice(-2).flatMap((step) => step.evidence.slice(0, 3)),
  ])].slice(0, 12);
  const confidence = Math.min(0.99, input.alert.confidence + Math.min(0.08, related.length * 0.02));
  return {
    summary: `${profile.name} completed ${phase.name.toLowerCase()} for ${input.alert.title} using ${evidence.length} retained evidence reference${evidence.length === 1 ? "" : "s"}.`,
    confidence,
    evidence,
    actions: phase.fallbackActions.map((action) => phase.approvalRequired ? `Approval required: ${action}` : action),
    handoff: [`${profile.specialization}: ${phase.instructions}`, `Evidence references: ${evidence.join(", ") || "none"}`],
    meta: { engine: "deterministic", note },
  };
}

export async function runSpecialistAgent(tenantId: string, agentId: SocAgentId, phase: AgentWorkflowPhase, input: SpecialistInput): Promise<SpecialistResult> {
  const profile = socAgentById[agentId];
  const fallback = deterministicSpecialist(agentId, phase, input);
  const run = await runAgentJson(tenantId, agentId, buildSpecialistPrompt(agentId, phase, input), profile.maxTokens);
  if (!run) return deterministicSpecialist(agentId, phase, input, "AI engine unavailable or agent disabled; deterministic specialist analysis applied.");
  const allowedEvidence = new Set(fallback.evidence);
  const evidence = asStringList(run.data.evidence, fallback.evidence).filter((item) => allowedEvidence.has(item));
  const actions = asStringList(run.data.actions, fallback.actions).map((action) => phase.approvalRequired && !/^approval required:/i.test(action) ? `Approval required: ${action}` : action);
  return {
    summary: asString(run.data.summary, fallback.summary),
    confidence: asConfidence(run.data.confidence, fallback.confidence),
    evidence: evidence.length ? evidence : fallback.evidence,
    actions,
    handoff: asStringList(run.data.handoff, fallback.handoff),
    meta: run.meta,
  };
}

export function buildSpecialistPrompt(agentId: SocAgentId, phase: AgentWorkflowPhase, input: SpecialistInput): AiChatMessage[] {
  const profile = socAgentById[agentId];
  return [
    {
      role: "system",
      content:
        `You are ${profile.name} inside Tawny-SOC. Specialization: ${profile.specialization}. ` +
        (profile.deepReasoning ? "Reasoning mode: perform thorough multi-signal analysis before returning concise findings. " : "Reasoning mode: make a fast, decisive assessment from supplied evidence. ") +
        `Method: ${profile.methodology.join("; ")}. Complete workflow phase "${phase.name}": ${phase.instructions} ` +
        `Allowed evidence interfaces: ${[...new Set([...profile.tools, ...phase.tools])].join(", ")}. ` +
        "You receive already-retrieved tenant evidence; never claim an interface or containment action executed. " +
        (phase.approvalRequired ? "Every containment or state-changing action must be labelled approval-required. " : "") +
        UNTRUSTED_DATA_GUARDRAIL +
        ' Return JSON only: {"summary":string,"confidence":0-1,"evidence":string[],"actions":string[],"handoff":string[]}.',
    },
    {
      role: "user",
      content: JSON.stringify({
        focusAlert: input.alert,
        relatedSignals: input.relatedSignals.slice(0, 30),
        matchedRules: input.matchedRules.map((rule) => ({ id: rule.id, title: rule.title, severity: rule.severity, mitreTechniques: rule.mitreTechniques })),
        threatIntel: input.indicators.slice(0, 20),
        priorAgentHandoffs: input.priorSteps,
      }),
    },
  ];
}
