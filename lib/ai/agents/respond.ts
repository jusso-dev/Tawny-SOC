import { asString, asStringList, runAgentJson, UNTRUSTED_DATA_GUARDRAIL } from "@/lib/ai/agents/shared";
import type { AgentRunMeta } from "@/lib/ai/types";
import type { EnrichmentAgentResult } from "@/lib/ai/agents/enrichment";
import type { TriageAgentResult } from "@/lib/ai/agents/triage";
import type { Playbook, SocAlert } from "@/lib/types";

export type RespondAgentResult = {
  summary: string;
  playbookId: string;
  immediateActions: string[];
  approvalGatedActions: string[];
  verificationSteps: string[];
  meta: AgentRunMeta;
};

type RespondInput = {
  alert: SocAlert;
  triage: TriageAgentResult;
  hunt: EnrichmentAgentResult;
  playbooks: Playbook[];
};

export function deterministicRespond(input: RespondInput, note?: string): RespondAgentResult {
  const requested = input.playbooks.find((playbook) => playbook.id === input.triage.suggestedPlaybook) ?? input.playbooks[0];
  return {
    summary: `Prepared a governed ${requested?.name ?? "incident response"} plan. Investigation may run now; containment remains human-approved.`,
    playbookId: requested?.id ?? "incident-response",
    immediateActions: [...input.triage.recommendedActions, ...input.hunt.huntQueries.map((query) => `Run hunt: ${query}`)].slice(0, 6),
    approvalGatedActions: ["Isolate affected host", "Block confirmed malicious indicators", "Revoke exposed credentials"],
    verificationSteps: ["Confirm telemetry continues after investigation", "Verify containment target immediately before approval", "Record outcome in case timeline"],
    meta: { engine: "deterministic", note },
  };
}

export async function runRespondAgent(tenantId: string, input: RespondInput): Promise<RespondAgentResult> {
  const fallback = deterministicRespond(input);
  const run = await runAgentJson(tenantId, "respond", [
    {
      role: "system",
      content:
        "You are Tawny-SOC Respond. Turn validated triage and hunt evidence into a reversible response plan. Never claim an action ran. Put containment in approvalGatedActions. " +
        UNTRUSTED_DATA_GUARDRAIL +
        ' Return JSON only: {"summary":string,"playbookId":string,"immediateActions":string[],"approvalGatedActions":string[],"verificationSteps":string[]}.',
    },
    { role: "user", content: JSON.stringify(input) },
  ], 1800);
  if (!run) return deterministicRespond(input, "AI engine unavailable; deterministic response plan applied.");
  const playbookId = asString(run.data.playbookId, fallback.playbookId);
  return {
    summary: asString(run.data.summary, fallback.summary),
    playbookId: input.playbooks.some((playbook) => playbook.id === playbookId) ? playbookId : fallback.playbookId,
    immediateActions: asStringList(run.data.immediateActions, fallback.immediateActions),
    approvalGatedActions: asStringList(run.data.approvalGatedActions, fallback.approvalGatedActions),
    verificationSteps: asStringList(run.data.verificationSteps, fallback.verificationSteps),
    meta: run.meta,
  };
}
