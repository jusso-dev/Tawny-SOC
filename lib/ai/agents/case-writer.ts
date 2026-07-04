import { asString, asStringList, runAgentJson, UNTRUSTED_DATA_GUARDRAIL } from "@/lib/ai/agents/shared";
import type { AgentRunMeta } from "@/lib/ai/types";
import type { SocAlert, SocIncident } from "@/lib/types";

export type CaseDraftResult = {
  title: string;
  executiveSummary: string;
  technicalNarrative: string;
  impactAssessment: string;
  recommendations: string[];
  meta: AgentRunMeta;
};

export type CaseWriterInput = {
  incident: SocIncident;
  linkedAlerts: SocAlert[];
};

export function buildCaseWriterPrompt(input: CaseWriterInput) {
  const { incident, linkedAlerts } = input;
  const context = {
    incident: {
      number: incident.number,
      title: incident.title,
      severity: incident.severity,
      priority: incident.priority,
      status: incident.status,
      classification: incident.classification,
      tlp: incident.tlp,
      mitreTechniques: incident.mitreTechniques,
      linkedHosts: incident.linkedHosts,
      createdAt: incident.createdAt,
      observables: incident.observables.map((ioc) => ({ type: ioc.type, value: ioc.value, sourceFeed: ioc.sourceFeed })),
      timeline: incident.timeline.map((item) => ({ at: item.at, actor: item.actor, action: item.action, detail: item.detail })),
      tasks: incident.tasks.map((task) => ({ title: task.title, status: task.status })),
    },
    linkedAlerts: linkedAlerts.map((alert) => ({
      title: alert.title,
      severity: alert.severity,
      host: alert.hostname ?? null,
      user: alert.user ?? null,
      process: alert.process ?? null,
      commandLine: alert.commandLine || null,
      mitreTechniques: alert.mitreTechniques,
      timestamp: alert.timestamp,
    })),
  };

  return [
    {
      role: "system" as const,
      content:
        "You are the case-writing agent inside Tawny-SOC. Draft a professional incident case write-up from the case record, " +
        "linked alerts, and analyst timeline. Write for two audiences: an executive summary in plain language, and a technical " +
        "narrative for responders. Only state what the evidence supports. " +
        UNTRUSTED_DATA_GUARDRAIL +
        ' Respond with a single JSON object only: {"title": string, "executiveSummary": string (3-5 sentences, plain language), ' +
        '"technicalNarrative": string (chronological, references hosts/users/techniques), "impactAssessment": string, ' +
        '"recommendations": string[] (next steps and hardening actions)}',
    },
    { role: "user" as const, content: JSON.stringify(context) },
  ];
}

export function deterministicCaseDraft(input: CaseWriterInput, note?: string): CaseDraftResult {
  const { incident, linkedAlerts } = input;
  const hosts = incident.linkedHosts.join(", ") || "no linked hosts";
  const techniques = incident.mitreTechniques.join(", ") || "no mapped techniques";
  return {
    title: `${incident.number}: ${incident.title}`,
    executiveSummary:
      `${incident.severity} severity case ${incident.number} (${incident.priority}) is ${incident.status} with ` +
      `${linkedAlerts.length} linked alert${linkedAlerts.length === 1 ? "" : "s"} affecting ${hosts}.`,
    technicalNarrative: incident.timeline.length
      ? incident.timeline.map((item) => `${new Date(item.at).toISOString()} — ${item.actor}: ${item.action} (${item.detail})`).join("\n")
      : "No analyst timeline entries recorded yet.",
    impactAssessment: `Observed activity maps to ${techniques}. Classification is ${incident.classification.replace("_", " ")}.`,
    recommendations: [
      "Complete outstanding case tasks and record evidence",
      "Confirm containment on all linked hosts",
      "Update classification once root cause is confirmed",
    ],
    meta: { engine: "deterministic", note },
  };
}

export async function runCaseWriterAgent(tenantId: string, input: CaseWriterInput): Promise<CaseDraftResult> {
  const run = await runAgentJson(tenantId, "case-writer", buildCaseWriterPrompt(input), 2200);
  if (!run) return deterministicCaseDraft(input, "AI engine unavailable; deterministic draft applied.");

  const fallback = deterministicCaseDraft(input);
  return {
    title: asString(run.data.title, fallback.title),
    executiveSummary: asString(run.data.executiveSummary, fallback.executiveSummary),
    technicalNarrative: asString(run.data.technicalNarrative, fallback.technicalNarrative),
    impactAssessment: asString(run.data.impactAssessment, fallback.impactAssessment),
    recommendations: asStringList(run.data.recommendations, fallback.recommendations),
    meta: run.meta,
  };
}
