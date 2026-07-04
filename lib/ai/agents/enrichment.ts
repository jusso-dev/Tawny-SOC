import { asString, asStringList, runAgentJson, UNTRUSTED_DATA_GUARDRAIL } from "@/lib/ai/agents/shared";
import type { AgentRunMeta } from "@/lib/ai/types";
import type { SocAlert, ThreatIntelMatch } from "@/lib/types";

export type IndicatorAssessment = {
  value: string;
  type: string;
  assessment: string;
  risk: "high" | "medium" | "low";
};

export type EnrichmentAgentResult = {
  summary: string;
  indicators: IndicatorAssessment[];
  huntQueries: string[];
  hypotheses: string[];
  meta: AgentRunMeta;
};

export type EnrichmentAgentInput = {
  alert: SocAlert;
  indicators: ThreatIntelMatch[];
};

function parseRisk(value: unknown): "high" | "medium" | "low" {
  return value === "high" || value === "medium" || value === "low" ? value : "medium";
}

export function buildEnrichmentPrompt(input: EnrichmentAgentInput) {
  const { alert, indicators } = input;
  const context = {
    alert: {
      title: alert.title,
      severity: alert.severity,
      host: alert.hostname ?? null,
      user: alert.user ?? null,
      process: alert.process ?? null,
      commandLine: alert.commandLine || null,
      externalIps: alert.externalIps ?? [],
      mitreTechniques: alert.mitreTechniques,
      payload: alert.payload,
    },
    threatIntelMatches: indicators.map((ioc) => ({
      type: ioc.type,
      value: ioc.value,
      sourceFeed: ioc.sourceFeed,
      confidence: ioc.confidence,
      tags: ioc.tags,
      firstSeen: ioc.firstSeen,
      lastSeen: ioc.lastSeen,
    })),
    huntLanguage:
      "YAAQL: field contains host:win-*, exact eventType=DnsQuery, has:ip / has:domain / has:hash, boolean and/or/not, " +
      "lists severity in (critical, high), payload paths payload.alert.command_line:powershell",
  };

  return [
    {
      role: "system" as const,
      content:
        "You are the threat-intel enrichment agent inside Tawny-SOC. Correlate the alert's observables with the supplied " +
        "feed matches, assess each indicator, and give the analyst pivots to run next. Label speculation clearly as hypothesis. " +
        UNTRUSTED_DATA_GUARDRAIL +
        ' Respond with a single JSON object only: {"summary": string (2-3 sentences), ' +
        '"indicators": [{"value": string, "type": string, "assessment": string, "risk": "high"|"medium"|"low"}], ' +
        '"huntQueries": string[] (valid YAAQL queries to pivot on this activity), "hypotheses": string[] (clearly-labeled hypotheses)}',
    },
    { role: "user" as const, content: JSON.stringify(context) },
  ];
}

export function deterministicEnrichment(input: EnrichmentAgentInput, note?: string): EnrichmentAgentResult {
  const { alert, indicators } = input;
  const feeds = [...new Set(indicators.map((ioc) => ioc.sourceFeed))];
  const host = alert.hostname ?? "";
  return {
    summary: indicators.length
      ? `${indicators.length} indicator${indicators.length === 1 ? "" : "s"} matched across ${feeds.join(", ")}. Review indicator context before containment.`
      : "No threat intel feed matches for this alert's observables yet. Re-check after the next feed sync.",
    indicators: indicators.map((ioc) => ({
      value: ioc.value,
      type: ioc.type,
      assessment: `Seen in ${ioc.sourceFeed} (${ioc.confidence}% confidence)${ioc.tags.length ? `, tagged ${ioc.tags.join(", ")}` : ""}.`,
      risk: ioc.confidence >= 75 ? "high" : ioc.confidence >= 40 ? "medium" : "low",
    })),
    huntQueries: [
      ...(host ? [`host:${host}`] : []),
      ...indicators.slice(0, 3).map((ioc) => ioc.type === "ip" ? `ip:${ioc.value}` : ioc.type === "domain" ? `domain:${ioc.value}` : `"${ioc.value}"`),
      "has:mitre and severity in (critical, high)",
    ],
    hypotheses: [],
    meta: { engine: "deterministic", note },
  };
}

export async function runEnrichmentAgent(tenantId: string, input: EnrichmentAgentInput): Promise<EnrichmentAgentResult> {
  const run = await runAgentJson(tenantId, "enrichment", buildEnrichmentPrompt(input));
  if (!run) return deterministicEnrichment(input, "AI engine unavailable; deterministic enrichment applied.");

  const fallback = deterministicEnrichment(input);
  const rawIndicators = Array.isArray(run.data.indicators) ? run.data.indicators : [];
  const indicators = rawIndicators
    .filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === "object")
    .map((item) => ({
      value: asString(item.value, "unknown"),
      type: asString(item.type, "observable"),
      assessment: asString(item.assessment, "No assessment provided."),
      risk: parseRisk(item.risk),
    }));

  return {
    summary: asString(run.data.summary, fallback.summary),
    indicators: indicators.length ? indicators : fallback.indicators,
    huntQueries: asStringList(run.data.huntQueries, fallback.huntQueries),
    hypotheses: asStringList(run.data.hypotheses),
    meta: run.meta,
  };
}
