import { sigmaRules } from "@/lib/rules";
import type { Severity, SigmaRule } from "@/lib/types";

const severityScore: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

export function normalizeSeverity(value: unknown): Severity {
  const normalized = String(value ?? "low").toLowerCase();
  if (normalized === "critical" || normalized === "high" || normalized === "medium" || normalized === "low") {
    return normalized;
  }
  return "low";
}

export function topSeverity(values: Severity[]): Severity {
  return values.sort((a, b) => severityScore[b] - severityScore[a])[0] ?? "low";
}

export function payloadText(payload: unknown): string {
  if (typeof payload === "string") return payload.toLowerCase();
  try {
    return JSON.stringify(payload).toLowerCase();
  } catch {
    return "";
  }
}

export function matchRules(payload: unknown, eventType?: string, explicitRuleId?: string): SigmaRule[] {
  const text = payloadText(payload);
  const matches = sigmaRules.filter((rule) => {
    if (explicitRuleId && rule.id === explicitRuleId) return true;
    const haystack = `${text} ${String(eventType ?? "").toLowerCase()}`;

    if (rule.id.includes("ps-encoded-command")) {
      return /powershell|pwsh/.test(haystack) && /-enc|-encodedcommand|\/encodedcommand/.test(haystack);
    }
    if (rule.id.includes("lolbin-mshta")) {
      return haystack.includes("mshta") && /http:\/\/|https:\/\/|javascript:|vbscript:/.test(haystack);
    }
    if (rule.id.includes("curl-pipe")) {
      return /(curl|wget).*(\|\s*(sh|bash|python))/.test(haystack);
    }
    if (rule.id.includes("launch-agent")) {
      return /launchagents|launchdaemons|\/library\/launch/.test(haystack);
    }
    if (rule.id.includes("dns-dga")) {
      return /\b[a-z0-9]{22,}\.[a-z]{2,}\b/.test(haystack);
    }
    if (rule.id.includes("credential-dump")) {
      return /lsass|procdump|sekurlsa::|minidump|comsvcs\.dll/.test(haystack);
    }
    return false;
  });

  return matches;
}

export function triageSummary(input: {
  title: string;
  hostname?: string;
  severity: Severity;
  rules: SigmaRule[];
  eventType?: string;
}) {
  const techniques = [...new Set(input.rules.flatMap((rule) => rule.mitreTechniques))];
  const topRule = input.rules[0];
  const host = input.hostname ? ` on ${input.hostname}` : "";
  const basis = topRule
    ? `${topRule.title} mapped to ${techniques.join(", ")}`
    : `${input.eventType ?? "telemetry"} did not match the starter Sigma pack`;
  const recommendedPlaybook = input.severity === "critical" || input.severity === "high"
    ? "incident-response"
    : input.rules.length > 0
      ? "full-investigation"
      : "threat-hunt";

  return {
    confidence: Math.min(0.98, input.rules.length ? 0.74 + input.rules.length * 0.07 : 0.42),
    aiSummary: `${input.title}${host}: ${basis}. Review neighboring Tawny telemetry before containment.`,
    recommendedPlaybook,
    techniques,
  };
}
