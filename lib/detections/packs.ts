import type { Severity, SocEvent } from "../types";
import { filterWithYaaql } from "../yaaql";

export type DetectionPackManifest = {
  schemaVersion: "tawny-detection-pack/v1";
  id: string;
  name: string;
  version: string;
  description: string;
  author?: string;
  license?: string;
  repository?: {
    path: string;
    ciCommand: string;
  };
  detections: DetectionPackRule[];
  summaryRules: DetectionSummaryRule[];
};

export type DetectionPackRule = {
  id: string;
  title: string;
  status: "draft" | "test" | "enabled" | "disabled" | "deprecated";
  severity: Severity;
  query?: string;
  sigma?: string;
  mitreTechniques: string[];
  tests?: Array<{
    name: string;
    expectedMatchIds: string[];
    expectedNonMatchIds?: string[];
  }>;
};

export type DetectionSummaryRule = {
  id: string;
  name: string;
  description: string;
  query: string;
  groupBy: string[];
  windowMinutes: number;
  threshold: number;
  severity: Severity;
  tenantScoped?: boolean;
  uniqueField?: string;
  mitreTechniques?: string[];
};

export type DetectionPackValidationIssue = {
  level: "error" | "warning";
  path: string;
  message: string;
};

export type DetectionSummarySignal = {
  ruleId: string;
  ruleName: string;
  severity: Severity;
  tenantId: string;
  groupKey: string;
  groupValues: Record<string, string>;
  count: number;
  uniqueCount?: number;
  startedAt: string;
  endedAt: string;
  recordIds: string[];
  summary: string;
  reasons: string[];
  mitreTechniques: string[];
};

export const starterDetectionPack: DetectionPackManifest = {
  schemaVersion: "tawny-detection-pack/v1",
  id: "tawny-soc-starter-behavior-pack",
  name: "Tawny-SOC Starter Behavior Pack",
  version: "0.1.0",
  description: "Portable YAAQL detections and summary rules for authentication, process, and network behavior.",
  author: "Tawny-SOC",
  license: "Apache-2.0",
  repository: {
    path: "detections/tawny-soc-starter-behavior-pack.json",
    ciCommand: "pnpm test -- tests/detection-packs.test.ts",
  },
  detections: [
    {
      id: "tawny-yaaq-auth-failure",
      title: "Authentication failure signal",
      status: "test",
      severity: "medium",
      query: "type:AuthFailure or title:*failed authentication* or payload.outcome=failure",
      mitreTechniques: ["T1110"],
    },
    {
      id: "tawny-yaaq-suspicious-powershell",
      title: "Suspicious PowerShell execution",
      status: "test",
      severity: "high",
      query: "cmd:*powershell* and (cmd:*-enc* or cmd:*downloadstring* or cmd:*base64*)",
      mitreTechniques: ["T1059.001"],
    },
  ],
  summaryRules: [
    {
      id: "summary-auth-failure-burst",
      name: "Authentication failure burst",
      description: "Summarizes repeated authentication failures by user and host inside a short window.",
      query: "type:AuthFailure or title:*failed authentication* or payload.outcome=failure",
      groupBy: ["user", "host"],
      windowMinutes: 60,
      threshold: 3,
      severity: "medium",
      mitreTechniques: ["T1110"],
    },
    {
      id: "summary-suspicious-process-by-host",
      name: "Suspicious process concentration",
      description: "Summarizes suspicious process execution by host for detection review.",
      query: "cmd:*powershell* or cmd:*rundll32* or cmd:*downloadstring* or cmd:*-enc*",
      groupBy: ["host"],
      windowMinutes: 240,
      threshold: 2,
      severity: "high",
      mitreTechniques: ["T1059"],
    },
  ],
};

export function validateDetectionPack(pack: DetectionPackManifest): DetectionPackValidationIssue[] {
  const issues: DetectionPackValidationIssue[] = [];
  const ids = new Set<string>();

  if (pack.schemaVersion !== "tawny-detection-pack/v1") {
    issues.push({ level: "error", path: "schemaVersion", message: "Unsupported detection pack schema version." });
  }
  if (!/^[a-z0-9][a-z0-9-_.]+$/i.test(pack.id)) {
    issues.push({ level: "error", path: "id", message: "Detection pack id must be stable and slug-like." });
  }
  if (!/^\d+\.\d+\.\d+(-[a-z0-9-.]+)?$/i.test(pack.version)) {
    issues.push({ level: "error", path: "version", message: "Detection pack version must use semantic versioning." });
  }
  if (!pack.detections.length && !pack.summaryRules.length) {
    issues.push({ level: "warning", path: "detections", message: "Detection pack has no detections or summary rules." });
  }

  pack.detections.forEach((rule, index) => {
    const path = `detections[${index}]`;
    validateUniqueId(rule.id, `${path}.id`, ids, issues);
    if (!rule.query && !rule.sigma) {
      issues.push({ level: "error", path, message: "Detection rules need either a YAAQL query or Sigma source." });
    }
    if (rule.query) validateYaaql(rule.query, `${path}.query`, issues);
  });

  pack.summaryRules.forEach((rule, index) => {
    const path = `summaryRules[${index}]`;
    validateUniqueId(rule.id, `${path}.id`, ids, issues);
    if (rule.windowMinutes <= 0) {
      issues.push({ level: "error", path: `${path}.windowMinutes`, message: "Summary rule window must be positive." });
    }
    if (rule.threshold <= 0) {
      issues.push({ level: "error", path: `${path}.threshold`, message: "Summary rule threshold must be positive." });
    }
    if (!rule.groupBy.length) {
      issues.push({ level: "warning", path: `${path}.groupBy`, message: "Summary rule has no grouping fields." });
    }
    validateYaaql(rule.query, `${path}.query`, issues);
  });

  return issues;
}

export function runSummaryRules(
  records: SocEvent[],
  rules: DetectionSummaryRule[],
  options: { now?: Date | string } = {},
): DetectionSummarySignal[] {
  const now = toDate(options.now ?? new Date());
  return rules.flatMap((rule) => runSummaryRule(records, rule, now))
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || b.count - a.count || a.ruleId.localeCompare(b.ruleId));
}

function runSummaryRule(records: SocEvent[], rule: DetectionSummaryRule, now: Date): DetectionSummarySignal[] {
  const windowStart = new Date(now.getTime() - rule.windowMinutes * 60_000);
  const windowed = records.filter((record) => {
    const timestamp = Date.parse(record.timestamp);
    return Number.isFinite(timestamp) && timestamp >= windowStart.getTime() && timestamp <= now.getTime();
  });
  const result = filterWithYaaql(windowed, rule.query);
  if (result.error) return [];

  const groups = new Map<string, SocEvent[]>();
  for (const record of result.records) {
    const tenantId = rule.tenantScoped === false ? "*" : record.tenantId || "unknown-tenant";
    const groupValues = groupValuesFor(record, rule.groupBy);
    const groupKey = stableGroupKey(tenantId, groupValues);
    groups.set(groupKey, [...groups.get(groupKey) ?? [], record]);
  }

  return [...groups.entries()].flatMap(([groupKey, groupedRecords]) => {
    const groupValues = groupValuesFor(groupedRecords[0], rule.groupBy);
    const uniqueField = rule.uniqueField;
    const uniqueValues = uniqueField
      ? new Set(groupedRecords.map((record) => fieldValue(record, uniqueField)).filter(Boolean))
      : undefined;
    const scoreCount = uniqueValues ? uniqueValues.size : groupedRecords.length;
    if (scoreCount < rule.threshold) return [];

    const sorted = [...groupedRecords].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
    const tenantId = rule.tenantScoped === false ? "*" : groupedRecords[0].tenantId || "unknown-tenant";
    const groupLabel = Object.entries(groupValues).map(([key, value]) => `${key}=${value}`).join(", ") || tenantId;

    return [{
      ruleId: rule.id,
      ruleName: rule.name,
      severity: rule.severity,
      tenantId,
      groupKey,
      groupValues,
      count: groupedRecords.length,
      uniqueCount: uniqueValues?.size,
      startedAt: sorted[0].timestamp,
      endedAt: sorted[sorted.length - 1].timestamp,
      recordIds: sorted.map((record) => record.id),
      summary: `${rule.name}: ${scoreCount} matching ${scoreCount === 1 ? "record" : "records"} for ${groupLabel}.`,
      reasons: [
        `Query matched: ${rule.query}`,
        `Window: last ${rule.windowMinutes} minutes`,
        `Threshold: ${rule.threshold}`,
        `Grouped by: ${rule.groupBy.join(", ") || "tenant"}`,
      ],
      mitreTechniques: rule.mitreTechniques ?? [],
    }];
  });
}

function validateUniqueId(id: string, path: string, ids: Set<string>, issues: DetectionPackValidationIssue[]) {
  if (!/^[a-z0-9][a-z0-9-_.]+$/i.test(id)) {
    issues.push({ level: "error", path, message: "Rule id must be stable and slug-like." });
  }
  if (ids.has(id)) {
    issues.push({ level: "error", path, message: "Rule id must be unique inside the pack." });
  }
  ids.add(id);
}

function validateYaaql(query: string, path: string, issues: DetectionPackValidationIssue[]) {
  const result = filterWithYaaql([], query);
  if (result.error) {
    issues.push({ level: "error", path, message: result.error });
  }
}

function groupValuesFor(record: SocEvent, fields: string[]) {
  return Object.fromEntries(fields.map((field) => [field, fieldValue(record, field) || "unknown"]));
}

function stableGroupKey(tenantId: string, values: Record<string, string>) {
  const parts = Object.entries(values).map(([key, value]) => `${key}:${value.toLowerCase()}`);
  return [tenantId, ...parts].join("|");
}

function fieldValue(record: SocEvent, field: string): string {
  const aliases: Record<string, string[]> = {
    cmd: ["commandLine", "command_line", "CommandLine"],
    host: ["hostname", "host", "computer"],
    tenant: ["tenantId", "tenant_id"],
    type: ["eventType", "event_type"],
    user: ["user", "username", "UserId", "userId", "account", "subjectUserName"],
  };
  const candidates = aliases[field.toLowerCase()] ?? [field];
  for (const candidate of candidates) {
    const direct = candidate.includes(".") ? valueAtPath(record, candidate) : valueAt(record as unknown, candidate);
    if (direct) return direct;
    const payload = candidate.includes(".") ? valueAtPath(record.payload, candidate.replace(/^payload\./, "")) : valueAt(record.payload, candidate);
    if (payload) return payload;
  }
  return "";
}

function valueAtPath(value: unknown, path: string): string {
  const segments = path.split(".").filter(Boolean);
  let cursor = value;
  for (const segment of segments) {
    if (!cursor || typeof cursor !== "object" || !(segment in cursor)) return "";
    cursor = (cursor as Record<string, unknown>)[segment];
  }
  if (typeof cursor === "string" || typeof cursor === "number" || typeof cursor === "boolean") return String(cursor);
  return "";
}

function valueAt(value: unknown, key: string): string {
  if (!value || typeof value !== "object") return "";
  if (key in value) {
    const found = (value as Record<string, unknown>)[key];
    if (typeof found === "string" || typeof found === "number" || typeof found === "boolean") return String(found);
  }
  for (const child of Object.values(value)) {
    const nested = valueAt(child, key);
    if (nested) return nested;
  }
  return "";
}

function toDate(value: Date | string) {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new Error("now must be a valid timestamp.");
  return date;
}

function severityRank(severity: Severity) {
  if (severity === "critical") return 4;
  if (severity === "high") return 3;
  if (severity === "medium") return 2;
  return 1;
}
