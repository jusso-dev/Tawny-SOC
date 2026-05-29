import type { Severity, SocEvent } from "@/lib/types";

export type UebaBehaviorCategory =
  | "authentication"
  | "process"
  | "network"
  | "privilege"
  | "data_access"
  | "threat_intel";

export type UebaEntityKind =
  | "application"
  | "host"
  | "ip"
  | "process"
  | "service_account"
  | "user"
  | "unknown";

export type UebaEntityRef = {
  kind: UebaEntityKind;
  value: string;
};

export type UebaBehaviorRecord = {
  id: string;
  tenantId: string;
  category: UebaBehaviorCategory;
  behavior: string;
  summary: string;
  actor: UebaEntityRef;
  target?: UebaEntityRef;
  observedAt: string;
  sourceEventIds: string[];
  riskScore: number;
  confidence: number;
  reasons: string[];
  fields: Record<string, string>;
};

export type UebaEntityBehaviorSummary = {
  tenantId: string;
  entity: UebaEntityRef;
  behaviorCount: number;
  riskScore: number;
  firstSeen: string;
  lastSeen: string;
  categories: UebaBehaviorCategory[];
  topReasons: string[];
  sourceEventIds: string[];
};

type FieldMap = Map<string, string>;

const severityRisk: Record<Severity, number> = {
  critical: 80,
  high: 60,
  medium: 35,
  low: 15,
};

export function buildBehaviorRecords(records: SocEvent[]): UebaBehaviorRecord[] {
  return records
    .flatMap((record) => buildBehaviorsForRecord(record))
    .sort((a, b) => Date.parse(b.observedAt) - Date.parse(a.observedAt) || a.id.localeCompare(b.id));
}

export function summarizeBehaviorEntities(behaviors: UebaBehaviorRecord[]): UebaEntityBehaviorSummary[] {
  const groups = new Map<string, UebaBehaviorRecord[]>();

  for (const behavior of behaviors) {
    const key = entityKey(behavior.tenantId, behavior.actor);
    groups.set(key, [...groups.get(key) ?? [], behavior]);
  }

  return [...groups.values()]
    .map((items) => {
      const sorted = [...items].sort((a, b) => Date.parse(a.observedAt) - Date.parse(b.observedAt));
      const reasons = new Map<string, number>();
      for (const item of items) {
        for (const reason of item.reasons) reasons.set(reason, (reasons.get(reason) ?? 0) + 1);
      }
      const maxRisk = Math.max(...items.map((item) => item.riskScore));
      const riskScore = Math.min(100, Math.round(maxRisk + Math.log2(items.length + 1) * 6));

      return {
        tenantId: items[0].tenantId,
        entity: items[0].actor,
        behaviorCount: items.length,
        riskScore,
        firstSeen: sorted[0].observedAt,
        lastSeen: sorted[sorted.length - 1].observedAt,
        categories: unique(items.map((item) => item.category)),
        topReasons: [...reasons.entries()]
          .sort(([, left], [, right]) => right - left)
          .slice(0, 5)
          .map(([reason]) => reason),
        sourceEventIds: unique(items.flatMap((item) => item.sourceEventIds)),
      };
    })
    .sort((a, b) => b.riskScore - a.riskScore || b.behaviorCount - a.behaviorCount || a.entity.value.localeCompare(b.entity.value));
}

function buildBehaviorsForRecord(record: SocEvent): UebaBehaviorRecord[] {
  const fields = collectRecordFields(record);
  const haystack = searchableText(record, fields);
  const actor = actorFor(fields);
  const host = field(fields, "hostname", "host", "computer", "device_name", "deviceName");
  const processName = field(fields, "process", "process_name", "processName", "image", "Image", "new_process_name", "NewProcessName");
  const commandLine = field(fields, "command_line", "commandLine", "CommandLine", "process.command_line");
  const sourceIp = field(fields, "source_ip", "src_ip", "src", "ipaddress", "IPAddress", "clientip", "ClientIP", "remote_ip");
  const destinationIp = field(fields, "destination_ip", "dst_ip", "dst", "DestinationIp", "remote_ip", "externalIp");
  const destinationPort = field(fields, "destination_port", "dst_port", "dpt", "destinationPort");
  const url = field(fields, "url", "request_url", "requestUrl", "url_full", "objectid", "ObjectId");
  const objectName = field(fields, "object", "objectid", "ObjectId", "file_name", "fileName", "path");
  const eventType = record.eventType ?? field(fields, "event_type", "eventType", "operation", "Operation");
  const tenantId = record.tenantId || field(fields, "tenant_id", "tenantId") || "unknown-tenant";
  const base = baseRisk(record);
  const output: UebaBehaviorRecord[] = [];

  if (isAuthenticationBehavior(eventType, haystack)) {
    const failed = /fail|den(y|ied)|invalid|error|50074|lock(ed|out)?/i.test(haystack);
    const target = sourceIp ? entity("ip", sourceIp) : host ? entity("host", host) : undefined;
    output.push(behavior(record, tenantId, "authentication", {
      actor,
      target,
      behavior: failed ? "authentication_failure" : "authentication_observed",
      summary: failed
        ? `${actor.value} failed authentication${sourceIp ? ` from ${sourceIp}` : ""}${host ? ` involving ${host}` : ""}.`
        : `${actor.value} authenticated${sourceIp ? ` from ${sourceIp}` : ""}${host ? ` involving ${host}` : ""}.`,
      riskScore: clampRisk(base + (failed ? 18 : 4)),
      reasons: compact([
        `Event type maps to authentication: ${eventType || "unknown"}`,
        failed ? "Outcome indicates failed or denied authentication." : "Outcome indicates authentication activity.",
        sourceIp ? `Source IP observed: ${sourceIp}` : "",
        host ? `Host context observed: ${host}` : "",
      ]),
      fields: compactRecord({ eventType, user: actor.value, sourceIp, host }),
    }));
  }

  if (isProcessBehavior(eventType, haystack, processName, commandLine)) {
    const suspiciousMarkers = suspiciousCommandMarkers(`${processName ?? ""} ${commandLine ?? ""}`);
    output.push(behavior(record, tenantId, "process", {
      actor,
      target: processName ? entity("process", processName) : host ? entity("host", host) : undefined,
      behavior: suspiciousMarkers.length ? "suspicious_process_execution" : "process_execution",
      summary: `${actor.value} executed ${processName || "a process"}${host ? ` on ${host}` : ""}.`,
      riskScore: clampRisk(base + (suspiciousMarkers.length ? 28 : 8)),
      reasons: compact([
        `Event type maps to process activity: ${eventType || "unknown"}`,
        processName ? `Process observed: ${processName}` : "",
        commandLine ? "Command line is present for analyst review." : "",
        ...suspiciousMarkers.map((marker) => `Command line matched suspicious marker: ${marker}`),
      ]),
      fields: compactRecord({ eventType, user: actor.value, host, process: processName, commandLine }),
    }));
  }

  if (isNetworkBehavior(eventType, haystack, sourceIp, destinationIp, destinationPort, url)) {
    const denied = /deny|denied|blocked|failure|reject/i.test(haystack);
    const targetValue = destinationIp || url || destinationPort || sourceIp || host || "network";
    output.push(behavior(record, tenantId, "network", {
      actor: host ? entity("host", host) : actor,
      target: destinationIp ? entity("ip", destinationIp) : url ? entity("application", url) : undefined,
      behavior: denied ? "network_block" : "network_activity",
      summary: `${host || actor.value} ${denied ? "was blocked during" : "performed"} network activity involving ${targetValue}.`,
      riskScore: clampRisk(base + (denied ? 14 : 8) + (destinationIp ? 6 : 0)),
      reasons: compact([
        `Event type maps to network activity: ${eventType || "unknown"}`,
        denied ? "Network action indicates block or deny." : "Network fields were observed.",
        sourceIp ? `Source IP observed: ${sourceIp}` : "",
        destinationIp ? `Destination IP observed: ${destinationIp}` : "",
        destinationPort ? `Destination port observed: ${destinationPort}` : "",
        url ? `URL/object observed: ${url}` : "",
      ]),
      fields: compactRecord({ eventType, host, sourceIp, destinationIp, destinationPort, url }),
    }));
  }

  if (isPrivilegeBehavior(eventType, haystack)) {
    output.push(behavior(record, tenantId, "privilege", {
      actor,
      target: host ? entity("host", host) : undefined,
      behavior: "privilege_or_admin_change",
      summary: `${actor.value} performed privileged or administrative activity${host ? ` involving ${host}` : ""}.`,
      riskScore: clampRisk(base + 30),
      reasons: compact([
        `Event type or payload maps to privileged activity: ${eventType || "unknown"}`,
        "Administrative, role, group, or privilege keywords were observed.",
        host ? `Host context observed: ${host}` : "",
      ]),
      fields: compactRecord({ eventType, user: actor.value, host }),
    }));
  }

  if (isDataAccessBehavior(eventType, haystack, objectName, url)) {
    output.push(behavior(record, tenantId, "data_access", {
      actor,
      target: objectName || url ? entity("application", objectName || url || "object") : undefined,
      behavior: "data_access",
      summary: `${actor.value} accessed ${objectName || url || "a data object"}.`,
      riskScore: clampRisk(base + 10),
      reasons: compact([
        `Event type maps to data access: ${eventType || "unknown"}`,
        objectName ? `Object observed: ${objectName}` : "",
        url ? `URL/object URL observed: ${url}` : "",
      ]),
      fields: compactRecord({ eventType, user: actor.value, object: objectName, url }),
    }));
  }

  if (record.matchedRules.length > 0 || record.mitreTechniques.length > 0) {
    output.push(behavior(record, tenantId, "threat_intel", {
      actor,
      target: host ? entity("host", host) : undefined,
      behavior: "detection_context",
      summary: `${actor.value} has detection context from ${record.matchedRules.length || record.mitreTechniques.length} signal${record.matchedRules.length + record.mitreTechniques.length === 1 ? "" : "s"}.`,
      riskScore: clampRisk(base + 16),
      reasons: compact([
        record.matchedRules.length ? `Matched rules: ${record.matchedRules.join(", ")}` : "",
        record.mitreTechniques.length ? `MITRE techniques: ${record.mitreTechniques.join(", ")}` : "",
      ]),
      fields: compactRecord({ eventType, user: actor.value, host, rules: record.matchedRules.join(","), mitre: record.mitreTechniques.join(",") }),
    }));
  }

  return output.map((item, index) => ({
    ...item,
    id: `behavior-${slug(record.id)}-${item.category}-${index + 1}`,
  }));
}

function behavior(
  record: SocEvent,
  tenantId: string,
  category: UebaBehaviorCategory,
  input: Omit<UebaBehaviorRecord, "category" | "confidence" | "id" | "observedAt" | "sourceEventIds" | "tenantId">,
): UebaBehaviorRecord {
  return {
    id: "",
    tenantId,
    category,
    confidence: confidenceFor(input.reasons),
    observedAt: record.timestamp,
    sourceEventIds: [record.id],
    ...input,
  };
}

function collectRecordFields(record: SocEvent): FieldMap {
  const fields = new Map<string, string>();
  setField(fields, "id", record.id);
  setField(fields, "source", record.source);
  setField(fields, "kind", record.kind);
  setField(fields, "title", record.title);
  setField(fields, "severity", record.severity);
  setField(fields, "timestamp", record.timestamp);
  setField(fields, "tenantId", record.tenantId);
  setField(fields, "agentId", record.agentId);
  setField(fields, "hostname", record.hostname);
  setField(fields, "eventType", record.eventType);
  flattenPayload(record.payload, fields);
  return fields;
}

function flattenPayload(value: unknown, fields: FieldMap, path: string[] = [], depth = 0) {
  if (depth > 6 || value === null || value === undefined) return;
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    setField(fields, path.join("."), String(value));
    setField(fields, path[path.length - 1] ?? "", String(value));
    return;
  }
  if (Array.isArray(value)) {
    value.slice(0, 25).forEach((item, index) => flattenPayload(item, fields, [...path, String(index)], depth + 1));
    return;
  }
  if (typeof value === "object") {
    for (const [key, child] of Object.entries(value)) flattenPayload(child, fields, [...path, key], depth + 1);
  }
}

function setField(fields: FieldMap, key: string, value: unknown) {
  const text = typeof value === "string" ? value.trim() : value === undefined || value === null ? "" : String(value);
  if (!key || !text) return;
  fields.set(key.toLowerCase(), text);
}

function field(fields: FieldMap, ...names: string[]) {
  for (const name of names) {
    const value = fields.get(name.toLowerCase());
    if (value) return value;
  }
  return "";
}

function actorFor(fields: FieldMap): UebaEntityRef {
  const user = field(fields, "user", "username", "user_id", "userId", "userid", "UserId", "subjectUserName", "account", "principal", "actor");
  if (user) return entity(isServiceAccount(user) ? "service_account" : "user", user);
  const host = field(fields, "hostname", "host", "computer", "device");
  if (host) return entity("host", host);
  return entity("unknown", "unknown actor");
}

function entity(kind: UebaEntityKind, value: string): UebaEntityRef {
  return { kind, value: value.trim() || "unknown" };
}

function searchableText(record: SocEvent, fields: FieldMap) {
  return [
    record.title,
    record.eventType,
    record.severity,
    ...fields.values(),
  ].join(" ").toLowerCase();
}

function isAuthenticationBehavior(eventType: string, text: string) {
  return /auth|login|logon|signin|sign-in|sign_in|credential|mfa/.test(`${eventType} ${text}`.toLowerCase());
}

function isProcessBehavior(eventType: string, text: string, processName: string, commandLine: string) {
  return Boolean(processName || commandLine || /process|command|script|powershell|shell|exec/.test(`${eventType} ${text}`.toLowerCase()));
}

function isNetworkBehavior(eventType: string, text: string, sourceIp: string, destinationIp: string, destinationPort: string, url: string) {
  return Boolean(sourceIp || destinationIp || destinationPort || url || /network|firewall|proxy|dns|http|url|connection|traffic/.test(`${eventType} ${text}`.toLowerCase()));
}

function isPrivilegeBehavior(eventType: string, text: string) {
  return /admin|privilege|role|group|permission|elevat|new user|user created|member added|iam|root/.test(`${eventType} ${text}`.toLowerCase());
}

function isDataAccessBehavior(eventType: string, text: string, objectName: string, url: string) {
  return Boolean(objectName || (/file|object|sharepoint|mailbox|download|upload|data access|fileaccessed/.test(`${eventType} ${text}`.toLowerCase()) && url));
}

function suspiciousCommandMarkers(value: string) {
  const text = value.toLowerCase();
  return [
    ["powershell", "powershell"],
    ["encoded command", "-enc"],
    ["download cradle", "downloadstring"],
    ["curl", "curl "],
    ["wget", "wget "],
    ["base64", "base64"],
    ["living-off-the-land binary", "rundll32"],
  ]
    .filter(([, marker]) => text.includes(marker))
    .map(([label]) => label);
}

function baseRisk(record: SocEvent) {
  return severityRisk[record.severity] ?? 15;
}

function confidenceFor(reasons: string[]) {
  return Math.min(95, 55 + reasons.length * 8);
}

function clampRisk(value: number) {
  return Math.max(0, Math.min(100, Math.round(value)));
}

function compact(values: string[]) {
  return values.map((value) => value.trim()).filter(Boolean);
}

function compactRecord(values: Record<string, string | undefined>): Record<string, string> {
  const output: Record<string, string> = {};
  for (const [key, value] of Object.entries(values)) {
    if (value) output[key] = value;
  }
  return output;
}

function isServiceAccount(value: string) {
  return /(^svc[-_.])|([-_.]svc$)|service account/i.test(value);
}

function entityKey(tenantId: string, entityRef: UebaEntityRef) {
  return `${tenantId}:${entityRef.kind}:${entityRef.value.toLowerCase()}`;
}

function unique<T extends string>(values: T[]): T[] {
  return [...new Set(values)];
}

function slug(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "event";
}
