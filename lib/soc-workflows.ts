import { randomUUID } from "node:crypto";
import type {
  AlertStatus,
  IntegrationDelivery,
  KelpieIntegrationConfig,
  KelpieSyncStatus,
  Severity,
  SocAlert,
  SocIncident,
  SuppressionRule,
  ThreatIntelMatch,
} from "@/lib/types";

type Actor = {
  id: string;
  name: string;
  tenantId: string;
};

type KelpieClient = {
  createAlert(input: Record<string, unknown>): Promise<{ id: string; url?: string }>;
  createCase(input: Record<string, unknown>): Promise<{ id: string; url?: string }>;
  syncCase?(id: string, input: Record<string, unknown>): Promise<{ id: string; url?: string }>;
};

export function createIncidentFromAlert(alert: SocAlert, actor: Actor, existingCount = 0): SocIncident {
  const now = new Date().toISOString();
  return {
    id: `case-${randomUUID()}`,
    tenantId: actor.tenantId,
    number: `SOC-${String(existingCount + 1).padStart(5, "0")}`,
    title: `${alert.title} on ${alert.hostname ?? "unknown host"}`,
    severity: alert.severity,
    priority: severityToPriority(alert.severity),
    status: "triaging",
    assignee: actor.name,
    tags: ["tawny", "created-from-alert"],
    tlp: "amber",
    pap: "green",
    classification: "undetermined",
    mitreTechniques: alert.mitreTechniques,
    observables: alert.tiMatches ?? [],
    linkedHosts: alert.hostname ? [alert.hostname] : [],
    linkedAlertIds: [alert.id],
    kelpieSyncStatus: "not_synced",
    createdAt: now,
    updatedAt: now,
    timeline: [
      {
        id: `timeline-${randomUUID()}`,
        actor: actor.name,
        action: "created_incident_from_alert",
        at: now,
        detail: `Created from alert ${alert.id}.`,
      },
    ],
    tasks: [],
    comments: [],
  };
}

export function assignAlert(alert: SocAlert, assignee: string, actor: Actor): SocAlert {
  assertTenant(alert.tenantId, actor.tenantId);
  return {
    ...alert,
    assignee,
    status: alert.status === "open" ? "triaging" : alert.status,
  };
}

export function assignIncident(incident: SocIncident, assignee: string, actor: Actor): SocIncident {
  assertTenant(incident.tenantId, actor.tenantId);
  const now = new Date().toISOString();
  return {
    ...incident,
    assignee,
    updatedAt: now,
    timeline: [
      ...incident.timeline,
      {
        id: `timeline-${randomUUID()}`,
        actor: actor.name,
        action: "assigned_case",
        at: now,
        detail: `Assigned to ${assignee}.`,
      },
    ],
  };
}

export function enrichAlertWithThreatIntel(alert: SocAlert, indicators: ThreatIntelMatch[]): SocAlert {
  const payload = JSON.stringify(alert.payload).toLowerCase();
  const commandLine = (alert.commandLine ?? "").toLowerCase();
  const externalIps = (alert.externalIps ?? []).map((value) => value.toLowerCase());
  const matches = indicators.filter((indicator) => {
    const value = indicator.value.toLowerCase();
    return payload.includes(value) || commandLine.includes(value) || externalIps.includes(value);
  });

  return {
    ...alert,
    tiMatches: mergeMatches(alert.tiMatches ?? [], matches),
    confidence: matches.length ? Math.min(0.99, alert.confidence + 0.08) : alert.confidence,
  };
}

export async function promoteAlertToKelpie(alert: SocAlert, config: KelpieIntegrationConfig, client: KelpieClient): Promise<IntegrationDelivery> {
  if (!config.enabled || !config.tokenConfigured) {
    return delivery("kelpie", "failed", "/api/v1/alerts", "Kelpie integration is not fully configured", `tawny-alert-${alert.id}`);
  }

  try {
    const result = await client.createAlert({
      externalRef: `tawny-alert-${alert.id}`,
      title: alert.title,
      severity: alert.severity,
      source: "Tawny-SOC",
      tenantId: alert.tenantId,
      hostname: alert.hostname,
      mitreTechniques: alert.mitreTechniques,
      observables: alert.tiMatches ?? [],
      raw: alert.payload,
    });
    return delivery("kelpie", "delivered", "/api/v1/alerts", undefined, result.id);
  } catch (err) {
    return delivery("kelpie", "failed", "/api/v1/alerts", (err as Error).message, `tawny-alert-${alert.id}`);
  }
}

export async function promoteIncidentToKelpie(incident: SocIncident, config: KelpieIntegrationConfig, client: KelpieClient): Promise<SocIncident> {
  if (!config.enabled || !config.tokenConfigured) {
    return withKelpieStatus(incident, "failed", "Kelpie integration is not fully configured");
  }

  try {
    const result = incident.kelpieCaseId && client.syncCase
      ? await client.syncCase(incident.kelpieCaseId, toKelpieCase(incident))
      : await client.createCase(toKelpieCase(incident));

    return {
      ...withKelpieStatus(incident, "synced", `Synced with Kelpie case ${result.id}.`),
      kelpieCaseId: result.id,
      kelpieUrl: result.url,
    };
  } catch (err) {
    return withKelpieStatus(incident, "failed", (err as Error).message);
  }
}

export function recordDeliveryState(previous: IntegrationDelivery | undefined, state: IntegrationDelivery["state"], error?: string): IntegrationDelivery {
  return {
    id: previous?.id ?? `delivery-${randomUUID()}`,
    channel: previous?.channel ?? "webhook",
    target: previous?.target ?? "unconfigured",
    state,
    attempts: (previous?.attempts ?? 0) + 1,
    lastAttemptAt: new Date().toISOString(),
    error,
    externalRef: previous?.externalRef,
  };
}

export function filterTenantAlerts(alerts: SocAlert[], tenantId: string) {
  return alerts.filter((alert) => alert.tenantId === tenantId);
}

export function applySuppressionRules(alert: SocAlert, rules: SuppressionRule[]): SocAlert {
  const now = Date.now();
  const matched = rules.find((rule) => {
    if (!rule.enabled) return false;
    if (rule.expiresAt && Date.parse(rule.expiresAt) < now) return false;
    if (rule.tenantId !== alert.tenantId) return false;
    if (rule.ruleId && !alert.matchedRules.includes(rule.ruleId)) return false;
    if (rule.host && rule.host !== alert.hostname) return false;
    if (rule.user && rule.user !== alert.user) return false;
    if (rule.severity && rule.severity !== alert.severity) return false;
    return Boolean(rule.ruleId || rule.host || rule.user || rule.severity);
  });

  return matched ? { ...alert, status: "suppressed" satisfies AlertStatus } : alert;
}

function severityToPriority(severity: Severity): SocIncident["priority"] {
  if (severity === "critical") return "P1";
  if (severity === "high") return "P2";
  if (severity === "medium") return "P3";
  return "P4";
}

function assertTenant(entityTenantId: string | undefined, actorTenantId: string) {
  if (entityTenantId && entityTenantId !== actorTenantId) {
    throw new Error("Cross-tenant operation denied");
  }
}

function mergeMatches(existing: ThreatIntelMatch[], next: ThreatIntelMatch[]) {
  const byId = new Map(existing.map((item) => [item.id, item]));
  for (const item of next) byId.set(item.id, item);
  return [...byId.values()];
}

function delivery(
  channel: IntegrationDelivery["channel"],
  state: IntegrationDelivery["state"],
  target: string,
  error?: string,
  externalRef?: string,
): IntegrationDelivery {
  return {
    id: `delivery-${randomUUID()}`,
    channel,
    target,
    state,
    attempts: 1,
    lastAttemptAt: new Date().toISOString(),
    error,
    externalRef,
  };
}

function toKelpieCase(incident: SocIncident) {
  return {
    externalRef: `tawny-case-${incident.id}`,
    title: incident.title,
    severity: incident.severity,
    status: incident.status,
    assignee: incident.assignee,
    observables: incident.observables,
    comments: incident.comments,
    linkedAlerts: incident.linkedAlertIds,
    mitreTechniques: incident.mitreTechniques,
  };
}

function withKelpieStatus(incident: SocIncident, status: KelpieSyncStatus, detail: string): SocIncident {
  const now = new Date().toISOString();
  return {
    ...incident,
    kelpieSyncStatus: status,
    updatedAt: now,
    timeline: [
      ...incident.timeline,
      {
        id: `timeline-${randomUUID()}`,
        actor: "Kelpie sync",
        action: `kelpie_${status}`,
        at: now,
        detail,
      },
    ],
  };
}
