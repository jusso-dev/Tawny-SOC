import { playbooks } from "@/lib/rules";
import { getSession } from "@/lib/session";
import {
  getKelpieIntegration,
  listAuditLogs,
  listComplianceReports,
  listConnectorCatalog,
  listConnectorInstances,
  listAlerts,
  listDeliveryLog,
  listEvidence,
  listEvents,
  listIngestDeadLetters,
  listIngestSources,
  listIncidents,
  listIntegrationChannels,
  listRetentionPolicies,
  listSocSettings,
  listThreatIntelFeeds,
  listThreatIntelMatches,
} from "@/lib/store";
import { listSigmaRules } from "@/lib/sigma";
import type {
  Severity,
  SocAlert,
  SocIncident,
  ThreatIntelMatch,
} from "@/lib/types";

export const severityRank: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

export const threatIntelMatches: ThreatIntelMatch[] = [];

export function severityClass(severity: Severity) {
  return `severity severity-${severity}`;
}

export function relativeTime(value: string) {
  const diff = Date.now() - Date.parse(value);
  if (!Number.isFinite(diff)) return "unknown";
  const minutes = Math.max(0, Math.floor(diff / 60000));
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

export function timeUntil(value?: string) {
  if (!value) return "no expiry";
  const diff = Date.parse(value) - Date.now();
  if (!Number.isFinite(diff)) return "unknown";
  if (diff <= 0) return "expired";
  const minutes = Math.ceil(diff / 60000);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.ceil(minutes / 60);
  if (hours < 24) return `${hours}h`;
  return `${Math.ceil(hours / 24)}d`;
}

export function extractAlertContext(alert: SocAlert, indicators: ThreatIntelMatch[] = []) {
  const payload = alert.payload as { alert?: Record<string, unknown>; telemetry?: Record<string, unknown> };
  const alertPayload = payload?.alert ?? {};
  const telemetryPayload = payload?.telemetry ?? {};
  const commandLine = String(alertPayload.command_line ?? alertPayload.commandLine ?? telemetryPayload.command_line ?? telemetryPayload.commandLine ?? "");
  const user = String(alertPayload.user ?? telemetryPayload.user ?? telemetryPayload.username ?? "unknown");
  const process = String(alertPayload.process ?? telemetryPayload.process ?? telemetryPayload.image ?? telemetryPayload.Image ?? "unknown");
  const destinationIp = String(alertPayload.destination_ip ?? telemetryPayload.destination_ip ?? telemetryPayload.DestinationIp ?? "");

  return {
    ...alert,
    commandLine: alert.commandLine ?? commandLine,
    user: alert.user ?? user,
    process: alert.process ?? process,
    externalIps: alert.externalIps ?? (destinationIp ? [destinationIp] : []),
    tiMatches: alert.tiMatches ?? indicators.filter((ioc) => {
      const haystack = JSON.stringify(alert.payload).toLowerCase();
      return haystack.includes(ioc.value.toLowerCase()) || alert.mitreTechniques.some((technique) => ioc.tags.join(" ").includes(technique.toLowerCase()));
    }),
  };
}

export async function getSocData() {
  const tenantId = await getCurrentTenantId();
  const [
    alerts,
    events,
    incidents,
    rules,
    deliveries,
    feeds,
    indicators,
    kelpie,
    channels,
    settings,
    ingestSources,
    deadLetters,
    connectors,
    reports,
    auditLogs,
    retentionPolicies,
    evidence,
  ] = await Promise.all([
    listAlerts(),
    listEvents(),
    listIncidents(),
    listSigmaRules(),
    listDeliveryLog(),
    listThreatIntelFeeds(tenantId),
    listThreatIntelMatches(tenantId),
    getKelpieIntegration(tenantId),
    listIntegrationChannels(tenantId),
    listSocSettings(tenantId),
    listIngestSources(tenantId),
    listIngestDeadLetters(tenantId),
    listConnectorInstances(tenantId),
    listComplianceReports(tenantId),
    listAuditLogs(tenantId),
    listRetentionPolicies(tenantId),
    listEvidence(tenantId),
  ]);
  const enrichedAlerts = alerts.map((alert) => extractAlertContext(alert, indicators)).sort((a, b) => severityRank[b.severity] - severityRank[a.severity] || Date.parse(b.timestamp) - Date.parse(a.timestamp));
  return {
    alerts: enrichedAlerts,
    events,
    incidents,
    rules,
    playbooks,
    threatIntelMatches: indicators,
    threatIntelFeeds: feeds,
    kelpieConfig: kelpie,
    integrationChannels: channels,
    connectorCatalog: listConnectorCatalog(),
    connectors,
    ingestSources,
    ingestDeadLetters: deadLetters,
    complianceReports: reports,
    auditLogs,
    retentionPolicies,
    evidence,
    settings,
    tenantId,
    deliveryLog: deliveries,
    overview: buildOverview(enrichedAlerts, incidents),
  };
}

async function getCurrentTenantId() {
  const session = await getSession();
  if (!session) return "local-tenant";
  const activeOrganizationId = (session.session as { activeOrganizationId?: string | null }).activeOrganizationId;
  return activeOrganizationId ?? "local-tenant";
}

function countBy<T extends string>(values: T[]) {
  return values.reduce<Record<string, number>>((acc, value) => {
    acc[value] = (acc[value] ?? 0) + 1;
    return acc;
  }, {});
}

function topEntries(values: Record<string, number>, limit = 5) {
  return Object.entries(values)
    .sort(([, a], [, b]) => b - a)
    .slice(0, limit)
    .map(([name, count]) => ({ name, count }));
}

function buildOverview(alerts: SocAlert[], incidents: SocIncident[]) {
  const openAlerts = alerts.filter((alert) => !["resolved", "dismissed", "suppressed"].includes(alert.status));
  const assignedAlerts = alerts.filter((alert) => alert.assignee).length;
  const criticalHigh = alerts.filter((alert) => ["critical", "high"].includes(alert.severity)).length;
  const hosts = alerts.map((alert) => alert.hostname ?? "unknown").filter(Boolean);
  const users = alerts.map((alert) => alert.user ?? "unknown").filter(Boolean);
  const processes = alerts.map((alert) => alert.process ?? "unknown").filter(Boolean);
  const externalIps = alerts.flatMap((alert) => alert.externalIps ?? []);
  const tactics = alerts.flatMap((alert) => alert.mitreTechniques.map((technique) => technique.split(".")[0] ?? technique));
  const rules = alerts.flatMap((alert) => alert.matchedRules);

  return {
    alertVolume: alerts.length,
    incidentVolume: incidents.length,
    openCases: incidents.filter((incident) => incident.status !== "closed").length,
    criticalHigh,
    affectedHosts: new Set(hosts).size,
    unassignedAlerts: alerts.length - assignedAlerts,
    staleAlerts: openAlerts.filter((alert) => Date.now() - Date.parse(alert.timestamp) > 30 * 60_000).length,
    slaBreaches: incidents.filter((incident) => incident.priority === "P1" && incident.status !== "contained").length,
    noisyRules: topEntries(countBy(rules), 3),
    alertToCaseRate: alerts.length ? Math.round((incidents.length / alerts.length) * 100) : 0,
    topRules: topEntries(countBy(rules)),
    topTactics: topEntries(countBy(tactics)),
    topUsers: topEntries(countBy(users)),
    topProcesses: topEntries(countBy(processes)),
    topExternalIps: topEntries(countBy(externalIps)),
    trend: buildTrend(alerts, incidents),
    needsAttention: alerts.length || incidents.length
      ? [
          `${criticalHigh} critical or high alerts need review`,
          `${alerts.length - assignedAlerts} alerts are unassigned`,
        ]
      : ["No alerts, cases, or telemetry have been ingested."],
  };
}

function buildTrend(alerts: SocAlert[], incidents: SocIncident[]) {
  const buckets = [5, 4, 3, 2, 1, 0].map((hoursAgo) => {
    const end = Date.now() - hoursAgo * 60 * 60_000;
    const start = end - 60 * 60_000;
    return {
      label: hoursAgo === 0 ? "Now" : `${hoursAgo}h`,
      alerts: alerts.filter((alert) => Date.parse(alert.timestamp) >= start && Date.parse(alert.timestamp) < end).length,
      cases: incidents.filter((incident) => Date.parse(incident.createdAt) >= start && Date.parse(incident.createdAt) < end).length,
    };
  });
  return buckets;
}
