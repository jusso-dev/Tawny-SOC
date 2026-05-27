import { playbooks, sigmaRules } from "@/lib/rules";
import { listAlerts, listEvents } from "@/lib/store";
import type {
  IntegrationDelivery,
  KelpieIntegrationConfig,
  Severity,
  SocAlert,
  SocIncident,
  SocTask,
  SocTimelineItem,
  ThreatIntelFeed,
  ThreatIntelMatch,
} from "@/lib/types";

const now = new Date();
const iso = (minutesAgo: number) => new Date(now.getTime() - minutesAgo * 60_000).toISOString();

export const severityRank: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

export const threatIntelMatches: ThreatIntelMatch[] = [
  {
    id: "ioc-ip-185-199-110-153",
    type: "ip",
    value: "185.199.110.153",
    sourceFeed: "OTX suspicious infrastructure",
    confidence: 82,
    tags: ["c2", "powershell", "recent"],
    firstSeen: iso(60 * 24 * 6),
    lastSeen: iso(28),
    expiry: iso(-60 * 24 * 21),
  },
  {
    id: "ioc-domain-a83kdl",
    type: "domain",
    value: "a83kdl29dls02ka9sldk20v.example",
    sourceFeed: "Custom DGA watchlist",
    confidence: 74,
    tags: ["dga", "dns", "hunt"],
    firstSeen: iso(60 * 24 * 2),
    lastSeen: iso(11),
  },
  {
    id: "ioc-hash-lsass-dump-tool",
    type: "hash",
    value: "0f343b0931126a20f133d67c2b018a3b58f1d7d3f52e6f01dcf45d8aa0b8b2f1",
    sourceFeed: "URLhaus malware hashes",
    confidence: 91,
    tags: ["credential-access", "tooling"],
    firstSeen: iso(60 * 24 * 12),
    lastSeen: iso(6),
    expiry: iso(-60 * 24 * 30),
  },
];

export const threatIntelFeeds: ThreatIntelFeed[] = [
  {
    id: "feed-otx",
    name: "AlienVault OTX pulses",
    type: "OTX",
    url: "https://otx.alienvault.com/api/v1/pulses/subscribed",
    enabled: true,
    lastRunAt: iso(18),
    status: "healthy",
    indicatorCount: 12418,
  },
  {
    id: "feed-urlhaus",
    name: "URLhaus malware URLs",
    type: "URLhaus",
    url: "https://urlhaus.abuse.ch/downloads/csv_recent/",
    enabled: true,
    lastRunAt: iso(42),
    status: "healthy",
    indicatorCount: 2310,
  },
  {
    id: "feed-misp",
    name: "MISP tenant feed",
    type: "MISP",
    url: "https://misp.internal/events/restSearch",
    enabled: false,
    status: "paused",
    indicatorCount: 0,
  },
  {
    id: "feed-custom",
    name: "Executive allow and watch list",
    type: "CSV",
    url: "https://feeds.example.local/tawny-watch.csv",
    enabled: true,
    lastRunAt: iso(60 * 8),
    status: "stale",
    indicatorCount: 86,
  },
];

export const kelpieConfig: KelpieIntegrationConfig = {
  enabled: true,
  baseUrl: process.env.KELPIE_BASE_URL ?? "http://localhost:3000",
  tokenConfigured: Boolean(process.env.KELPIE_API_TOKEN),
  dedupeBy: "externalRef",
  syncFields: ["status", "assignee", "severity", "observables", "comments"],
};

export const deliveryLog: IntegrationDelivery[] = [
  {
    id: "delivery-kelpie-9001",
    channel: "kelpie",
    target: "/api/v1/alerts",
    state: "delivered",
    attempts: 1,
    lastAttemptAt: iso(5),
    externalRef: "tawny-alert-9001",
  },
  {
    id: "delivery-slack-9002",
    channel: "slack",
    target: "#soc-alerts",
    state: "delivered",
    attempts: 1,
    lastAttemptAt: iso(17),
  },
  {
    id: "delivery-sentinel-9003",
    channel: "sentinel",
    target: "Log Analytics workspace",
    state: "retrying",
    attempts: 2,
    lastAttemptAt: iso(31),
    error: "429 rate limited by workspace ingestion endpoint",
  },
];

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

export function extractAlertContext(alert: SocAlert) {
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
    tiMatches: alert.tiMatches ?? threatIntelMatches.filter((ioc) => {
      const haystack = JSON.stringify(alert.payload).toLowerCase();
      return haystack.includes(ioc.value.toLowerCase()) || alert.mitreTechniques.some((technique) => ioc.tags.join(" ").includes(technique.toLowerCase()));
    }),
  };
}

export async function getSocData() {
  const [alerts, events] = await Promise.all([listAlerts(), listEvents()]);
  const enrichedAlerts = alerts.map(extractAlertContext).sort((a, b) => severityRank[b.severity] - severityRank[a.severity] || Date.parse(b.timestamp) - Date.parse(a.timestamp));
  const incidents = buildIncidents(enrichedAlerts);
  return {
    alerts: enrichedAlerts,
    events,
    incidents,
    rules: sigmaRules,
    playbooks,
    threatIntelMatches,
    threatIntelFeeds,
    kelpieConfig,
    deliveryLog,
    overview: buildOverview(enrichedAlerts, incidents),
  };
}

function buildTimeline(alert: SocAlert, caseId: string): SocTimelineItem[] {
  return [
    {
      id: `${caseId}-tl-1`,
      actor: "Tawny-SOC",
      action: "Incident created",
      at: alert.timestamp,
      detail: `Grouped from ${alert.title} on ${alert.hostname ?? "unknown host"}.`,
    },
    {
      id: `${caseId}-tl-2`,
      actor: "AI triage",
      action: "Recommended playbook",
      at: iso(4),
      detail: alert.aiSummary,
    },
  ];
}

function buildTasks(alert: SocAlert): SocTask[] {
  const selected = playbooks.find((playbook) => playbook.id === alert.recommendedPlaybook) ?? playbooks[0];
  return selected.phases.slice(0, 4).map((phase, index) => ({
    id: `${alert.id}-task-${index + 1}`,
    title: phase.name,
    owner: phase.owner,
    status: index === 0 ? "doing" : "todo",
    dueAt: iso(-(index + 1) * 45),
    requiredEvidence: phase.actions.slice(0, 2),
    responseAction: phase.actions.find((action) => action.toLowerCase().includes("isolation")),
  }));
}

export function buildIncidents(alerts: SocAlert[]): SocIncident[] {
  return alerts.slice(0, 6).map((alert, index) => {
    const caseId = `case-${alert.id.replace(/^alert-/, "")}`;
    return {
      id: caseId,
      tenantId: alert.tenantId ?? "demo-tenant",
      number: `SOC-${String(1042 + index).padStart(5, "0")}`,
      title: `${alert.title} on ${alert.hostname ?? "unknown host"}`,
      severity: alert.severity,
      priority: alert.severity === "critical" ? "P1" : alert.severity === "high" ? "P2" : "P3",
      status: index === 0 ? "investigating" : index === 1 ? "triaging" : "open",
      assignee: index === 0 ? "A. Chen" : index === 1 ? "M. Singh" : undefined,
      tags: ["tawny", "edr-native", ...(alert.mitreTechniques.length ? ["mitre-mapped"] : [])],
      tlp: "amber",
      pap: "green",
      classification: index === 0 ? "true_positive" : "undetermined",
      mitreTechniques: alert.mitreTechniques,
      observables: alert.tiMatches ?? [],
      linkedHosts: alert.hostname ? [alert.hostname] : [],
      linkedAlertIds: [alert.id],
      kelpieCaseId: index === 0 ? "KEL-2407" : undefined,
      kelpieUrl: index === 0 ? `${kelpieConfig.baseUrl}/cases/KEL-2407` : undefined,
      kelpieSyncStatus: index === 0 ? "synced" : index === 1 ? "stale" : "not_synced",
      createdAt: alert.timestamp,
      updatedAt: iso(index * 16 + 2),
      timeline: buildTimeline(alert, caseId),
      tasks: buildTasks(alert),
      comments: [
        {
          id: `${caseId}-comment-1`,
          author: "A. Chen",
          body: "Validated the source host and queued nearby process telemetry for review.",
          createdAt: iso(3),
        },
      ],
    };
  });
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
    trend: [
      { label: "08:00", alerts: 2, cases: 0 },
      { label: "10:00", alerts: 5, cases: 1 },
      { label: "12:00", alerts: 3, cases: 1 },
      { label: "14:00", alerts: 9, cases: 2 },
      { label: "16:00", alerts: 6, cases: 1 },
      { label: "Now", alerts: Math.max(1, alerts.length), cases: Math.max(0, incidents.length) },
    ],
    needsAttention: [
      `${criticalHigh} critical or high alerts need review`,
      `${alerts.length - assignedAlerts} alerts are unassigned`,
      `${threatIntelMatches.length} threat intel matches should be linked to cases`,
      kelpieConfig.tokenConfigured ? "Kelpie sync token is configured" : "Kelpie API token is not configured",
    ],
  };
}
