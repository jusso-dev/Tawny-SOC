export type Severity = "critical" | "high" | "medium" | "low";
export type AlertStatus = "open" | "triaging" | "investigating" | "suppressed" | "dismissed" | "resolved";
export type IncidentStatus = "new" | "open" | "triaging" | "investigating" | "contained" | "eradicated" | "recovered" | "closed";
export type KelpieSyncStatus = "not_synced" | "synced" | "failed" | "stale" | "conflict";

export type SocEvent = {
  id: string;
  source: "tawny" | "demo" | "manual";
  kind: "alert" | "telemetry";
  title: string;
  severity: Severity;
  status: AlertStatus | "acknowledged";
  timestamp: string;
  tenantId?: string;
  agentId?: string;
  hostname?: string;
  os?: string;
  eventType?: string;
  telemetryId?: number;
  alertId?: number;
  ruleId?: string;
  payload: unknown;
  matchedRules: string[];
  mitreTechniques: string[];
};

export type SocAlert = SocEvent & {
  kind: "alert";
  confidence: number;
  aiSummary: string;
  recommendedPlaybook: string;
  assignee?: string;
  user?: string;
  process?: string;
  commandLine?: string;
  externalIps?: string[];
  tiMatches?: ThreatIntelMatch[];
  relatedCaseIds?: string[];
};

export type SigmaRule = {
  id: string;
  title: string;
  status: "stable" | "test" | "experimental";
  severity: Severity;
  source: string;
  logsource: {
    product: string;
    category?: string;
    service?: string;
  };
  mitreTechniques: string[];
  tags: string[];
  description: string;
  falsePositives: string[];
  detection: Record<string, unknown>;
  sigma: string;
};

export type Playbook = {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  agents: string[];
  triggers: string[];
  phases: Array<{
    name: string;
    owner: string;
    objective: string;
    actions: string[];
  }>;
};

export type ThreatIntelMatch = {
  id: string;
  type: "ip" | "domain" | "url" | "hash" | "email" | "file";
  value: string;
  sourceFeed: string;
  confidence: number;
  tags: string[];
  firstSeen: string;
  lastSeen: string;
  expiry?: string;
};

export type ThreatIntelFeed = {
  id: string;
  name: string;
  type: "STIX" | "OpenIOC" | "CSV" | "TXT" | "MISP" | "OTX" | "URLhaus" | "Custom URL";
  url: string;
  enabled: boolean;
  lastRunAt?: string;
  status: "healthy" | "failed" | "stale" | "paused";
  indicatorCount: number;
  lastError?: string;
};

export type SocIncident = {
  id: string;
  tenantId: string;
  number: string;
  title: string;
  severity: Severity;
  priority: "P1" | "P2" | "P3" | "P4";
  status: IncidentStatus;
  assignee?: string;
  tags: string[];
  tlp: "clear" | "green" | "amber" | "red";
  pap: "clear" | "green" | "amber" | "red";
  classification: "true_positive" | "benign_positive" | "false_positive" | "undetermined";
  mitreTechniques: string[];
  observables: ThreatIntelMatch[];
  linkedHosts: string[];
  linkedAlertIds: string[];
  kelpieCaseId?: string;
  kelpieUrl?: string;
  kelpieSyncStatus: KelpieSyncStatus;
  createdAt: string;
  updatedAt: string;
  timeline: SocTimelineItem[];
  tasks: SocTask[];
  comments: SocComment[];
};

export type SocTimelineItem = {
  id: string;
  actor: string;
  action: string;
  at: string;
  detail: string;
};

export type SocTask = {
  id: string;
  title: string;
  owner: string;
  status: "todo" | "doing" | "blocked" | "done";
  dueAt: string;
  requiredEvidence: string[];
  responseAction?: string;
};

export type SocComment = {
  id: string;
  author: string;
  body: string;
  createdAt: string;
};

export type KelpieIntegrationConfig = {
  enabled: boolean;
  baseUrl: string;
  tokenConfigured: boolean;
  dedupeBy: "externalRef";
  syncFields: string[];
};

export type IntegrationDelivery = {
  id: string;
  channel: "email" | "slack" | "webhook" | "sentinel" | "wazuh" | "kelpie";
  target: string;
  state: "queued" | "delivered" | "retrying" | "failed";
  attempts: number;
  lastAttemptAt: string;
  error?: string;
  externalRef?: string;
};

export type SuppressionRule = {
  id: string;
  tenantId: string;
  name: string;
  enabled: boolean;
  ruleId?: string;
  host?: string;
  user?: string;
  severity?: Severity;
  reason: string;
  expiresAt?: string;
};

export type IngestPayload = {
  source?: string;
  kind?: "alert_batch" | "telemetry_batch";
  sent_at?: string;
  tenant_id?: string;
  agent?: {
    id?: string;
    tenant_id?: string;
    hostname?: string;
    operating_system?: string;
    os_version?: string;
    architecture?: string;
    agent_version?: string;
  };
  alerts?: Array<Record<string, unknown>>;
  events?: Array<Record<string, unknown>>;
  telemetry_events?: Record<string, Record<string, unknown>>;
};
