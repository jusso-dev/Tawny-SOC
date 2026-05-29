import { boolean, index, integer, jsonb, pgTable, text, timestamp, uniqueIndex } from "drizzle-orm/pg-core";
import type { IncidentStatus, KelpieSyncStatus, Severity } from "@/lib/types";

export const socEvent = pgTable("soc_event", {
  id: text("id").primaryKey(),
  source: text("source").notNull(),
  kind: text("kind").notNull(),
  title: text("title").notNull(),
  severity: text("severity").$type<Severity>().notNull(),
  status: text("status").notNull(),
  timestamp: timestamp("timestamp", { withTimezone: true }).notNull(),
  tenantId: text("tenant_id"),
  agentId: text("agent_id"),
  hostname: text("hostname"),
  os: text("os"),
  eventType: text("event_type"),
  telemetryId: text("telemetry_id"),
  alertId: text("alert_id"),
  ruleId: text("rule_id"),
  payload: jsonb("payload").notNull(),
  matchedRules: jsonb("matched_rules").$type<string[]>().notNull().default([]),
  mitreTechniques: jsonb("mitre_techniques").$type<string[]>().notNull().default([]),
}, (table) => [
  index("soc_event_timestamp_idx").on(table.timestamp),
  index("soc_event_hostname_idx").on(table.hostname),
]);

export const socAlert = pgTable("soc_alert", {
  id: text("id").primaryKey(),
  source: text("source").notNull(),
  kind: text("kind").notNull(),
  title: text("title").notNull(),
  severity: text("severity").$type<Severity>().notNull(),
  status: text("status").notNull(),
  timestamp: timestamp("timestamp", { withTimezone: true }).notNull(),
  tenantId: text("tenant_id"),
  agentId: text("agent_id"),
  hostname: text("hostname"),
  os: text("os"),
  eventType: text("event_type"),
  assignee: text("assignee"),
  telemetryId: text("telemetry_id"),
  alertId: text("alert_id"),
  ruleId: text("rule_id"),
  payload: jsonb("payload").notNull(),
  matchedRules: jsonb("matched_rules").$type<string[]>().notNull().default([]),
  mitreTechniques: jsonb("mitre_techniques").$type<string[]>().notNull().default([]),
  confidence: text("confidence").notNull(),
  aiSummary: text("ai_summary").notNull(),
  recommendedPlaybook: text("recommended_playbook").notNull(),
}, (table) => [
  index("soc_alert_timestamp_idx").on(table.timestamp),
  index("soc_alert_status_idx").on(table.status),
  index("soc_alert_hostname_idx").on(table.hostname),
]);

export const socIncident = pgTable("soc_incident", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  number: text("number").notNull(),
  title: text("title").notNull(),
  severity: text("severity").$type<Severity>().notNull(),
  priority: text("priority").notNull(),
  status: text("status").$type<IncidentStatus>().notNull(),
  assignee: text("assignee"),
  tags: jsonb("tags").$type<string[]>().notNull().default([]),
  tlp: text("tlp").notNull().default("amber"),
  pap: text("pap").notNull().default("green"),
  classification: text("classification").notNull().default("undetermined"),
  mitreTechniques: jsonb("mitre_techniques").$type<string[]>().notNull().default([]),
  observables: jsonb("observables").notNull().default([]),
  linkedHosts: jsonb("linked_hosts").$type<string[]>().notNull().default([]),
  kelpieCaseId: text("kelpie_case_id"),
  kelpieUrl: text("kelpie_url"),
  kelpieSyncStatus: text("kelpie_sync_status").$type<KelpieSyncStatus>().notNull().default("not_synced"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull(),
  closedAt: timestamp("closed_at", { withTimezone: true }),
}, (table) => [
  index("soc_incident_tenant_status_idx").on(table.tenantId, table.status),
  index("soc_incident_number_idx").on(table.tenantId, table.number),
]);

export const socIncidentAlert = pgTable("soc_incident_alert", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  incidentId: text("incident_id").notNull().references(() => socIncident.id, { onDelete: "cascade" }),
  alertId: text("alert_id").notNull().references(() => socAlert.id, { onDelete: "cascade" }),
  addedBy: text("added_by"),
  addedAt: timestamp("added_at", { withTimezone: true }).notNull(),
}, (table) => [
  index("soc_incident_alert_tenant_idx").on(table.tenantId, table.incidentId),
]);

export const socTimeline = pgTable("soc_timeline", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  incidentId: text("incident_id").references(() => socIncident.id, { onDelete: "cascade" }),
  alertId: text("alert_id").references(() => socAlert.id, { onDelete: "cascade" }),
  actor: text("actor").notNull(),
  action: text("action").notNull(),
  detail: text("detail").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
}, (table) => [
  index("soc_timeline_tenant_created_idx").on(table.tenantId, table.createdAt),
]);

export const socComment = pgTable("soc_comment", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  incidentId: text("incident_id").references(() => socIncident.id, { onDelete: "cascade" }),
  alertId: text("alert_id").references(() => socAlert.id, { onDelete: "cascade" }),
  author: text("author").notNull(),
  body: text("body").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
}, (table) => [
  index("soc_comment_tenant_created_idx").on(table.tenantId, table.createdAt),
]);

export const socThreatIntelFeed = pgTable("soc_threat_intel_feed", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  name: text("name").notNull(),
  type: text("type").notNull(),
  url: text("url").notNull(),
  enabled: boolean("enabled").notNull().default(true),
  status: text("status").notNull().default("paused"),
  indicatorCount: integer("indicator_count").notNull().default(0),
  lastRunAt: timestamp("last_run_at", { withTimezone: true }),
  lastError: text("last_error"),
}, (table) => [
  index("soc_ti_feed_tenant_status_idx").on(table.tenantId, table.status),
]);

export const socThreatIntelIndicator = pgTable("soc_threat_intel_indicator", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  feedId: text("feed_id").notNull().references(() => socThreatIntelFeed.id, { onDelete: "cascade" }),
  type: text("type").notNull(),
  value: text("value").notNull(),
  sourceFeed: text("source_feed").notNull(),
  confidence: integer("confidence").notNull().default(80),
  tags: jsonb("tags").$type<string[]>().notNull().default([]),
  firstSeen: timestamp("first_seen", { withTimezone: true }).notNull(),
  lastSeen: timestamp("last_seen", { withTimezone: true }).notNull(),
  expiresAt: timestamp("expires_at", { withTimezone: true }),
}, (table) => [
  index("soc_ti_indicator_tenant_type_idx").on(table.tenantId, table.type),
  index("soc_ti_indicator_feed_idx").on(table.feedId),
  uniqueIndex("soc_ti_indicator_tenant_feed_value_idx").on(table.tenantId, table.feedId, table.value),
]);

export const socPlaybook = pgTable("soc_playbook", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  name: text("name").notNull(),
  description: text("description").notNull(),
  severity: text("severity").$type<Severity>().notNull(),
  owner: text("owner").notNull(),
  steps: jsonb("steps").notNull().default([]),
  enabled: boolean("enabled").notNull().default(true),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull(),
}, (table) => [
  index("soc_playbook_tenant_enabled_idx").on(table.tenantId, table.enabled),
]);

export const socTask = pgTable("soc_task", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  incidentId: text("incident_id").notNull().references(() => socIncident.id, { onDelete: "cascade" }),
  title: text("title").notNull(),
  owner: text("owner").notNull(),
  status: text("status").notNull(),
  dueAt: timestamp("due_at", { withTimezone: true }),
  requiredEvidence: jsonb("required_evidence").$type<string[]>().notNull().default([]),
  responseAction: text("response_action"),
}, (table) => [
  index("soc_task_tenant_status_idx").on(table.tenantId, table.status),
]);

export const socKelpieIntegration = pgTable("soc_kelpie_integration", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  baseUrl: text("base_url").notNull(),
  tokenReference: text("token_reference"),
  enabled: boolean("enabled").notNull().default(false),
  dedupeBy: text("dedupe_by").notNull().default("externalRef"),
  syncFields: jsonb("sync_fields").$type<string[]>().notNull().default([]),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull(),
}, (table) => [
  index("soc_kelpie_tenant_idx").on(table.tenantId),
]);

export const socDeliveryLog = pgTable("soc_delivery_log", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  channel: text("channel").notNull(),
  target: text("target").notNull(),
  state: text("state").notNull(),
  attempts: integer("attempts").notNull().default(0),
  lastAttemptAt: timestamp("last_attempt_at", { withTimezone: true }).notNull(),
  error: text("error"),
  externalRef: text("external_ref"),
}, (table) => [
  index("soc_delivery_tenant_state_idx").on(table.tenantId, table.state),
]);

export const socSetting = pgTable("soc_setting", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  key: text("key").notNull(),
  value: jsonb("value").$type<Record<string, unknown>>().notNull().default({}),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull(),
}, (table) => [
  index("soc_setting_tenant_key_idx").on(table.tenantId, table.key),
]);

export const socIngestSource = pgTable("soc_ingest_source", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  name: text("name").notNull(),
  sourceType: text("source_type").notNull(),
  authMode: text("auth_mode").notNull().default("shared-secret"),
  parser: text("parser").notNull().default("generic-json"),
  status: text("status").notNull().default("untested"),
  lastSeenAt: timestamp("last_seen_at", { withTimezone: true }),
  lastError: text("last_error"),
  throughput: integer("throughput").notNull().default(0),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull(),
}, (table) => [
  index("soc_ingest_source_tenant_status_idx").on(table.tenantId, table.status),
]);

export const socIngestDeadLetter = pgTable("soc_ingest_dead_letter", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  sourceId: text("source_id").references(() => socIngestSource.id, { onDelete: "set null" }),
  reason: text("reason").notNull(),
  payload: jsonb("payload").notNull(),
  status: text("status").notNull().default("open"),
  receivedAt: timestamp("received_at", { withTimezone: true }).notNull(),
}, (table) => [
  index("soc_ingest_dead_letter_tenant_status_idx").on(table.tenantId, table.status),
]);

export const socConnector = pgTable("soc_connector", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  catalogId: text("catalog_id").notNull(),
  provider: text("provider").notNull(),
  category: text("category").notNull(),
  name: text("name").notNull(),
  authType: text("auth_type").notNull(),
  status: text("status").notNull().default("untested"),
  enabled: boolean("enabled").notNull().default(false),
  schedule: text("schedule").notNull().default("manual"),
  config: jsonb("config").$type<Record<string, unknown>>().notNull().default({}),
  credentialReference: text("credential_reference"),
  lastTestAt: timestamp("last_test_at", { withTimezone: true }),
  lastSyncAt: timestamp("last_sync_at", { withTimezone: true }),
  lastError: text("last_error"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull(),
}, (table) => [
  index("soc_connector_tenant_status_idx").on(table.tenantId, table.status),
  index("soc_connector_catalog_idx").on(table.catalogId),
]);

export const socReport = pgTable("soc_report", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  framework: text("framework").notNull(),
  title: text("title").notNull(),
  status: text("status").notNull().default("draft"),
  schedule: text("schedule").notNull().default("manual"),
  evidence: jsonb("evidence").$type<string[]>().notNull().default([]),
  generatedAt: timestamp("generated_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
}, (table) => [
  index("soc_report_tenant_framework_idx").on(table.tenantId, table.framework),
]);

export const socRetentionPolicy = pgTable("soc_retention_policy", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  target: text("target").notNull(),
  hotDays: integer("hot_days").notNull().default(30),
  archiveDays: integer("archive_days").notNull().default(180),
  deleteAfterDays: integer("delete_after_days").notNull().default(365),
  preserveCaseEvidence: boolean("preserve_case_evidence").notNull().default(true),
  legalHold: boolean("legal_hold").notNull().default(false),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull(),
}, (table) => [
  uniqueIndex("soc_retention_policy_tenant_target_idx").on(table.tenantId, table.target),
]);

export const socApiToken = pgTable("soc_api_token", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  name: text("name").notNull(),
  tokenHash: text("token_hash").notNull().unique(),
  tokenPrefix: text("token_prefix").notNull(),
  role: text("role").notNull().default("member"),
  scopes: jsonb("scopes").$type<string[]>().notNull().default([]),
  status: text("status").notNull().default("active"),
  lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
  expiresAt: timestamp("expires_at", { withTimezone: true }),
  createdBy: text("created_by"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull(),
  revokedAt: timestamp("revoked_at", { withTimezone: true }),
}, (table) => [
  index("soc_api_token_tenant_status_idx").on(table.tenantId, table.status),
  index("soc_api_token_hash_idx").on(table.tokenHash),
]);

export const socEvidence = pgTable("soc_evidence", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  incidentId: text("incident_id").references(() => socIncident.id, { onDelete: "cascade" }),
  alertId: text("alert_id").references(() => socAlert.id, { onDelete: "cascade" }),
  evidenceType: text("evidence_type").notNull(),
  title: text("title").notNull(),
  sourceRef: text("source_ref"),
  checksum: text("checksum"),
  metadata: jsonb("metadata").$type<Record<string, unknown>>().notNull().default({}),
  createdBy: text("created_by").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
}, (table) => [
  index("soc_evidence_tenant_incident_idx").on(table.tenantId, table.incidentId),
]);

export const socAuditLog = pgTable("soc_audit_log", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  actorId: text("actor_id"),
  actorName: text("actor_name"),
  action: text("action").notNull(),
  resourceType: text("resource_type").notNull(),
  resourceId: text("resource_id"),
  detail: text("detail"),
  metadata: jsonb("metadata").$type<Record<string, unknown>>().notNull().default({}),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
}, (table) => [
  index("soc_audit_log_tenant_created_idx").on(table.tenantId, table.createdAt),
]);
