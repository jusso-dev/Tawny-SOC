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
