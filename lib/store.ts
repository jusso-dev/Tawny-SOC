import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { desc } from "drizzle-orm";
import { matchRules, normalizeSeverity, topSeverity, triageSummary } from "@/lib/detection";
import { db, schema } from "@/lib/db/client";
import type { IngestPayload, SocAlert, SocEvent } from "@/lib/types";

const runtimeDir = path.join(process.cwd(), "data", "runtime");
const eventsPath = path.join(runtimeDir, "events.json");
const alertsPath = path.join(runtimeDir, "alerts.json");

async function readJson<T>(filePath: string, fallback: T): Promise<T> {
  try {
    const raw = await readFile(filePath, "utf8");
    return JSON.parse(raw) as T;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return fallback;
    throw err;
  }
}

async function writeJson<T>(filePath: string, value: T) {
  await mkdir(runtimeDir, { recursive: true });
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function fromDbEvent(row: typeof schema.socEvent.$inferSelect): SocEvent {
  return {
    id: row.id,
    source: row.source as SocEvent["source"],
    kind: row.kind as SocEvent["kind"],
    title: row.title,
    severity: row.severity,
    status: row.status as SocEvent["status"],
    timestamp: row.timestamp.toISOString(),
    tenantId: row.tenantId ?? undefined,
    agentId: row.agentId ?? undefined,
    hostname: row.hostname ?? undefined,
    os: row.os ?? undefined,
    eventType: row.eventType ?? undefined,
    telemetryId: row.telemetryId ? Number(row.telemetryId) : undefined,
    alertId: row.alertId ? Number(row.alertId) : undefined,
    ruleId: row.ruleId ?? undefined,
    payload: row.payload,
    matchedRules: row.matchedRules,
    mitreTechniques: row.mitreTechniques,
  };
}

function fromDbAlert(row: typeof schema.socAlert.$inferSelect): SocAlert {
  return {
    ...fromDbEvent({
      ...row,
      kind: "alert",
    } as typeof schema.socEvent.$inferSelect),
    kind: "alert",
    confidence: Number(row.confidence),
    aiSummary: row.aiSummary,
    recommendedPlaybook: row.recommendedPlaybook,
  };
}

function id(prefix: string, sourceId?: unknown) {
  const suffix = sourceId ? String(sourceId) : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `${prefix}-${suffix}`;
}

function extractTimestamp(record: Record<string, unknown>, fallback?: string) {
  return String(
    record.created_at
      ?? record.occurred_at
      ?? record.received_at
      ?? fallback
      ?? new Date().toISOString(),
  );
}

function cleanText(value: unknown, fallback: string) {
  const text = typeof value === "string" ? value.trim() : "";
  return text.length > 0 ? text : fallback;
}

export async function listEvents() {
  try {
    const rows = await db.select().from(schema.socEvent).orderBy(desc(schema.socEvent.timestamp)).limit(1000);
    return rows.map(fromDbEvent);
  } catch {
    const events = await readJson<SocEvent[]>(eventsPath, []);
    return events.sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp));
  }
}

export async function listAlerts() {
  try {
    const rows = await db.select().from(schema.socAlert).orderBy(desc(schema.socAlert.timestamp)).limit(500);
    return rows.map(fromDbAlert);
  } catch {
    const alerts = await readJson<SocAlert[]>(alertsPath, []);
    return alerts.sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp));
  }
}

export async function clearRuntimeStore() {
  await writeJson(eventsPath, []);
  await writeJson(alertsPath, []);
}

export async function ingestTawny(payload: IngestPayload) {
  const existingEvents = await readJson<SocEvent[]>(eventsPath, []);
  const existingAlerts = await readJson<SocAlert[]>(alertsPath, []);
  const now = payload.sent_at ?? new Date().toISOString();
  const agent = payload.agent ?? {};
  const telemetryById = payload.telemetry_events ?? {};

  const nextEvents: SocEvent[] = [];
  const nextAlerts: SocAlert[] = [];

  for (const rawAlert of payload.alerts ?? []) {
    const telemetryId = Number(rawAlert.telemetry_event_id ?? rawAlert.telemetryEventId ?? 0);
    const telemetry = telemetryById[String(telemetryId)] ?? {};
    const mergedPayload = { alert: rawAlert, telemetry };
    const explicitSeverity = normalizeSeverity(rawAlert.alert_severity ?? rawAlert.severity);
    const matches = matchRules(
      mergedPayload,
      String(telemetry.event_type ?? telemetry.eventType ?? ""),
      String(rawAlert.rule_id ?? rawAlert.alert_rule_id ?? ""),
    );
    const severity = matches.length ? topSeverity([explicitSeverity, ...matches.map((rule) => rule.severity)]) : explicitSeverity;
    const title = cleanText(rawAlert.alert_title ?? rawAlert.title, "Tawny alert");
    const triage = triageSummary({
      title,
      hostname: agent.hostname,
      severity,
      rules: matches,
      eventType: String(telemetry.event_type ?? telemetry.eventType ?? ""),
    });

    nextAlerts.push({
      id: id("alert", rawAlert.alert_id ?? rawAlert.id),
      source: "tawny",
      kind: "alert",
      title,
      severity,
      status: "open",
      timestamp: extractTimestamp(rawAlert, now),
      tenantId: cleanText(agent.tenant_id ?? payload.tenant_id, ""),
      agentId: cleanText(agent.id, ""),
      hostname: cleanText(agent.hostname, "unknown-host"),
      os: cleanText(agent.operating_system, ""),
      eventType: cleanText(telemetry.event_type ?? telemetry.eventType, "unknown"),
      telemetryId: Number.isFinite(telemetryId) ? telemetryId : undefined,
      alertId: Number(rawAlert.alert_id ?? rawAlert.id ?? 0) || undefined,
      ruleId: cleanText(rawAlert.rule_id ?? rawAlert.alert_rule_id, ""),
      payload: mergedPayload,
      matchedRules: matches.map((rule) => rule.id),
      mitreTechniques: triage.techniques,
      confidence: triage.confidence,
      aiSummary: triage.aiSummary,
      recommendedPlaybook: triage.recommendedPlaybook,
    });
  }

  for (const rawEvent of payload.events ?? []) {
    const eventType = cleanText(rawEvent.event_type ?? rawEvent.eventType, "telemetry");
    const matches = matchRules(rawEvent, eventType);
    const severity = matches.length ? topSeverity(matches.map((rule) => rule.severity)) : "low";
    nextEvents.push({
      id: id("event", rawEvent.telemetry_id ?? rawEvent.id),
      source: "tawny",
      kind: "telemetry",
      title: matches[0]?.title ?? `Tawny ${eventType}`,
      severity,
      status: "open",
      timestamp: extractTimestamp(rawEvent, now),
      tenantId: cleanText(agent.tenant_id ?? payload.tenant_id, ""),
      agentId: cleanText(agent.id, ""),
      hostname: cleanText(agent.hostname, "unknown-host"),
      os: cleanText(agent.operating_system, ""),
      eventType,
      telemetryId: Number(rawEvent.telemetry_id ?? rawEvent.id ?? 0) || undefined,
      payload: rawEvent,
      matchedRules: matches.map((rule) => rule.id),
      mitreTechniques: [...new Set(matches.flatMap((rule) => rule.mitreTechniques))],
    });
  }

  const mergedEvents = [...nextEvents, ...existingEvents].slice(0, 1000);
  const mergedAlerts = [...nextAlerts, ...existingAlerts].slice(0, 500);
  try {
    if (nextEvents.length > 0) {
      await db.insert(schema.socEvent).values(nextEvents.map((event) => ({
        ...event,
        timestamp: new Date(event.timestamp),
        telemetryId: event.telemetryId?.toString(),
        alertId: event.alertId?.toString(),
      }))).onConflictDoNothing();
    }
    if (nextAlerts.length > 0) {
      await db.insert(schema.socAlert).values(nextAlerts.map((alert) => ({
        ...alert,
        timestamp: new Date(alert.timestamp),
        telemetryId: alert.telemetryId?.toString(),
        alertId: alert.alertId?.toString(),
        confidence: alert.confidence.toString(),
      }))).onConflictDoNothing();
    }
  } catch {
    await writeJson(eventsPath, mergedEvents);
    await writeJson(alertsPath, mergedAlerts);
  }

  return {
    accepted: nextEvents.length + nextAlerts.length,
    alerts: nextAlerts.length,
    events: nextEvents.length,
  };
}
