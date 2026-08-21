import { randomUUID } from "node:crypto";
import { and, desc, eq } from "drizzle-orm";
import cron from "node-cron";
import { runDetectAgent } from "@/lib/ai/agents/detect";
import { runEnrichmentAgent } from "@/lib/ai/agents/enrichment";
import { runRespondAgent } from "@/lib/ai/agents/respond";
import { runTriageAgent } from "@/lib/ai/agents/triage";
import { huntTenant } from "@/lib/agent-api";
import { db, schema } from "@/lib/db/client";
import { playbooks } from "@/lib/rules";
import { listSigmaRules } from "@/lib/sigma";
import { extractAlertContext } from "@/lib/soc-domain";
import { listAlerts, listEvents, listThreatIntelMatches, recordAuditLog, type SocActor } from "@/lib/store";

export type AgentStep = {
  agent: "Detect" | "Triage" | "Hunt" | "Respond";
  status: "completed" | "failed";
  summary: string;
  engine: string;
  confidence?: number;
  evidence: string[];
  actions: string[];
  startedAt: string;
  completedAt: string;
};

export type AgentRun = {
  id: string;
  tenantId: string;
  alertId?: string;
  trigger: string;
  status: string;
  title: string;
  summary: string;
  steps: AgentStep[];
  findings: Array<Record<string, unknown>>;
  initiatedBy: string;
  startedAt: string;
  completedAt?: string;
};

export type HuntSchedule = {
  id: string;
  tenantId: string;
  name: string;
  hypothesis: string;
  query: string;
  schedule: string;
  timezone: string;
  enabled: boolean;
  lastRunAt?: string;
  lastStatus: string;
  lastFindingCount: number;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
};

export async function runAgentMesh(input: { tenantId: string; alertId: string; actorName: string; trigger?: string }) {
  if (input.trigger === "automatic-ingest") {
    const [existing] = await db.select().from(schema.socAgentRun).where(and(
      eq(schema.socAgentRun.tenantId, input.tenantId),
      eq(schema.socAgentRun.alertId, input.alertId),
      eq(schema.socAgentRun.trigger, "automatic-ingest"),
    )).limit(1);
    if (existing) return { id: existing.id, status: existing.status, summary: existing.summary, steps: existing.steps as AgentStep[], findings: existing.findings };
  }
  const startedAt = new Date();
  const runId = `agent-run-${randomUUID()}`;
  const alerts = await listAlerts(input.tenantId);
  const rawAlert = alerts.find((alert) => alert.id === input.alertId);
  if (!rawAlert) throw new Error("Alert not found.");
  const [events, indicators, sigmaRules] = await Promise.all([
    listEvents(input.tenantId),
    listThreatIntelMatches(input.tenantId),
    listSigmaRules(),
  ]);
  const alert = extractAlertContext(rawAlert, indicators);
  const matchedRules = sigmaRules.filter((rule) => alert.matchedRules.includes(rule.id));
  await db.insert(schema.socAgentRun).values({
    id: runId,
    tenantId: input.tenantId,
    alertId: alert.id,
    trigger: input.trigger ?? "manual",
    status: "running",
    title: alert.title,
    initiatedBy: input.actorName,
    startedAt,
  });

  try {
    const detectStarted = new Date().toISOString();
    const detect = await runDetectAgent(input.tenantId, { alert, related: [...alerts, ...events].filter((event) => event.id !== alert.id), matchedRules });
    const triageStarted = new Date().toISOString();
    const triage = await runTriageAgent(input.tenantId, { alert, matchedRules, playbooks });
    const huntStarted = new Date().toISOString();
    const hunt = await runEnrichmentAgent(input.tenantId, { alert, indicators: alert.tiMatches ?? [] });
    const respondStarted = new Date().toISOString();
    const respond = await runRespondAgent(input.tenantId, { alert, triage, hunt, playbooks });
    const completedAt = new Date();
    const steps: AgentStep[] = [
      { agent: "Detect", status: "completed", summary: detect.summary, engine: detect.meta.engine, confidence: detect.confidence, evidence: detect.signalIds, actions: detect.attackChain, startedAt: detectStarted, completedAt: triageStarted },
      { agent: "Triage", status: "completed", summary: triage.summary, engine: triage.meta.engine, confidence: triage.confidence, evidence: triage.rationale, actions: triage.recommendedActions, startedAt: triageStarted, completedAt: huntStarted },
      { agent: "Hunt", status: "completed", summary: hunt.summary, engine: hunt.meta.engine, evidence: hunt.indicators.map((item) => `${item.type}:${item.value}`), actions: hunt.huntQueries, startedAt: huntStarted, completedAt: respondStarted },
      { agent: "Respond", status: "completed", summary: respond.summary, engine: respond.meta.engine, evidence: respond.verificationSteps, actions: [...respond.immediateActions, ...respond.approvalGatedActions.map((action) => `Approval required: ${action}`)], startedAt: respondStarted, completedAt: completedAt.toISOString() },
    ];
    const findings = [
      { type: "verdict", value: triage.verdict, confidence: triage.confidence },
      { type: "playbook", value: respond.playbookId },
      { type: "attack-chain", value: detect.attackChain },
      { type: "hunt-queries", value: hunt.huntQueries },
    ];
    const summary = `${triage.verdict.replace("_", " ")} at ${Math.round(triage.confidence * 100)}% confidence. ${respond.summary}`;
    await db.update(schema.socAgentRun).set({ status: "completed", summary, steps, findings, completedAt }).where(eq(schema.socAgentRun.id, runId));
    await recordAuditLog({ tenantId: input.tenantId, action: "agent.mesh.completed", resourceType: "agent-run", resourceId: runId, detail: summary });
    return { id: runId, status: "completed", summary, steps, findings };
  } catch (error) {
    const detail = error instanceof Error ? error.message : "Agent mesh failed.";
    await db.update(schema.socAgentRun).set({ status: "failed", summary: detail, completedAt: new Date() }).where(eq(schema.socAgentRun.id, runId));
    throw error;
  }
}

export async function listAgentRuns(tenantId: string, limit = 20): Promise<AgentRun[]> {
  const rows = await db.select().from(schema.socAgentRun).where(eq(schema.socAgentRun.tenantId, tenantId)).orderBy(desc(schema.socAgentRun.startedAt)).limit(limit);
  return rows.map((row) => ({
    id: row.id, tenantId: row.tenantId, alertId: row.alertId ?? undefined, trigger: row.trigger, status: row.status,
    title: row.title, summary: row.summary, steps: row.steps as AgentStep[], findings: row.findings,
    initiatedBy: row.initiatedBy, startedAt: row.startedAt.toISOString(), completedAt: row.completedAt?.toISOString(),
  }));
}

export async function listHuntSchedules(tenantId?: string): Promise<HuntSchedule[]> {
  const rows = tenantId
    ? await db.select().from(schema.socHuntSchedule).where(eq(schema.socHuntSchedule.tenantId, tenantId)).orderBy(desc(schema.socHuntSchedule.createdAt))
    : await db.select().from(schema.socHuntSchedule).where(eq(schema.socHuntSchedule.enabled, true));
  return rows.map(mapHuntSchedule);
}

export async function createHuntSchedule(input: { tenantId: string; name: string; hypothesis: string; query: string; schedule: string; timezone: string; actor: SocActor }) {
  if (!input.name.trim() || !input.hypothesis.trim() || !input.query.trim()) throw new Error("Name, hypothesis, and YAAQL query are required.");
  if (!cron.validate(input.schedule)) throw new Error("Invalid five-field cron schedule.");
  try { new Intl.DateTimeFormat("en-AU", { timeZone: input.timezone }).format(); } catch { throw new Error("Invalid IANA timezone."); }
  const now = new Date();
  const row = {
    id: `hunt-schedule-${randomUUID()}`, tenantId: input.tenantId, name: input.name.trim(), hypothesis: input.hypothesis.trim(),
    query: input.query.trim(), schedule: input.schedule, timezone: input.timezone, enabled: true, createdBy: input.actor.name, createdAt: now, updatedAt: now,
  };
  await db.insert(schema.socHuntSchedule).values(row);
  await recordAuditLog({ tenantId: input.tenantId, actor: input.actor, action: "hunt.schedule.created", resourceType: "hunt-schedule", resourceId: row.id, detail: `${row.name}: ${row.schedule} ${row.timezone}` });
  return row.id;
}

export async function setHuntScheduleEnabled(tenantId: string, id: string, enabled: boolean, actor?: SocActor) {
  const [row] = await db.update(schema.socHuntSchedule).set({ enabled, updatedAt: new Date() })
    .where(and(eq(schema.socHuntSchedule.tenantId, tenantId), eq(schema.socHuntSchedule.id, id))).returning();
  if (!row) throw new Error("Hunt schedule not found.");
  await recordAuditLog({ tenantId, actor, action: enabled ? "hunt.schedule.resumed" : "hunt.schedule.paused", resourceType: "hunt-schedule", resourceId: id, detail: row.name });
}

export async function runHuntSchedule(tenantId: string, id: string, trigger = "manual") {
  const [row] = await db.select().from(schema.socHuntSchedule).where(and(eq(schema.socHuntSchedule.tenantId, tenantId), eq(schema.socHuntSchedule.id, id))).limit(1);
  if (!row) throw new Error("Hunt schedule not found.");
  const startedAt = new Date();
  const result = await huntTenant(tenantId, { q: row.query, limit: 250 });
  if (!result.ok) {
    await db.update(schema.socHuntSchedule).set({ lastRunAt: startedAt, lastStatus: "failed", updatedAt: new Date() }).where(eq(schema.socHuntSchedule.id, id));
    throw new Error(result.error?.message ?? "Scheduled hunt failed.");
  }
  const runId = `agent-run-${randomUUID()}`;
  const findings = result.records.slice(0, 50).map((record) => ({ id: record.id, title: record.title, severity: record.severity, timestamp: record.timestamp }));
  const summary = `${row.name} matched ${result.totalMatched} retained records for hypothesis: ${row.hypothesis}`;
  const completedAt = new Date();
  const step: AgentStep = { agent: "Hunt", status: "completed", summary, engine: "deterministic", evidence: findings.map((item) => String(item.id)), actions: [row.query], startedAt: startedAt.toISOString(), completedAt: completedAt.toISOString() };
  await db.transaction(async (tx) => {
    await tx.insert(schema.socAgentRun).values({ id: runId, tenantId, trigger: `hunt-schedule:${trigger}`, status: "completed", title: row.name, summary, steps: [step], findings, initiatedBy: trigger === "scheduled" ? "Hunt scheduler" : "Analyst", startedAt, completedAt });
    await tx.update(schema.socHuntSchedule).set({ lastRunAt: startedAt, lastStatus: "completed", lastFindingCount: result.totalMatched, updatedAt: completedAt }).where(eq(schema.socHuntSchedule.id, id));
  });
  return { id: runId, summary, findingCount: result.totalMatched };
}

export async function runDueHuntSchedules(now = new Date()) {
  const schedules = await listHuntSchedules();
  for (const schedule of schedules) {
    if (!cronMatches(schedule.schedule, schedule.timezone, now)) continue;
    if (schedule.lastRunAt && Math.floor(Date.parse(schedule.lastRunAt) / 60_000) === Math.floor(now.getTime() / 60_000)) continue;
    await runHuntSchedule(schedule.tenantId, schedule.id, "scheduled").catch(() => undefined);
  }
}

export function cronMatches(expression: string, timezone: string, date: Date) {
  const values = new Intl.DateTimeFormat("en-CA", { timeZone: timezone, minute: "2-digit", hour: "2-digit", day: "2-digit", month: "2-digit", weekday: "short", hourCycle: "h23" })
    .formatToParts(date).reduce<Record<string, string>>((out, part) => ({ ...out, [part.type]: part.value }), {});
  const current = [Number(values.minute), Number(values.hour), Number(values.day), Number(values.month), ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].indexOf(values.weekday)];
  return expression.trim().split(/\s+/).every((field, index) => cronFieldMatches(field, current[index]));
}

function cronFieldMatches(field: string, value: number) {
  return field.split(",").some((part) => {
    const [base, stepText] = part.split("/");
    const step = stepText ? Number(stepText) : 1;
    if (!Number.isInteger(step) || step < 1) return false;
    if (base === "*") return value % step === 0;
    const [startText, endText] = base.split("-");
    const start = Number(startText);
    const end = endText === undefined ? start : Number(endText);
    return Number.isInteger(start) && Number.isInteger(end) && value >= start && value <= end && (value - start) % step === 0;
  });
}

function mapHuntSchedule(row: typeof schema.socHuntSchedule.$inferSelect): HuntSchedule {
  return {
    id: row.id, tenantId: row.tenantId, name: row.name, hypothesis: row.hypothesis, query: row.query,
    schedule: row.schedule, timezone: row.timezone, enabled: row.enabled, lastRunAt: row.lastRunAt?.toISOString(),
    lastStatus: row.lastStatus, lastFindingCount: row.lastFindingCount, createdBy: row.createdBy,
    createdAt: row.createdAt.toISOString(), updatedAt: row.updatedAt.toISOString(),
  };
}
