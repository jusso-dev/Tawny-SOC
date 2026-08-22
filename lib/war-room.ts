import { randomUUID } from "node:crypto";
import { and, asc, desc, eq, inArray } from "drizzle-orm";
import cron from "node-cron";
import { isSocAgentId, socAgentProfiles, type SocAgentId } from "@/lib/ai/agents/catalog";
import { runSpecialistAgent } from "@/lib/ai/agents/specialist";
import { huntTenant } from "@/lib/agent-api";
import { agentWorkflows, defaultAgentWorkflowId, getAgentWorkflow } from "@/lib/agent-workflows";
import { db, schema } from "@/lib/db/client";
import { listSigmaRules } from "@/lib/sigma";
import { extractAlertContext } from "@/lib/soc-domain";
import { listAlerts, listEvents, listThreatIntelMatches, recordAuditLog, type SocActor } from "@/lib/store";

export type AgentStep = {
  agent: string;
  agentId?: SocAgentId;
  phaseId?: string;
  phaseName?: string;
  status: "completed" | "failed";
  summary: string;
  engine: string;
  confidence?: number;
  evidence: string[];
  actions: string[];
  handoff?: string[];
  tools?: string[];
  approvalRequired?: boolean;
  startedAt: string;
  completedAt: string;
};

export type AgentRun = {
  id: string;
  tenantId: string;
  alertId?: string;
  workflowId?: string;
  trigger: string;
  status: string;
  title: string;
  summary: string;
  steps: AgentStep[];
  events: AgentRoomEvent[];
  findings: Array<Record<string, unknown>>;
  initiatedBy: string;
  startedAt: string;
  completedAt?: string;
};

export type AgentRoomEvent = {
  id: string;
  sequence: number;
  runId: string;
  eventType: string;
  status: string;
  actorId?: string;
  actorName: string;
  agentId?: SocAgentId;
  targetAgentId?: SocAgentId;
  phaseId?: string;
  toolName?: string;
  summary: string;
  detail: Record<string, unknown>;
  createdAt: string;
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

export function listSocAgents() {
  return socAgentProfiles;
}

export function listAgentWorkflows() {
  return agentWorkflows;
}

export async function runAgentMesh(input: { tenantId: string; alertId: string; actorName: string; trigger?: string }) {
  return runAgentWorkflow({ ...input, workflowId: defaultAgentWorkflowId });
}

export async function runAgentWorkflow(input: { tenantId: string; alertId: string; workflowId?: string; actorName: string; trigger?: string }) {
  const workflow = getAgentWorkflow(input.workflowId ?? defaultAgentWorkflowId);
  if (!workflow) throw new Error("Agent workflow not found.");
  if (input.trigger === "automatic-ingest") {
    const [existing] = await db.select().from(schema.socAgentRun).where(and(
      eq(schema.socAgentRun.tenantId, input.tenantId),
      eq(schema.socAgentRun.alertId, input.alertId),
      eq(schema.socAgentRun.trigger, "automatic-ingest"),
    )).limit(1);
    if (existing) return getAgentRoom(input.tenantId, existing.id);
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
    workflowId: workflow.id,
    trigger: input.trigger ?? "manual",
    status: "running",
    title: `${workflow.name}: ${alert.title}`,
    initiatedBy: input.actorName,
    startedAt,
  });

  const steps: AgentStep[] = [];
  try {
    await appendAgentRoomEvent({
      tenantId: input.tenantId,
      runId,
      eventType: "room.opened",
      status: "running",
      actorName: input.actorName,
      summary: `${workflow.name} room opened for ${alert.title}.`,
      detail: { workflowId: workflow.id, alertId: alert.id, trigger: input.trigger ?? "manual" },
    });
    const relatedSignals = [...alerts, ...events]
      .filter((event) => event.id !== alert.id)
      .sort((left, right) => signalRelevance(right, alert) - signalRelevance(left, alert));
    for (const [phaseIndex, phase] of workflow.phases.entries()) {
      const phaseStarted = new Date();
      const profile = socAgentProfiles.find((agent) => agent.id === phase.agent);
      await appendAgentRoomEvent({
        tenantId: input.tenantId,
        runId,
        eventType: "agent.started",
        status: "running",
        actorName: profile?.name ?? phase.agent,
        agentId: phase.agent,
        phaseId: phase.id,
        summary: `${phase.name} started.`,
        detail: { instructions: phase.instructions, tools: phase.tools, approvalRequired: Boolean(phase.approvalRequired) },
      });
      const result = await runSpecialistAgent(input.tenantId, phase.agent, phase, {
        alert,
        relatedSignals,
        matchedRules,
        indicators: alert.tiMatches ?? [],
        priorSteps: steps.map((step) => ({ agent: step.agent, summary: step.summary, evidence: step.evidence, actions: step.handoff ?? step.actions })),
      });
      const completedAt = new Date();
      const step: AgentStep = {
        agent: profile?.name ?? phase.agent,
        agentId: phase.agent,
        phaseId: phase.id,
        phaseName: phase.name,
        status: "completed",
        summary: result.summary,
        engine: result.meta.engine,
        confidence: result.confidence,
        evidence: result.evidence,
        actions: result.actions,
        handoff: result.handoff,
        tools: phase.tools,
        approvalRequired: phase.approvalRequired,
        startedAt: phaseStarted.toISOString(),
        completedAt: completedAt.toISOString(),
      };
      steps.push(step);
      await db.update(schema.socAgentRun).set({ steps, summary: `${phase.name} completed by ${step.agent}.` }).where(eq(schema.socAgentRun.id, runId));
      await appendAgentRoomEvent({
        tenantId: input.tenantId,
        runId,
        eventType: "agent.completed",
        status: "completed",
        actorName: step.agent,
        agentId: phase.agent,
        phaseId: phase.id,
        summary: result.summary,
        detail: { engine: result.meta.engine, confidence: result.confidence, evidence: result.evidence, actions: result.actions, handoff: result.handoff },
      });
      if (phase.approvalRequired) {
        await appendAgentRoomEvent({
          tenantId: input.tenantId,
          runId,
          eventType: "approval.requested",
          status: "waiting",
          actorName: step.agent,
          agentId: phase.agent,
          phaseId: phase.id,
          summary: `${phase.name} produced approval-gated actions.`,
          detail: { actions: result.actions, evidence: result.evidence },
        });
      }
      const nextPhase = workflow.phases[phaseIndex + 1];
      if (nextPhase) {
        await appendAgentRoomEvent({
          tenantId: input.tenantId,
          runId,
          eventType: "agent.handoff",
          status: "sent",
          actorName: step.agent,
          agentId: phase.agent,
          targetAgentId: nextPhase.agent,
          phaseId: phase.id,
          summary: `${step.agent} handed room context to ${socAgentProfiles.find((agent) => agent.id === nextPhase.agent)?.name ?? nextPhase.agent}.`,
          detail: { messages: result.handoff, evidence: result.evidence },
        });
      }
    }
    const completedAt = new Date();
    const findings = [
      { type: "workflow", value: workflow.id },
      { type: "agents", value: workflow.phases.map((phase) => phase.agent) },
      { type: "approval-gates", value: workflow.phases.filter((phase) => phase.approvalRequired).map((phase) => phase.id) },
    ];
    const summary = `${workflow.name} completed ${steps.length} specialist phases. ${steps.at(-1)?.summary ?? "Investigation ledger complete."}`;
    await db.update(schema.socAgentRun).set({ status: "completed", summary, steps, findings, completedAt }).where(eq(schema.socAgentRun.id, runId));
    await appendAgentRoomEvent({ tenantId: input.tenantId, runId, eventType: "room.completed", status: "completed", actorName: input.actorName, summary, detail: { workflowId: workflow.id, phases: steps.length } });
    await recordAuditLog({ tenantId: input.tenantId, action: "agent.workflow.completed", resourceType: "agent-run", resourceId: runId, detail: summary, metadata: { workflowId: workflow.id, agents: workflow.phases.map((phase) => phase.agent) } });
    return getAgentRoom(input.tenantId, runId);
  } catch (error) {
    const detail = error instanceof Error ? error.message : "Agent workflow failed.";
    await db.update(schema.socAgentRun).set({ status: "failed", summary: detail, steps, completedAt: new Date() }).where(eq(schema.socAgentRun.id, runId));
    await appendAgentRoomEvent({ tenantId: input.tenantId, runId, eventType: "room.failed", status: "failed", actorName: input.actorName, summary: detail }).catch(() => undefined);
    throw error;
  }
}

export async function listAgentRuns(tenantId: string, limit = 20): Promise<AgentRun[]> {
  const rows = await db.select().from(schema.socAgentRun).where(eq(schema.socAgentRun.tenantId, tenantId)).orderBy(desc(schema.socAgentRun.startedAt)).limit(limit);
  if (!rows.length) return [];
  const eventRows = await db.select().from(schema.socAgentRoomEvent).where(and(
    eq(schema.socAgentRoomEvent.tenantId, tenantId),
    inArray(schema.socAgentRoomEvent.runId, rows.map((row) => row.id)),
  )).orderBy(asc(schema.socAgentRoomEvent.sequence));
  return rows.map((row) => mapAgentRun(row, eventRows.filter((event) => event.runId === row.id)));
}

export async function getAgentRoom(tenantId: string, roomId: string): Promise<AgentRun> {
  const [row] = await db.select().from(schema.socAgentRun).where(and(eq(schema.socAgentRun.tenantId, tenantId), eq(schema.socAgentRun.id, roomId))).limit(1);
  if (!row) throw new Error("Agent room not found.");
  const events = await db.select().from(schema.socAgentRoomEvent).where(and(
    eq(schema.socAgentRoomEvent.tenantId, tenantId),
    eq(schema.socAgentRoomEvent.runId, roomId),
  )).orderBy(asc(schema.socAgentRoomEvent.sequence));
  return mapAgentRun(row, events);
}

export async function openAgentRoom(input: { tenantId: string; alertId: string; workflowId: string; actorId?: string; actorName: string; agentId: SocAgentId; title?: string }) {
  const workflow = getAgentWorkflow(input.workflowId);
  if (!workflow) throw new Error("Agent workflow not found.");
  const alert = (await listAlerts(input.tenantId)).find((item) => item.id === input.alertId);
  if (!alert) throw new Error("Alert not found.");
  const roomId = `agent-run-${randomUUID()}`;
  const startedAt = new Date();
  await db.insert(schema.socAgentRun).values({
    id: roomId,
    tenantId: input.tenantId,
    alertId: alert.id,
    workflowId: workflow.id,
    trigger: "hermes-bot-mode",
    status: "collaborating",
    title: input.title?.trim() || `${workflow.name}: ${alert.title}`,
    initiatedBy: input.actorName,
    startedAt,
  });
  await appendAgentRoomEvent({
    tenantId: input.tenantId,
    runId: roomId,
    eventType: "room.opened",
    status: "collaborating",
    actorId: input.actorId,
    actorName: input.actorName,
    agentId: input.agentId,
    summary: `${workflow.name} Hermes Bot Mode room opened for ${alert.title}.`,
    detail: { workflowId: workflow.id, alertId: alert.id, phases: workflow.phases.map((phase) => ({ id: phase.id, agent: phase.agent, approvalRequired: Boolean(phase.approvalRequired) })) },
  });
  return getAgentRoom(input.tenantId, roomId);
}

const roomMessageTypes = ["message", "handoff", "decision", "status", "approval.requested", "agent.completed"] as const;
export type AgentRoomMessageType = typeof roomMessageTypes[number];

export async function postAgentRoomMessage(input: {
  tenantId: string;
  roomId: string;
  actorId?: string;
  actorName: string;
  agentId: SocAgentId;
  targetAgentId?: SocAgentId;
  phaseId?: string;
  messageType: AgentRoomMessageType;
  message: string;
  evidence?: string[];
  actions?: string[];
}) {
  if (!roomMessageTypes.includes(input.messageType)) throw new Error("Invalid room message type.");
  if (!input.message.trim()) throw new Error("message is required.");
  return appendAgentRoomEvent({
    tenantId: input.tenantId,
    runId: input.roomId,
    eventType: input.messageType === "handoff" ? "agent.handoff" : input.messageType,
    status: input.messageType === "approval.requested" ? "waiting" : input.messageType === "agent.completed" ? "completed" : "sent",
    actorId: input.actorId,
    actorName: input.actorName,
    agentId: input.agentId,
    targetAgentId: input.targetAgentId,
    phaseId: input.phaseId,
    summary: input.message.trim(),
    detail: { evidence: input.evidence ?? [], actions: input.actions ?? [] },
  });
}

export async function closeAgentRoom(input: { tenantId: string; roomId: string; actorId?: string; actorName: string; agentId: SocAgentId; summary: string }) {
  if (!input.summary.trim()) throw new Error("summary is required.");
  const completedAt = new Date();
  const [row] = await db.update(schema.socAgentRun).set({ status: "completed", summary: input.summary.trim(), completedAt })
    .where(and(eq(schema.socAgentRun.tenantId, input.tenantId), eq(schema.socAgentRun.id, input.roomId))).returning({ id: schema.socAgentRun.id });
  if (!row) throw new Error("Agent room not found.");
  await appendAgentRoomEvent({
    tenantId: input.tenantId,
    runId: input.roomId,
    eventType: "room.completed",
    status: "completed",
    actorId: input.actorId,
    actorName: input.actorName,
    agentId: input.agentId,
    summary: input.summary.trim(),
  });
  return getAgentRoom(input.tenantId, input.roomId);
}

export async function appendAgentRoomEvent(input: {
  tenantId: string;
  runId: string;
  eventType: string;
  status: string;
  actorId?: string;
  actorName: string;
  agentId?: SocAgentId;
  targetAgentId?: SocAgentId;
  phaseId?: string;
  toolName?: string;
  summary: string;
  detail?: Record<string, unknown>;
}) {
  if (input.agentId && !isSocAgentId(input.agentId)) throw new Error("Invalid SOC agent ID.");
  if (input.targetAgentId && !isSocAgentId(input.targetAgentId)) throw new Error("Invalid target SOC agent ID.");
  const [room] = await db.select({ id: schema.socAgentRun.id }).from(schema.socAgentRun).where(and(
    eq(schema.socAgentRun.tenantId, input.tenantId),
    eq(schema.socAgentRun.id, input.runId),
  )).limit(1);
  if (!room) throw new Error("Agent room not found.");
  const [event] = await db.insert(schema.socAgentRoomEvent).values({
    id: `room-event-${randomUUID()}`,
    tenantId: input.tenantId,
    runId: input.runId,
    eventType: input.eventType,
    status: input.status,
    actorId: input.actorId,
    actorName: input.actorName,
    agentId: input.agentId,
    targetAgentId: input.targetAgentId,
    phaseId: input.phaseId,
    toolName: input.toolName,
    summary: input.summary,
    detail: input.detail ?? {},
    createdAt: new Date(),
  }).returning();
  return mapAgentRoomEvent(event);
}

type AgentRunRow = typeof schema.socAgentRun.$inferSelect;
type AgentRoomEventRow = typeof schema.socAgentRoomEvent.$inferSelect;

function mapAgentRun(row: AgentRunRow, events: AgentRoomEventRow[]): AgentRun {
  return {
    id: row.id, tenantId: row.tenantId, alertId: row.alertId ?? undefined, workflowId: row.workflowId ?? readWorkflowId(row.findings), trigger: row.trigger, status: row.status,
    title: row.title, summary: row.summary, steps: row.steps as AgentStep[], events: events.map(mapAgentRoomEvent), findings: row.findings,
    initiatedBy: row.initiatedBy, startedAt: row.startedAt.toISOString(), completedAt: row.completedAt?.toISOString(),
  };
}

function mapAgentRoomEvent(row: AgentRoomEventRow): AgentRoomEvent {
  return {
    id: row.id,
    sequence: row.sequence,
    runId: row.runId,
    eventType: row.eventType,
    status: row.status,
    actorId: row.actorId ?? undefined,
    actorName: row.actorName,
    agentId: isSocAgentId(row.agentId) ? row.agentId : undefined,
    targetAgentId: isSocAgentId(row.targetAgentId) ? row.targetAgentId : undefined,
    phaseId: row.phaseId ?? undefined,
    toolName: row.toolName ?? undefined,
    summary: row.summary,
    detail: row.detail,
    createdAt: row.createdAt.toISOString(),
  };
}

function readWorkflowId(findings: Array<Record<string, unknown>>) {
  const value = findings.find((finding) => finding.type === "workflow")?.value;
  return typeof value === "string" ? value : undefined;
}

function signalRelevance(signal: Awaited<ReturnType<typeof listEvents>>[number], alert: ReturnType<typeof extractAlertContext>) {
  let score = 0;
  if (signal.hostname && signal.hostname === alert.hostname) score += 5;
  score += signal.mitreTechniques.filter((technique) => alert.mitreTechniques.includes(technique)).length * 2;
  if (Math.abs(Date.parse(signal.timestamp) - Date.parse(alert.timestamp)) <= 60 * 60_000) score += 1;
  return score;
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
    await tx.insert(schema.socAgentRun).values({ id: runId, tenantId, workflowId: "scheduled-threat-hunt", trigger: `hunt-schedule:${trigger}`, status: "completed", title: row.name, summary, steps: [step], findings, initiatedBy: trigger === "scheduled" ? "Hunt scheduler" : "Analyst", startedAt, completedAt });
    await tx.update(schema.socHuntSchedule).set({ lastRunAt: startedAt, lastStatus: "completed", lastFindingCount: result.totalMatched, updatedAt: completedAt }).where(eq(schema.socHuntSchedule.id, id));
  });
  await appendAgentRoomEvent({ tenantId, runId, eventType: "room.opened", status: "running", actorName: trigger === "scheduled" ? "Hunt scheduler" : "Analyst", agentId: "threat_hunter", summary: `${row.name} scheduled hunt room opened.`, detail: { scheduleId: id, hypothesis: row.hypothesis, query: row.query } });
  await appendAgentRoomEvent({ tenantId, runId, eventType: "agent.completed", status: "completed", actorName: "Threat Hunter", agentId: "threat_hunter", summary, detail: { findingCount: result.totalMatched, evidence: step.evidence } });
  await appendAgentRoomEvent({ tenantId, runId, eventType: "room.completed", status: "completed", actorName: trigger === "scheduled" ? "Hunt scheduler" : "Analyst", agentId: "threat_hunter", summary });
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
