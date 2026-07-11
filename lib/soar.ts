import { randomUUID } from "node:crypto";
import { and, desc, eq, inArray } from "drizzle-orm";
import { db, schema } from "@/lib/db/client";
import { playbooks } from "@/lib/rules";
import { searchRecords } from "@/lib/search";
import { listAlerts, listEvents, listIncidents, recordAuditLog, recordTimeline, type SocActor } from "@/lib/store";
import type { Playbook, SocIncident } from "@/lib/types";
import { quoteYaaqlValue } from "@/lib/yaaql";

export type SoarActionKind = "hunt" | "enrichment" | "response" | "notification" | "analyst_task";
export type SoarActionStatus = "planned" | "completed" | "pending" | "awaiting_approval" | "failed";
export type SoarRunStatus = "preview" | "completed" | "awaiting_approval" | "failed";

export type SoarPlannedAction = {
  id: string;
  phase: string;
  position: number;
  action: string;
  kind: SoarActionKind;
  status: SoarActionStatus;
  approvalRequired: boolean;
  input: Record<string, unknown>;
  output: Record<string, unknown>;
  approvedBy?: string;
  approvedAt?: string;
  completedAt?: string;
};

export type SoarRun = {
  id: string;
  tenantId: string;
  playbookId: string;
  playbookName: string;
  incidentId: string;
  status: SoarRunStatus;
  trigger: "manual" | "api" | "mcp";
  dryRun: boolean;
  actorName: string;
  summary: Record<string, unknown>;
  startedAt: string;
  completedAt?: string;
  actions: SoarPlannedAction[];
};

const responseMarkers = /\b(isolat|contain|block|disable|revoke|quarantine|kill|reset|remove|eradicate)/i;
const huntMarkers = /\b(review|check|pivot|search|hunt|correlat|collect|timeline|nearby|query)/i;
const enrichmentMarkers = /\b(enrich|reputation|threat intel|whois|sandbox|context)/i;
const notificationMarkers = /\b(notif|message|email|slack|escalat|page|ticket)/i;

export function buildSoarPlan(playbook: Playbook, incident: SocIncident): SoarPlannedAction[] {
  let position = 0;
  return playbook.phases.flatMap((phase) => phase.actions.map((action) => {
    const kind = classifySoarAction(action);
    const approvalRequired = kind === "response";
    const input = kind === "hunt" || kind === "enrichment"
      ? { query: buildIncidentHuntQuery(action, incident), dataset: "all", limit: 25 }
      : { incidentId: incident.id, hosts: incident.linkedHosts, observables: incident.observables.map((item) => item.value) };
    const planned: SoarPlannedAction = {
      id: `planned-${position}`,
      phase: phase.name,
      position,
      action,
      kind,
      status: "planned",
      approvalRequired,
      input,
      output: {},
    };
    position += 1;
    return planned;
  }));
}

export function classifySoarAction(action: string): SoarActionKind {
  if (responseMarkers.test(action)) return "response";
  if (enrichmentMarkers.test(action)) return "enrichment";
  if (huntMarkers.test(action)) return "hunt";
  if (notificationMarkers.test(action)) return "notification";
  return "analyst_task";
}

export function buildIncidentHuntQuery(action: string, incident: SocIncident) {
  const clauses: string[] = [];
  if (incident.linkedHosts[0]) clauses.push(`host=${quoteYaaqlValue(incident.linkedHosts[0])}`);
  if (/technique|attack|correlat/i.test(action) && incident.mitreTechniques[0]) {
    clauses.push(`mitre=${quoteYaaqlValue(incident.mitreTechniques[0])}`);
  }
  if (/ip|network|destination|block/i.test(action)) clauses.push("has:ip");
  return clauses.join(" and ") || `severity in (${incident.severity}, critical)`;
}

export async function startSoarRun(input: {
  tenantId: string;
  incidentId: string;
  playbookId: string;
  dryRun?: boolean;
  trigger?: SoarRun["trigger"];
  actor: SocActor;
}): Promise<SoarRun> {
  const playbook = playbooks.find((item) => item.id === input.playbookId);
  if (!playbook) throw new Error("Playbook not found.");
  const incident = (await listIncidents(input.tenantId)).find((item) => item.id === input.incidentId);
  if (!incident) throw new Error("Case not found.");
  const plan = buildSoarPlan(playbook, incident);
  const startedAt = new Date();

  if (input.dryRun !== false) {
    return {
      id: `preview-${randomUUID()}`,
      tenantId: input.tenantId,
      playbookId: playbook.id,
      playbookName: playbook.name,
      incidentId: incident.id,
      status: "preview",
      trigger: input.trigger ?? "api",
      dryRun: true,
      actorName: input.actor.name,
      summary: summarize(plan),
      startedAt: startedAt.toISOString(),
      completedAt: startedAt.toISOString(),
      actions: plan,
    };
  }

  const runId = `run-${randomUUID()}`;
  const records = [...await listAlerts(input.tenantId), ...await listEvents(input.tenantId)];
  const executed = plan.map((action) => executePlannedAction(action, records));
  const status: SoarRunStatus = executed.some((action) => action.status === "awaiting_approval") ? "awaiting_approval" : "completed";
  const completedAt = status === "completed" ? new Date() : undefined;

  await db.insert(schema.socPlaybookRun).values({
    id: runId,
    tenantId: input.tenantId,
    playbookId: playbook.id,
    playbookName: playbook.name,
    incidentId: incident.id,
    status,
    trigger: input.trigger ?? "api",
    dryRun: false,
    actorId: input.actor.id,
    actorName: input.actor.name,
    summary: summarize(executed),
    startedAt,
    completedAt,
  });
  await db.insert(schema.socPlaybookAction).values(executed.map((action) => ({
    id: `action-${randomUUID()}`,
    tenantId: input.tenantId,
    runId,
    incidentId: incident.id,
    phase: action.phase,
    position: action.position,
    action: action.action,
    kind: action.kind,
    status: action.status,
    approvalRequired: action.approvalRequired,
    input: action.input,
    output: action.output,
    createdAt: startedAt,
    completedAt: action.completedAt ? new Date(action.completedAt) : null,
  })));

  for (const action of executed.filter((item) => item.status === "pending")) {
    await db.insert(schema.socTask).values({
      id: `task-${randomUUID()}`,
      tenantId: input.tenantId,
      incidentId: incident.id,
      title: action.action,
      owner: playbook.phases.find((phase) => phase.name === action.phase)?.owner ?? input.actor.name,
      status: "todo",
      dueAt: new Date(Date.now() + (action.position + 1) * 30 * 60_000),
      requiredEvidence: [action.action],
      responseAction: action.kind === "notification" ? action.action : undefined,
    });
  }

  await Promise.all([
    recordTimeline({
      tenantId: input.tenantId,
      incidentId: incident.id,
      actor: input.actor.name,
      action: "started_soar_run",
      detail: `Started ${playbook.name}; ${executed.filter((item) => item.status === "completed").length} automated actions completed and ${executed.filter((item) => item.status === "awaiting_approval").length} require approval.`,
    }),
    recordAuditLog({
      tenantId: input.tenantId,
      actor: input.actor,
      action: "started_soar_run",
      resourceType: "playbook_run",
      resourceId: runId,
      detail: `Started ${playbook.name} for ${incident.number}.`,
      metadata: { playbookId: playbook.id, incidentId: incident.id, trigger: input.trigger ?? "api", status },
    }),
  ]);

  const stored = await getSoarRun(input.tenantId, runId);
  if (!stored) throw new Error("SOAR run was created but could not be reloaded.");
  return stored;
}

export async function approveSoarAction(input: {
  tenantId: string;
  runId: string;
  actionId: string;
  reason: string;
  actor: SocActor;
}) {
  const [action] = await db.select().from(schema.socPlaybookAction).where(and(
    eq(schema.socPlaybookAction.id, input.actionId),
    eq(schema.socPlaybookAction.runId, input.runId),
    eq(schema.socPlaybookAction.tenantId, input.tenantId),
  )).limit(1);
  if (!action) throw new Error("SOAR action not found.");
  if (!action.approvalRequired || action.status !== "awaiting_approval") throw new Error("SOAR action is not awaiting approval.");
  if (!input.reason.trim()) throw new Error("Approval reason is required.");
  const now = new Date();
  await db.update(schema.socPlaybookAction).set({
    status: "completed",
    approvedBy: input.actor.name,
    approvedAt: now,
    completedAt: now,
    output: {
      result: "approval_recorded",
      reason: input.reason.trim(),
      dispatch: "connector_action_required",
      note: "Approval is recorded; configure a response connector before external containment is dispatched.",
    },
  }).where(eq(schema.socPlaybookAction.id, action.id));

  const remaining = await db.select({ id: schema.socPlaybookAction.id }).from(schema.socPlaybookAction).where(and(
    eq(schema.socPlaybookAction.runId, input.runId),
    eq(schema.socPlaybookAction.tenantId, input.tenantId),
    eq(schema.socPlaybookAction.status, "awaiting_approval"),
  ));
  if (!remaining.length) {
    await db.update(schema.socPlaybookRun).set({ status: "completed", completedAt: now })
      .where(and(eq(schema.socPlaybookRun.id, input.runId), eq(schema.socPlaybookRun.tenantId, input.tenantId)));
  }
  await Promise.all([
    recordTimeline({
      tenantId: input.tenantId,
      incidentId: action.incidentId,
      actor: input.actor.name,
      action: "approved_soar_action",
      detail: `Approved response action: ${action.action}. Reason: ${input.reason.trim()}`,
    }),
    recordAuditLog({
      tenantId: input.tenantId,
      actor: input.actor,
      action: "approved_soar_action",
      resourceType: "playbook_action",
      resourceId: action.id,
      detail: input.reason.trim(),
      metadata: { runId: input.runId, action: action.action },
    }),
  ]);
  return getSoarRun(input.tenantId, input.runId);
}

export async function listSoarRuns(tenantId: string, limit = 25): Promise<SoarRun[]> {
  const rows = await db.select().from(schema.socPlaybookRun)
    .where(eq(schema.socPlaybookRun.tenantId, tenantId))
    .orderBy(desc(schema.socPlaybookRun.startedAt))
    .limit(Math.min(100, Math.max(1, limit)));
  if (!rows.length) return [];
  const actions = await db.select().from(schema.socPlaybookAction)
    .where(and(eq(schema.socPlaybookAction.tenantId, tenantId), inArray(schema.socPlaybookAction.runId, rows.map((row) => row.id))));
  return rows.map((row) => mapRun(row, actions.filter((action) => action.runId === row.id)));
}

export async function getSoarRun(tenantId: string, runId: string) {
  const [row] = await db.select().from(schema.socPlaybookRun).where(and(
    eq(schema.socPlaybookRun.id, runId),
    eq(schema.socPlaybookRun.tenantId, tenantId),
  )).limit(1);
  if (!row) return null;
  const actions = await db.select().from(schema.socPlaybookAction).where(and(
    eq(schema.socPlaybookAction.runId, runId),
    eq(schema.socPlaybookAction.tenantId, tenantId),
  ));
  return mapRun(row, actions);
}

function executePlannedAction(action: SoarPlannedAction, records: Awaited<ReturnType<typeof listEvents>>) {
  const now = new Date().toISOString();
  if (action.approvalRequired) return { ...action, status: "awaiting_approval" as const };
  if (action.kind === "hunt" || action.kind === "enrichment") {
    const result = searchRecords(records, {
      dataset: "all",
      q: String(action.input.query ?? ""),
      limit: Number(action.input.limit ?? 25),
    });
    if (!result.ok) return { ...action, status: "failed" as const, output: { error: result.error }, completedAt: now };
    return {
      ...action,
      status: "completed" as const,
      output: { matched: result.totalMatched, sampleRecordIds: result.records.slice(0, 10).map((record) => record.id), warnings: result.warnings },
      completedAt: now,
    };
  }
  return { ...action, status: "pending" as const };
}

function summarize(actions: SoarPlannedAction[]) {
  return {
    totalActions: actions.length,
    automated: actions.filter((item) => item.kind === "hunt" || item.kind === "enrichment").length,
    approvalRequired: actions.filter((item) => item.approvalRequired).length,
    analystTasks: actions.filter((item) => item.kind === "analyst_task" || item.kind === "notification").length,
  };
}

function mapRun(
  row: typeof schema.socPlaybookRun.$inferSelect,
  actions: Array<typeof schema.socPlaybookAction.$inferSelect>,
): SoarRun {
  return {
    id: row.id,
    tenantId: row.tenantId,
    playbookId: row.playbookId,
    playbookName: row.playbookName,
    incidentId: row.incidentId,
    status: row.status as SoarRunStatus,
    trigger: row.trigger as SoarRun["trigger"],
    dryRun: row.dryRun,
    actorName: row.actorName,
    summary: row.summary,
    startedAt: row.startedAt.toISOString(),
    completedAt: row.completedAt?.toISOString(),
    actions: actions.sort((a, b) => a.position - b.position).map((action) => ({
      id: action.id,
      phase: action.phase,
      position: action.position,
      action: action.action,
      kind: action.kind as SoarActionKind,
      status: action.status as SoarActionStatus,
      approvalRequired: action.approvalRequired,
      input: action.input,
      output: action.output,
      approvedBy: action.approvedBy ?? undefined,
      approvedAt: action.approvedAt?.toISOString(),
      completedAt: action.completedAt?.toISOString(),
    })),
  };
}
