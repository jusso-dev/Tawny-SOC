import type { ApiPrincipal } from "@/lib/api-auth";
import type { ApiTokenScope } from "@/lib/api-token-policy";
import {
  getSoarRun,
  getTenantAlert,
  getTenantCase,
  huntTenant,
  listAgentPlaybooks,
  listTenantCases,
  listTenantIndicators,
} from "@/lib/agent-api";
import { approveSoarAction, startSoarRun } from "@/lib/soar";
import { createHuntSchedule, listAgentRuns, listHuntSchedules, runAgentMesh, runHuntSchedule } from "@/lib/war-room";

export const MCP_PROTOCOL_VERSION = "2025-11-25";
export const MCP_SUPPORTED_VERSIONS = ["2025-03-26", "2025-06-18", MCP_PROTOCOL_VERSION];

type JsonRpcId = string | number | null;
type JsonRpcMessage = { jsonrpc?: unknown; id?: JsonRpcId; method?: unknown; params?: unknown };

type McpToolDefinition = {
  name: string;
  title: string;
  description: string;
  inputSchema: Record<string, unknown>;
  annotations: Record<string, boolean | string>;
  requiredScope: ApiTokenScope;
};

export const mcpTools: McpToolDefinition[] = [
  {
    name: "tawny_hunt",
    title: "Hunt Tawny telemetry",
    description: "Run a tenant-scoped YAAQL hunt across retained alerts and telemetry. Use narrow time ranges and queries before broad sweeps.",
    requiredScope: "events:read",
    inputSchema: objectSchema({
      query: { type: "string", description: "YAAQL query, for example: host:win-* and severity in (critical, high)." },
      dataset: { type: "string", enum: ["all", "alerts", "events", "telemetry"], default: "all" },
      range: { type: "string", description: "Relative range such as 90m, 24h, or 7d." },
      from: { type: "string", format: "date-time" },
      to: { type: "string", format: "date-time" },
      limit: { type: "integer", minimum: 1, maximum: 1000, default: 100 },
      cursor: { type: "string" },
    }),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: "tawny_get_alert",
    title: "Get alert detail",
    description: "Pull a tenant-scoped alert including raw payload, detections, ATT&CK mappings, confidence, and triage context.",
    requiredScope: "alerts:read",
    inputSchema: objectSchema({ alertId: { type: "string" } }, ["alertId"]),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: "tawny_run_agent_mesh",
    title: "Run four-agent investigation",
    description: "Run Tawny-SOC Detect, Triage, Hunt, and Respond against one tenant alert and persist the evidence ledger. Response output is a plan; containment is never executed here.",
    requiredScope: "alerts:read",
    inputSchema: objectSchema({ alertId: { type: "string" } }, ["alertId"]),
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  },
  {
    name: "tawny_list_agent_runs",
    title: "List agent investigation ledgers",
    description: "Read recent four-agent investigation runs including step summaries, evidence, actions, engine mode, and timestamps.",
    requiredScope: "alerts:read",
    inputSchema: objectSchema({ limit: { type: "integer", minimum: 1, maximum: 50, default: 10 } }),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: "tawny_list_hunt_schedules",
    title: "List proactive threat hunts",
    description: "List tenant-scoped YAAQL hunt schedules and last finding counts.",
    requiredScope: "events:read",
    inputSchema: objectSchema({}),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: "tawny_run_hunt_schedule",
    title: "Run a proactive hunt now",
    description: "Execute one saved YAAQL threat-hunt schedule now and persist its findings in the agent ledger.",
    requiredScope: "events:read",
    inputSchema: objectSchema({ scheduleId: { type: "string" } }, ["scheduleId"]),
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  },
  {
    name: "tawny_create_hunt_schedule",
    title: "Create a proactive threat hunt",
    description: "Create an autonomous YAAQL hunt schedule. Requires detection write scope.",
    requiredScope: "detections:write",
    inputSchema: objectSchema({
      name: { type: "string" }, hypothesis: { type: "string" }, query: { type: "string" },
      schedule: { type: "string", description: "Five-field cron expression." },
      timezone: { type: "string", default: "UTC", description: "IANA timezone." },
    }, ["name", "hypothesis", "query", "schedule"]),
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  },
  {
    name: "tawny_list_cases",
    title: "List SOC cases",
    description: "List tenant-scoped SOC cases, optionally filtered by status.",
    requiredScope: "cases:read",
    inputSchema: objectSchema({ status: { type: "string" }, limit: { type: "integer", minimum: 1, maximum: 100, default: 25 } }),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: "tawny_get_case",
    title: "Get SOC case detail",
    description: "Get a case with linked alert IDs, observables, tasks, comments, and audit timeline.",
    requiredScope: "cases:read",
    inputSchema: objectSchema({ incidentId: { type: "string" } }, ["incidentId"]),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: "tawny_search_threat_intel",
    title: "Search threat intelligence",
    description: "Search active tenant threat indicators by value, type, source, or tag text.",
    requiredScope: "threat-intel:read",
    inputSchema: objectSchema({
      search: { type: "string" },
      type: { type: "string", enum: ["ip", "cidr", "domain", "url", "hash", "email", "file", "cve"] },
      limit: { type: "integer", minimum: 1, maximum: 100, default: 25 },
    }),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: "tawny_list_playbooks",
    title: "List SOAR playbooks",
    description: "Inspect available playbooks, phases, actions, and automation characteristics.",
    requiredScope: "playbooks:read",
    inputSchema: objectSchema({}),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: "tawny_run_playbook",
    title: "Preview or run a SOAR playbook",
    description: "Plan a playbook by default. Set dryRun=false to execute hunts and create analyst tasks; response actions remain approval-gated.",
    requiredScope: "playbooks:read",
    inputSchema: objectSchema({
      playbookId: { type: "string" },
      incidentId: { type: "string" },
      dryRun: { type: "boolean", default: true, description: "Defaults to true. False additionally requires playbooks:run." },
    }, ["playbookId", "incidentId"]),
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  },
  {
    name: "tawny_get_playbook_run",
    title: "Get SOAR run",
    description: "Read a persisted SOAR run, action results, and approval state.",
    requiredScope: "playbooks:read",
    inputSchema: objectSchema({ runId: { type: "string" } }, ["runId"]),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: "tawny_approve_response",
    title: "Approve SOAR response action",
    description: "Approve one response action with a reason. Owner-only. Approval is audited and does not claim external dispatch without a configured response connector.",
    requiredScope: "playbooks:approve",
    inputSchema: objectSchema({ runId: { type: "string" }, actionId: { type: "string" }, reason: { type: "string", minLength: 1 } }, ["runId", "actionId", "reason"]),
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  },
];

export function listMcpTools(principal: ApiPrincipal) {
  return mcpTools
    .filter((tool) => principal.scopes.includes(tool.requiredScope))
    .map(({ requiredScope: _requiredScope, ...tool }) => tool);
}

export async function handleMcpMessage(message: unknown, principal: ApiPrincipal) {
  if (!isRecord(message)) return rpcError(null, -32600, "Invalid Request");
  const request = message as JsonRpcMessage;
  if (request.jsonrpc !== "2.0" || typeof request.method !== "string") return rpcError(request.id ?? null, -32600, "Invalid Request");
  const isNotification = request.id === undefined;

  if (request.method === "notifications/initialized" || request.method === "notifications/cancelled") return isNotification ? null : rpcResult(request.id ?? null, {});
  if (request.method === "ping") return rpcResult(request.id ?? null, {});
  if (request.method === "initialize") {
    const params = isRecord(request.params) ? request.params : {};
    const requested = typeof params.protocolVersion === "string" ? params.protocolVersion : MCP_PROTOCOL_VERSION;
    return rpcResult(request.id ?? null, {
      protocolVersion: MCP_SUPPORTED_VERSIONS.includes(requested) ? requested : MCP_PROTOCOL_VERSION,
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: "tawny-soc", title: "Tawny-SOC AI War Room", version: "0.2.0" },
      instructions: "Use tawny_run_agent_mesh for alert investigation and tawny_hunt for scoped evidence collection. Preview playbooks before execution. Never approve containment without explicit user authorization.",
    });
  }
  if (request.method === "tools/list") return rpcResult(request.id ?? null, { tools: listMcpTools(principal) });
  if (request.method === "tools/call") {
    const params = isRecord(request.params) ? request.params : {};
    if (typeof params.name !== "string") return rpcError(request.id ?? null, -32602, "Tool name is required.");
    const args = isRecord(params.arguments) ? params.arguments : {};
    const tool = mcpTools.find((item) => item.name === params.name);
    if (!tool) return rpcError(request.id ?? null, -32602, `Unknown tool: ${params.name}`);
    if (!principal.scopes.includes(tool.requiredScope)) return rpcError(request.id ?? null, -32003, `Missing scope: ${tool.requiredScope}`);
    try {
      const output = await invokeMcpTool(params.name, args, principal);
      return rpcResult(request.id ?? null, toolResult(output));
    } catch (error) {
      const detail = error instanceof Error ? error.message : "Tool execution failed.";
      return rpcResult(request.id ?? null, { content: [{ type: "text", text: detail }], isError: true });
    }
  }
  return isNotification ? null : rpcError(request.id ?? null, -32601, "Method not found");
}

async function invokeMcpTool(name: string, args: Record<string, unknown>, principal: ApiPrincipal) {
  if (name === "tawny_hunt") {
    const result = await huntTenant(principal.tenantId, {
      q: optionalString(args.query), dataset: optionalString(args.dataset), range: optionalString(args.range),
      from: optionalString(args.from), to: optionalString(args.to), cursor: optionalString(args.cursor), limit: args.limit,
    });
    if (!result.ok) throw new Error(result.error?.message ?? "Hunt failed.");
    return { records: result.records, totalMatched: result.totalMatched, pageInfo: result.pageInfo, warnings: result.warnings };
  }
  if (name === "tawny_get_alert") {
    const alert = await getTenantAlert(principal.tenantId, requiredString(args.alertId, "alertId"));
    if (!alert) throw new Error("Alert not found.");
    return { alert };
  }
  if (name === "tawny_run_agent_mesh") return { run: await runAgentMesh({ tenantId: principal.tenantId, alertId: requiredString(args.alertId, "alertId"), actorName: principal.name, trigger: "hermes-mcp" }) };
  if (name === "tawny_list_agent_runs") return { runs: await listAgentRuns(principal.tenantId, optionalNumber(args.limit) ?? 10) };
  if (name === "tawny_list_hunt_schedules") return { schedules: await listHuntSchedules(principal.tenantId) };
  if (name === "tawny_run_hunt_schedule") return { run: await runHuntSchedule(principal.tenantId, requiredString(args.scheduleId, "scheduleId"), "hermes-mcp") };
  if (name === "tawny_create_hunt_schedule") return { scheduleId: await createHuntSchedule({
    tenantId: principal.tenantId,
    name: requiredString(args.name, "name"),
    hypothesis: requiredString(args.hypothesis, "hypothesis"),
    query: requiredString(args.query, "query"),
    schedule: requiredString(args.schedule, "schedule"),
    timezone: optionalString(args.timezone) ?? "UTC",
    actor: { id: principal.id, name: principal.name, tenantId: principal.tenantId, role: principal.role },
  }) };
  if (name === "tawny_list_cases") return { cases: await listTenantCases(principal.tenantId, { status: optionalString(args.status), limit: optionalNumber(args.limit) }) };
  if (name === "tawny_get_case") {
    const incident = await getTenantCase(principal.tenantId, requiredString(args.incidentId, "incidentId"));
    if (!incident) throw new Error("Case not found.");
    return { case: incident };
  }
  if (name === "tawny_search_threat_intel") return listTenantIndicators(principal.tenantId, { search: optionalString(args.search), type: optionalString(args.type), limit: optionalNumber(args.limit) });
  if (name === "tawny_list_playbooks") return { playbooks: listAgentPlaybooks() };
  if (name === "tawny_get_playbook_run") {
    const run = await getSoarRun(principal.tenantId, requiredString(args.runId, "runId"));
    if (!run) throw new Error("SOAR run not found.");
    return { run };
  }
  if (name === "tawny_run_playbook") {
    const dryRun = args.dryRun !== false;
    if (!dryRun && !principal.scopes.includes("playbooks:run")) throw new Error("Missing scope: playbooks:run");
    return { run: await startSoarRun({
      tenantId: principal.tenantId,
      incidentId: requiredString(args.incidentId, "incidentId"),
      playbookId: requiredString(args.playbookId, "playbookId"),
      dryRun,
      trigger: "mcp",
      actor: { id: principal.id, name: principal.name, tenantId: principal.tenantId, role: principal.role },
    }) };
  }
  if (name === "tawny_approve_response") return { run: await approveSoarAction({
    tenantId: principal.tenantId,
    runId: requiredString(args.runId, "runId"),
    actionId: requiredString(args.actionId, "actionId"),
    reason: requiredString(args.reason, "reason"),
    actor: { id: principal.id, name: principal.name, tenantId: principal.tenantId, role: principal.role },
  }) };
  throw new Error(`Unknown tool: ${name}`);
}

function objectSchema(properties: Record<string, unknown>, required: string[] = []) {
  return { type: "object", properties, required, additionalProperties: false };
}

function toolResult(output: unknown) {
  return { content: [{ type: "text", text: JSON.stringify(output) }], structuredContent: output, isError: false };
}

function rpcResult(id: JsonRpcId, result: unknown) {
  return { jsonrpc: "2.0", id, result };
}

function rpcError(id: JsonRpcId, code: number, message: string) {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function requiredString(value: unknown, field: string) {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${field} is required.`);
  return value.trim();
}

function optionalString(value: unknown) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function optionalNumber(value: unknown) {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}
