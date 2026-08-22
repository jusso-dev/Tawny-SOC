import { authenticateApiRequest, unauthorized } from "@/lib/api-auth";
import { isSocAgentId } from "@/lib/ai/agents/catalog";
import { listAgentRuns, openAgentRoom } from "@/lib/war-room";

export async function GET(request: Request) {
  const principal = await authenticateApiRequest(request, "agent-rooms:read");
  if (!principal) return unauthorized("agent-rooms:read");
  const url = new URL(request.url);
  const limit = Math.min(50, Math.max(1, Number(url.searchParams.get("limit") ?? 20) || 20));
  return Response.json({ rooms: await listAgentRuns(principal.tenantId, limit) });
}

export async function POST(request: Request) {
  const principal = await authenticateApiRequest(request, "agent-rooms:write");
  if (!principal) return unauthorized("agent-rooms:write");
  const body = await request.json().catch(() => ({})) as Record<string, unknown>;
  try {
    if (!isSocAgentId(body.agentId)) throw new Error("agentId must identify a registered SOC agent.");
    const room = await openAgentRoom({
      tenantId: principal.tenantId,
      alertId: required(body.alertId, "alertId"),
      workflowId: required(body.workflowId, "workflowId"),
      actorId: principal.id,
      actorName: principal.name,
      agentId: body.agentId,
      title: optional(body.title),
    });
    return Response.json({ room }, { status: 201 });
  } catch (error) {
    const detail = error instanceof Error ? error.message : "Agent room could not be opened.";
    return Response.json({ error: /not found/i.test(detail) ? "not_found" : "invalid_request", detail }, { status: /not found/i.test(detail) ? 404 : 400 });
  }
}

function required(value: unknown, field: string) {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${field} is required.`);
  return value.trim();
}

function optional(value: unknown) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}
