import { authenticateApiRequest, unauthorized } from "@/lib/api-auth";
import { runAgentWorkflow } from "@/lib/war-room";

export async function POST(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const principal = await authenticateApiRequest(request, "alerts:read");
  if (!principal) return unauthorized("alerts:read");
  const body = await request.json().catch(() => ({})) as Record<string, unknown>;
  try {
    const run = await runAgentWorkflow({
      tenantId: principal.tenantId,
      alertId: required(body.alertId, "alertId"),
      workflowId: id,
      actorName: principal.name,
      trigger: "agent-api",
    });
    return Response.json({ run });
  } catch (error) {
    const detail = error instanceof Error ? error.message : "Agent workflow failed.";
    return Response.json({ error: /not found/i.test(detail) ? "not_found" : "invalid_request", detail }, { status: /not found/i.test(detail) ? 404 : 400 });
  }
}

function required(value: unknown, field: string) {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${field} is required.`);
  return value.trim();
}
