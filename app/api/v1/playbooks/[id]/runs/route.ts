import { authenticateApiRequest, hasScope, unauthorized } from "@/lib/api-auth";
import { startSoarRun } from "@/lib/soar";

export async function POST(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const principal = await authenticateApiRequest(request, "playbooks:read");
  if (!principal) return unauthorized("playbooks:read");
  const body = await request.json().catch(() => ({})) as Record<string, unknown>;
  const dryRun = body.dryRun !== false;
  if (!dryRun && !hasScope(principal, "playbooks:run")) return unauthorized("playbooks:run");
  try {
    const run = await startSoarRun({
      tenantId: principal.tenantId,
      incidentId: String(body.incidentId ?? ""),
      playbookId: id,
      dryRun,
      trigger: "api",
      actor: { id: principal.id, name: principal.name, tenantId: principal.tenantId, role: principal.role },
    });
    return Response.json({ run });
  } catch (error) {
    const detail = error instanceof Error ? error.message : "SOAR run failed.";
    return Response.json({ error: /not found/i.test(detail) ? "not_found" : "invalid_request", detail }, { status: /not found/i.test(detail) ? 404 : 400 });
  }
}
