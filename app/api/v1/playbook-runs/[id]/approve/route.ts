import { withApiPrincipal } from "@/lib/api-response";
import { approveSoarAction } from "@/lib/soar";

export async function POST(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const body = await request.json().catch(() => ({})) as Record<string, unknown>;
  return withApiPrincipal(request, "playbooks:approve", async (principal) => ({
    run: await approveSoarAction({
      tenantId: principal.tenantId,
      runId: id,
      actionId: String(body.actionId ?? ""),
      reason: String(body.reason ?? ""),
      actor: { id: principal.id, name: principal.name, tenantId: principal.tenantId, role: principal.role },
    }),
  }));
}
