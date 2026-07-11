import { getSoarRun } from "@/lib/agent-api";
import { withApiPrincipal } from "@/lib/api-response";

export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return withApiPrincipal(request, "playbooks:read", async (principal) => {
    const run = await getSoarRun(principal.tenantId, id);
    if (!run) throw new Error("SOAR run not found.");
    return { run };
  });
}
