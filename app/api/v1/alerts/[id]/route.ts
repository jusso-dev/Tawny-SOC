import { getTenantAlert } from "@/lib/agent-api";
import { withApiPrincipal } from "@/lib/api-response";

export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return withApiPrincipal(request, "alerts:read", async (principal) => {
    const alert = await getTenantAlert(principal.tenantId, id);
    if (!alert) throw new Error("Alert not found.");
    return { alert };
  });
}
