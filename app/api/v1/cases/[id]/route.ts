import { getTenantCase } from "@/lib/agent-api";
import { withApiPrincipal } from "@/lib/api-response";

export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return withApiPrincipal(request, "cases:read", async (principal) => {
    const incident = await getTenantCase(principal.tenantId, id);
    if (!incident) throw new Error("Case not found.");
    return { case: incident };
  });
}
