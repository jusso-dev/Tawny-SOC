import { listTenantIndicators } from "@/lib/agent-api";
import { withApiPrincipal } from "@/lib/api-response";

export async function GET(request: Request) {
  return withApiPrincipal(request, "threat-intel:read", async (principal) => {
    const params = new URL(request.url).searchParams;
    return listTenantIndicators(principal.tenantId, {
      search: params.get("search") ?? undefined,
      type: params.get("type") ?? undefined,
      limit: Number(params.get("limit") ?? 25),
    });
  });
}
