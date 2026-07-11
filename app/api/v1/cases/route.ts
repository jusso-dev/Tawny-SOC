import { listTenantCases } from "@/lib/agent-api";
import { withApiPrincipal } from "@/lib/api-response";

export async function GET(request: Request) {
  return withApiPrincipal(request, "cases:read", async (principal) => {
    const params = new URL(request.url).searchParams;
    const cases = await listTenantCases(principal.tenantId, {
      status: params.get("status") ?? undefined,
      limit: Number(params.get("limit") ?? 25),
    });
    return { cases, count: cases.length };
  });
}
