import { huntTenant } from "@/lib/agent-api";
import { withApiPrincipal } from "@/lib/api-response";
import { searchInputFromParams } from "@/lib/search";

export async function GET(request: Request) {
  return withApiPrincipal(request, "events:read", async (principal) => {
    const result = await huntTenant(principal.tenantId, searchInputFromParams(new URL(request.url).searchParams));
    if (!result.ok) throw new Error(`Invalid hunt request: ${result.error?.message ?? "Unknown search error"}`);
    return { ok: true, records: result.records, totalMatched: result.totalMatched, pageInfo: result.pageInfo, warnings: result.warnings };
  });
}
