import { NextResponse } from "next/server";
import { authenticateApiRequest } from "@/lib/api-auth";
import { searchInputFromParams, searchRecords } from "@/lib/search";
import { listAlerts } from "@/lib/store";

export async function GET(request: Request) {
  const principal = await authenticateApiRequest(request, "alerts:read", { allowSession: true });
  if (!principal) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const alerts = await listAlerts(principal.tenantId);
  const result = searchRecords(alerts, searchInputFromParams(new URL(request.url).searchParams), { defaultDataset: "alerts" });

  if (!result.ok) {
    return NextResponse.json({ error: result.error, records: [], pageInfo: result.pageInfo }, { status: 400 });
  }

  return NextResponse.json({ records: result.records, pageInfo: result.pageInfo, totalMatched: result.totalMatched, warnings: result.warnings });
}
