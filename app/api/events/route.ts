import { NextResponse } from "next/server";
import { authenticateApiRequest } from "@/lib/api-auth";
import { searchInputFromParams, searchRecords } from "@/lib/search";
import { listEvents } from "@/lib/store";

export async function GET(request: Request) {
  const principal = await authenticateApiRequest(request, "events:read", { allowSession: true });
  if (!principal) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const events = await listEvents(principal.tenantId);
  const result = searchRecords(events, searchInputFromParams(new URL(request.url).searchParams), { defaultDataset: "telemetry" });

  if (!result.ok) {
    return NextResponse.json({ error: result.error, records: [], pageInfo: result.pageInfo }, { status: 400 });
  }

  return NextResponse.json({ records: result.records, pageInfo: result.pageInfo, totalMatched: result.totalMatched, warnings: result.warnings });
}
