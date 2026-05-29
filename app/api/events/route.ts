import { NextResponse } from "next/server";
import { searchInputFromParams, searchRecords } from "@/lib/search";
import { getSession } from "@/lib/session";
import { listEvents, validateApiToken } from "@/lib/store";

export async function GET(request: Request) {
  if (!await getSession()) {
    const authorization = request.headers.get("authorization") ?? "";
    const bearerToken = authorization.startsWith("Bearer ") ? authorization.slice("Bearer ".length).trim() : "";
    if (!bearerToken || !await validateApiToken(bearerToken, "events:read")) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  const events = await listEvents();
  const result = searchRecords(events, searchInputFromParams(new URL(request.url).searchParams), { defaultDataset: "telemetry" });

  if (!result.ok) {
    return NextResponse.json({ error: result.error, records: [], pageInfo: result.pageInfo }, { status: 400 });
  }

  return NextResponse.json({ records: result.records, pageInfo: result.pageInfo, totalMatched: result.totalMatched, warnings: result.warnings });
}
