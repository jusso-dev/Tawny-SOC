import { NextResponse } from "next/server";
import { listAlerts } from "@/lib/store";
import { filterWithYaaql } from "@/lib/yaaql";

export async function GET(request: Request) {
  const alerts = await listAlerts();
  const query = new URL(request.url).searchParams.get("q") ?? "";
  const result = filterWithYaaql(alerts, query);

  if (result.error) {
    return NextResponse.json({ error: result.error, query: result.query, records: [] }, { status: 400 });
  }

  return NextResponse.json(result.records);
}
