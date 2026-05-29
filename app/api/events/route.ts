import { NextResponse } from "next/server";
import { getSession } from "@/lib/session";
import { listEvents } from "@/lib/store";
import { filterWithYaaql } from "@/lib/yaaql";

export async function GET(request: Request) {
  if (!await getSession()) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const events = await listEvents();
  const query = new URL(request.url).searchParams.get("q") ?? "";
  const result = filterWithYaaql(events, query);

  if (result.error) {
    return NextResponse.json({ error: result.error, query: result.query, records: [] }, { status: 400 });
  }

  return NextResponse.json(result.records);
}
