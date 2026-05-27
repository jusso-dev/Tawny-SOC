import { NextResponse } from "next/server";
import { listEvents } from "@/lib/store";

export async function GET() {
  return NextResponse.json(await listEvents());
}
