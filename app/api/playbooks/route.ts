import { NextResponse } from "next/server";
import { playbooks } from "@/lib/rules";
import { getSession } from "@/lib/session";

export async function GET() {
  if (!await getSession()) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  return NextResponse.json(playbooks);
}
