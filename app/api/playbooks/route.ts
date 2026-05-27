import { NextResponse } from "next/server";
import { playbooks } from "@/lib/rules";

export async function GET() {
  return NextResponse.json(playbooks);
}
