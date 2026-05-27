import { NextResponse } from "next/server";
import { sigmaRules } from "@/lib/rules";

export async function GET() {
  return NextResponse.json(sigmaRules);
}
