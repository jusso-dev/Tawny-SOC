import { NextResponse } from "next/server";
import { getSession } from "@/lib/session";
import { importSigmaRule, listSigmaRules } from "@/lib/sigma";

export async function GET() {
  if (!await getSession()) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  return NextResponse.json(await listSigmaRules());
}

export async function POST(request: Request) {
  if (!await getSession()) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const body = await request.json().catch(() => ({}));
  const sigma = typeof body.sigma === "string" ? body.sigma : "";
  if (!sigma.trim()) return NextResponse.json({ error: "Sigma YAML is required." }, { status: 400 });

  try {
    const rule = await importSigmaRule(sigma);
    return NextResponse.json({ rule, message: `Imported ${rule.title}.` }, { status: 201 });
  } catch (error) {
    return NextResponse.json({ error: error instanceof Error ? error.message : "Invalid Sigma rule." }, { status: 400 });
  }
}
