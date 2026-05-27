import { NextResponse } from "next/server";
import { z } from "zod";
import { ingestTawny } from "@/lib/store";

const IngestSchema = z.object({
  source: z.string().optional(),
  kind: z.enum(["alert_batch", "telemetry_batch"]).optional(),
  sent_at: z.string().optional(),
  tenant_id: z.string().optional(),
  agent: z.record(z.string(), z.unknown()).optional(),
  alerts: z.array(z.record(z.string(), z.unknown())).optional(),
  events: z.array(z.record(z.string(), z.unknown())).optional(),
  telemetry_events: z.record(z.string(), z.record(z.string(), z.unknown())).optional(),
});

export async function POST(request: Request) {
  const expectedToken = process.env.TAWNY_SOC_INGEST_TOKEN;
  if (expectedToken) {
    const authorization = request.headers.get("authorization") ?? "";
    if (authorization !== `Bearer ${expectedToken}`) {
      return NextResponse.json({ error: "unauthorized" }, { status: 401 });
    }
  }

  const body = await request.json().catch(() => null);
  const parsed = IngestSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: "invalid_ingest_payload", detail: parsed.error.flatten() },
      { status: 400 },
    );
  }

  const result = await ingestTawny(parsed.data);
  return NextResponse.json({ ok: true, ...result });
}
