import { NextResponse } from "next/server";
import { z } from "zod";
import { ingestTawny, validateApiToken } from "@/lib/store";

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
  const authorization = request.headers.get("authorization") ?? "";
  const bearerToken = authorization.startsWith("Bearer ") ? authorization.slice("Bearer ".length).trim() : "";
  let authenticatedTenantId = "";

  if (expectedToken && bearerToken === expectedToken) {
    authenticatedTenantId = "";
  } else if (bearerToken) {
    const apiToken = await validateApiToken(bearerToken, "ingest:write");
    if (!apiToken) {
      return NextResponse.json({ error: "unauthorized" }, { status: 401 });
    }
    authenticatedTenantId = apiToken.tenantId;
  } else if (expectedToken) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }

  const body = await request.json().catch(() => null);
  const parsed = IngestSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: "invalid_ingest_payload", detail: parsed.error.flatten() },
      { status: 400 },
    );
  }

  const payload = authenticatedTenantId
    ? {
      ...parsed.data,
      tenant_id: authenticatedTenantId,
      agent: { ...(parsed.data.agent ?? {}), tenant_id: authenticatedTenantId },
    }
    : parsed.data;
  const result = await ingestTawny(payload);
  return NextResponse.json({ ok: true, ...result });
}
