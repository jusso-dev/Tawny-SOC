import { and, eq } from "drizzle-orm";
import { db, schema } from "@/lib/db/client";

export async function sendEmail(input: { to: string; subject: string; text: string; tenantId?: string }) {
  const tenantId = input.tenantId;
  if (tenantId) {
    const delivered = await sendViaTenantEmailChannel({ ...input, tenantId }).catch((error) => {
      console.warn("[email delivery failed]", error instanceof Error ? error.message : error);
      return false;
    });
    if (delivered) return;
  }
  console.info("[email local fallback]", input);
}

async function sendViaTenantEmailChannel(input: { to: string; subject: string; text: string; tenantId: string }) {
  const [row] = await db.select().from(schema.socSetting)
    .where(and(eq(schema.socSetting.tenantId, input.tenantId), eq(schema.socSetting.key, "integration.email")))
    .limit(1);
  const value = row?.value ?? {};
  if (value.enabled !== true || typeof value.endpoint !== "string" || !value.endpoint.trim()) return false;
  const credential = typeof value.credential === "string" ? value.credential : "";
  const res = await fetch(value.endpoint, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(credential ? { authorization: `Bearer ${credential}` } : {}),
    },
    body: JSON.stringify({
      to: input.to,
      subject: input.subject,
      text: input.text,
      source: "Tawny-SOC",
    }),
  });
  if (!res.ok) throw new Error(`Email endpoint returned HTTP ${res.status}`);
  return true;
}
