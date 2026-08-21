import { and, eq } from "drizzle-orm";
import { NextResponse } from "next/server";
import { db, schema } from "@/lib/db/client";
import { requirePermission } from "@/lib/governance";
import { getSession } from "@/lib/session";
import type { SocActor } from "@/lib/store";
import { createHuntSchedule, runAgentMesh, runHuntSchedule, setHuntScheduleEnabled } from "@/lib/war-room";

export async function POST(request: Request) {
  const session = await getSession();
  if (!session) return NextResponse.json({ error: "Sign in required." }, { status: 401 });
  const actor = await resolveActor(session);
  const body = await request.json().catch(() => ({})) as Record<string, unknown>;
  const action = typeof body.action === "string" ? body.action : "";

  try {
    if (action === "run-agent-mesh") {
      const run = await runAgentMesh({ tenantId: actor.tenantId, alertId: required(body.alertId, "alertId"), actorName: actor.name });
      return NextResponse.json({ message: "Agent mesh completed.", run });
    }
    if (action === "create-hunt-schedule") {
      requirePermission(actor.role, "detection.write");
      const id = await createHuntSchedule({
        tenantId: actor.tenantId,
        name: required(body.name, "name"),
        hypothesis: required(body.hypothesis, "hypothesis"),
        query: required(body.query, "query"),
        schedule: required(body.schedule, "schedule"),
        timezone: required(body.timezone, "timezone"),
        actor,
      });
      return NextResponse.json({ message: "Proactive hunt scheduled.", id });
    }
    if (action === "run-hunt-schedule") {
      const run = await runHuntSchedule(actor.tenantId, required(body.id, "id"));
      return NextResponse.json({ message: `Hunt completed with ${run.findingCount} findings.`, run });
    }
    if (action === "toggle-hunt-schedule") {
      requirePermission(actor.role, "detection.write");
      await setHuntScheduleEnabled(actor.tenantId, required(body.id, "id"), body.enabled === true, actor);
      return NextResponse.json({ message: body.enabled === true ? "Hunt schedule resumed." : "Hunt schedule paused." });
    }
    return NextResponse.json({ error: "Unknown war room action." }, { status: 400 });
  } catch (error) {
    return NextResponse.json({ error: error instanceof Error ? error.message : "War room action failed." }, { status: 400 });
  }
}

async function resolveActor(session: NonNullable<Awaited<ReturnType<typeof getSession>>>): Promise<SocActor> {
  const activeOrganizationId = (session.session as { activeOrganizationId?: string | null }).activeOrganizationId;
  const [membership] = await db.select().from(schema.member).where(and(
    eq(schema.member.userId, session.user.id),
    ...(activeOrganizationId ? [eq(schema.member.organizationId, activeOrganizationId)] : []),
  )).limit(1);
  return { id: session.user.id, name: session.user.name || session.user.email, tenantId: membership?.organizationId ?? "local-tenant", role: membership?.role ?? "member" };
}

function required(value: unknown, field: string) {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${field} is required.`);
  return value.trim();
}
