import { eq } from "drizzle-orm";
import { NextResponse } from "next/server";
import { runCaseWriterAgent } from "@/lib/ai/agents/case-writer";
import { runEnrichmentAgent } from "@/lib/ai/agents/enrichment";
import { runTriageAgent } from "@/lib/ai/agents/triage";
import { db, schema } from "@/lib/db/client";
import { playbooks } from "@/lib/rules";
import { getSession } from "@/lib/session";
import { listSigmaRules } from "@/lib/sigma";
import { extractAlertContext } from "@/lib/soc-domain";
import { listAlerts, listIncidents, listThreatIntelMatches } from "@/lib/store";
import { listAgentWorkflows, listSocAgents } from "@/lib/war-room";

export async function GET() {
  const session = await getSession();
  if (!session) return NextResponse.json({ error: "Sign in required." }, { status: 401 });
  return NextResponse.json({ agents: listSocAgents(), workflows: listAgentWorkflows() });
}

export async function POST(request: Request) {
  const session = await getSession();
  if (!session) return NextResponse.json({ error: "Sign in required." }, { status: 401 });

  const body = await request.json().catch(() => ({})) as Record<string, unknown>;
  const agent = typeof body.agent === "string" ? body.agent : "";
  const tenantId = await resolveTenantId(session);

  try {
    if (agent === "triage" || agent === "enrichment") {
      const alertId = typeof body.alertId === "string" ? body.alertId : "";
      const alerts = await listAlerts();
      const found = alerts.find((item) => item.id === alertId);
      if (!found) return NextResponse.json({ error: "Alert not found." }, { status: 404 });
      const indicators = await listThreatIntelMatches(found.tenantId ?? tenantId);
      const alert = extractAlertContext(found, indicators);

      if (agent === "triage") {
        const sigmaRules = await listSigmaRules();
        const matchedRules = sigmaRules.filter((rule) => alert.matchedRules.includes(rule.id));
        const result = await runTriageAgent(tenantId, { alert, matchedRules, playbooks });
        return NextResponse.json(result);
      }

      const result = await runEnrichmentAgent(tenantId, { alert, indicators: alert.tiMatches ?? [] });
      return NextResponse.json(result);
    }

    if (agent === "case-writer") {
      const incidentId = typeof body.incidentId === "string" ? body.incidentId : "";
      const incidents = await listIncidents();
      const incident = incidents.find((item) => item.id === incidentId);
      if (!incident) return NextResponse.json({ error: "Case not found." }, { status: 404 });
      const alerts = await listAlerts();
      const linkedAlerts = alerts.filter((alert) => incident.linkedAlertIds.includes(alert.id));
      const result = await runCaseWriterAgent(tenantId, { incident, linkedAlerts });
      return NextResponse.json(result);
    }

    return NextResponse.json({ error: "Unknown agent." }, { status: 400 });
  } catch (error) {
    return NextResponse.json({ error: error instanceof Error ? error.message : "Agent run failed." }, { status: 400 });
  }
}

async function resolveTenantId(session: NonNullable<Awaited<ReturnType<typeof getSession>>>) {
  const activeOrganizationId = (session.session as { activeOrganizationId?: string | null }).activeOrganizationId;
  if (activeOrganizationId) return activeOrganizationId;
  const [membership] = await db.select().from(schema.member)
    .where(eq(schema.member.userId, session.user.id))
    .limit(1);
  return membership?.organizationId ?? "local-tenant";
}
