import { eq } from "drizzle-orm";
import { NextResponse } from "next/server";
import { runTriageAgent } from "@/lib/ai/agents/triage";
import { db, schema } from "@/lib/db/client";
import { playbooks } from "@/lib/rules";
import { getSession } from "@/lib/session";
import { listSigmaRules } from "@/lib/sigma";
import { extractAlertContext } from "@/lib/soc-domain";
import { listAlerts, listThreatIntelMatches } from "@/lib/store";

export async function POST(request: Request) {
  const session = await getSession();
  if (!session) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const body = await request.json().catch(() => ({}));
  const alertId = typeof body.alert_id === "string" ? body.alert_id : "";
  const alerts = await listAlerts();
  const sigmaRules = await listSigmaRules();
  const found = alerts.find((item) => item.id === alertId) ?? alerts[0];

  if (!found) {
    return NextResponse.json(
      {
        verdict: "no_data",
        summary: "No alerts have been ingested yet. Send Tawny alerts to /api/ingest/tawny first.",
        actions: [],
      },
      { status: 404 },
    );
  }

  const tenantId = await resolveTenantId(session);
  const indicators = await listThreatIntelMatches(found.tenantId ?? tenantId);
  const alert = extractAlertContext(found, indicators);
  const matchedRules = sigmaRules.filter((rule) => alert.matchedRules.includes(rule.id));
  const triage = await runTriageAgent(tenantId, { alert, matchedRules, playbooks });
  const playbook = playbooks.find((item) => item.id === triage.suggestedPlaybook);

  return NextResponse.json({
    verdict: triage.verdict,
    confidence: triage.confidence,
    summary: triage.summary,
    rationale: triage.rationale,
    engine: triage.meta,
    evidence: matchedRules.map((rule) => ({
      rule_id: rule.id,
      title: rule.title,
      severity: rule.severity,
      mitre_techniques: rule.mitreTechniques,
    })),
    playbook: playbook
      ? {
          id: playbook.id,
          name: playbook.name,
          phases: playbook.phases.map((phase) => phase.name),
        }
      : null,
    actions: triage.recommendedActions,
  });
}

async function resolveTenantId(session: NonNullable<Awaited<ReturnType<typeof getSession>>>) {
  const activeOrganizationId = (session.session as { activeOrganizationId?: string | null }).activeOrganizationId;
  if (activeOrganizationId) return activeOrganizationId;
  const [membership] = await db.select().from(schema.member)
    .where(eq(schema.member.userId, session.user.id))
    .limit(1);
  return membership?.organizationId ?? "local-tenant";
}
