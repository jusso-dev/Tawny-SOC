import { NextResponse } from "next/server";
import { playbooks, sigmaRules } from "@/lib/rules";
import { listAlerts } from "@/lib/store";

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  const alertId = typeof body.alert_id === "string" ? body.alert_id : "";
  const alerts = await listAlerts();
  const alert = alerts.find((item) => item.id === alertId) ?? alerts[0];

  if (!alert) {
    return NextResponse.json(
      {
        verdict: "no_data",
        summary: "No alerts have been ingested yet. Send Tawny alerts to /api/ingest/tawny first.",
        actions: [],
      },
      { status: 404 },
    );
  }

  const matchedRules = sigmaRules.filter((rule) => alert.matchedRules.includes(rule.id));
  const playbook = playbooks.find((item) => item.id === alert.recommendedPlaybook);

  return NextResponse.json({
    verdict: alert.severity === "critical" || alert.severity === "high" ? "investigate" : "review",
    confidence: alert.confidence,
    summary: alert.aiSummary,
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
    actions: [
      "Pivot on host and telemetry ID in Tawny",
      "Review matching Sigma source and false-positive notes",
      "Run the recommended playbook before containment",
    ],
  });
}
