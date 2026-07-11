import { playbooks } from "@/lib/rules";
import { searchRecords, type SearchPlanInput } from "@/lib/search";
import { getSoarRun, listSoarRuns } from "@/lib/soar";
import { listAlerts, listEvents, listIncidents, listThreatIntelIndicatorsPage } from "@/lib/store";

export async function huntTenant(tenantId: string, input: SearchPlanInput = {}) {
  const [alerts, events] = await Promise.all([listAlerts(tenantId), listEvents(tenantId)]);
  return searchRecords([...alerts, ...events], input, { defaultDataset: "all" });
}

export async function getTenantAlert(tenantId: string, alertId: string) {
  return (await listAlerts(tenantId)).find((alert) => alert.id === alertId) ?? null;
}

export async function listTenantCases(tenantId: string, input: { status?: string; limit?: number } = {}) {
  const limit = boundedLimit(input.limit, 25, 100);
  return (await listIncidents(tenantId))
    .filter((incident) => !input.status || incident.status === input.status)
    .slice(0, limit);
}

export async function getTenantCase(tenantId: string, incidentId: string) {
  return (await listIncidents(tenantId)).find((incident) => incident.id === incidentId) ?? null;
}

export async function listTenantIndicators(tenantId: string, input: { search?: string; type?: string; limit?: number } = {}) {
  const page = await listThreatIntelIndicatorsPage(tenantId, {
    search: input.search,
    type: normalizeIndicatorType(input.type),
    pageSize: boundedLimit(input.limit, 25, 100),
  });
  return { indicators: page.indicators, total: page.total };
}

export function listAgentPlaybooks() {
  return playbooks.map((playbook) => ({
    ...playbook,
    automation: {
      dryRunSupported: true,
      approvalGatedResponse: true,
      phaseCount: playbook.phases.length,
      actionCount: playbook.phases.reduce((total, phase) => total + phase.actions.length, 0),
    },
  }));
}

export { getSoarRun, listSoarRuns };

function normalizeIndicatorType(value?: string) {
  return (["ip", "cidr", "domain", "url", "hash", "email", "file", "cve"] as const).find((type) => type === value) ?? "";
}

function boundedLimit(value: number | undefined, fallback: number, maximum: number) {
  return typeof value === "number" && Number.isFinite(value)
    ? Math.min(maximum, Math.max(1, Math.round(value)))
    : fallback;
}
