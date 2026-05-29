import { describe, expect, it } from "vitest";
import {
  canPerformSocAction,
  assertSocAction,
  SOC_PERMISSION_MATRIX,
  SocAuthorizationError,
} from "../lib/rbac/soc-permissions";
import {
  calculateRetentionDecision,
  resolveRetentionPolicy,
  retentionSweepPlan,
} from "../lib/retention/policies";
import {
  getComplianceReportTemplate,
  listComplianceReportTemplates,
  validateComplianceTemplateCoverage,
  type ComplianceFrameworkId,
} from "../lib/compliance/report-templates";
import {
  calculateIncidentSlaState,
  canTransitionIncidentStatus,
  createIncidentEvidenceRecord,
} from "../lib/governance/incident-lifecycle";
import {
  calculateIntegrationFleetHealth,
  calculateIntegrationHealth,
} from "../lib/governance/integration-health";
import type { IntegrationDelivery, SocIncident } from "../lib/types";

const now = new Date("2026-05-29T01:00:00.000Z");

const incident: SocIncident = {
  id: "case-1",
  tenantId: "tenant-a",
  number: "SOC-00001",
  title: "Critical identity compromise",
  severity: "critical",
  priority: "P1",
  status: "investigating",
  assignee: "Analyst One",
  tags: ["identity"],
  tlp: "amber",
  pap: "green",
  classification: "undetermined",
  mitreTechniques: ["T1078"],
  observables: [],
  linkedHosts: ["dc-01"],
  linkedAlertIds: ["alert-1"],
  kelpieSyncStatus: "not_synced",
  createdAt: "2026-05-29T00:00:00.000Z",
  updatedAt: "2026-05-29T00:10:00.000Z",
  timeline: [],
  tasks: [],
  comments: [],
};

describe("enterprise SIEM governance helpers", () => {
  it("guards SOC actions with a reusable role and permission matrix", () => {
    expect(SOC_PERMISSION_MATRIX.member).toContain("incident.create");
    expect(canPerformSocAction("member", "dismiss-alert")).toBe(true);
    expect(canPerformSocAction("member", "suppress-alert")).toBe(false);
    expect(canPerformSocAction("admin", "sync-incident-kelpie", { kelpieRole: "owner" })).toBe(false);
    expect(canPerformSocAction("owner", "sync-incident-kelpie", { kelpieRole: "owner" })).toBe(true);

    expect(() => assertSocAction({ id: "user-1", role: "member" }, "add-user")).toThrow(SocAuthorizationError);
  });

  it("calculates retention decisions and preserves active legal holds", () => {
    const policy = resolveRetentionPolicy("delivery_logs", {
      delivery_logs: { archiveAfterDays: 7, deleteAfterDays: 30 },
    });
    const expired = {
      id: "delivery-1",
      dataset: "delivery_logs" as const,
      createdAt: "2026-04-01T00:00:00.000Z",
    };

    expect(calculateRetentionDecision(expired, policy, now).action).toBe("delete");
    expect(calculateRetentionDecision({ ...expired, legalHold: true }, policy, now).action).toBe("preserve_legal_hold");
    expect(calculateRetentionDecision({ ...expired, legalHoldUntil: "2026-06-30T00:00:00.000Z" }, policy, now).action).toBe("preserve_legal_hold");

    const plan = retentionSweepPlan([expired], { delivery_logs: { archiveAfterDays: 7, deleteAfterDays: 30 } }, now);
    expect(plan[0].recordId).toBe("delivery-1");
  });

  it("defines report templates with required SIEM evidence coverage", () => {
    const expectedIds: ComplianceFrameworkId[] = ["pci-dss", "iso-27001", "nist-csf", "soc-2", "essential-eight"];
    const templates = listComplianceReportTemplates();

    expect(templates.map((template) => template.id).sort()).toEqual([...expectedIds].sort());
    for (const template of templates) {
      expect(template.sections.length).toBeGreaterThanOrEqual(5);
      expect(validateComplianceTemplateCoverage(template)).toEqual([]);
    }

    expect(getComplianceReportTemplate("pci-dss").version).toBe("PCI DSS v4.0.1");
    expect(getComplianceReportTemplate("nist-csf").version).toBe("CSF 2.0");
  });

  it("reports containment SLA breach state and lifecycle transitions", () => {
    const breached = calculateIncidentSlaState(incident, undefined, now);
    expect(breached.state).toBe("breached");
    expect(breached.breachedByMinutes).toBe(30);

    const met = calculateIncidentSlaState({ ...incident, status: "contained" }, undefined, now);
    expect(met.state).toBe("met");
    expect(canTransitionIncidentStatus("investigating", "contained")).toBe(true);
    expect(canTransitionIncidentStatus("closed", "contained")).toBe(false);
  });

  it("creates evidence records with custody metadata", () => {
    const evidence = createIncidentEvidenceRecord({
      id: "ev-1",
      incidentId: "case-1",
      type: "log",
      title: "EDR process tree",
      source: "edr://win-01/processes/123",
      collectedAt: now.toISOString(),
      collectedBy: "Analyst One",
      hash: "sha256:abc",
      legalHold: true,
    });

    expect(evidence.legalHold).toBe(true);
    expect(evidence.chainOfCustody[0]).toMatchObject({ action: "collected", actor: "Analyst One" });
  });

  it("calculates integration health from delivery outcomes", () => {
    const healthy = calculateIntegrationHealth({
      id: "slack",
      label: "Slack",
      enabled: true,
      configured: true,
      staleAfterMinutes: 60,
      deliveries: [delivery("delivered", 5)],
    }, now);

    const failing = calculateIntegrationHealth({
      id: "sentinel",
      label: "Sentinel",
      enabled: true,
      configured: true,
      failureThreshold: 3,
      deliveries: [delivery("failed", 1), delivery("retrying", 2), delivery("failed", 3), delivery("delivered", 90)],
    }, now);

    const notConfigured = calculateIntegrationHealth({
      id: "webhook",
      label: "Webhook",
      enabled: true,
      configured: false,
    }, now);

    expect(healthy.status).toBe("healthy");
    expect(failing.status).toBe("failing");
    expect(failing.consecutiveFailures).toBe(3);
    expect(notConfigured.status).toBe("not_configured");
    expect(calculateIntegrationFleetHealth([healthy, failing, notConfigured]).status).toBe("failing");
  });
});

function delivery(state: IntegrationDelivery["state"], minutesAgo: number): IntegrationDelivery {
  return {
    id: `delivery-${state}-${minutesAgo}`,
    channel: "webhook",
    target: "https://example.test/hook",
    state,
    attempts: 1,
    lastAttemptAt: new Date(now.getTime() - minutesAgo * 60_000).toISOString(),
    error: state === "failed" ? "HTTP 500" : undefined,
  };
}
