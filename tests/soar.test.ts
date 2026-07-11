import { describe, expect, it } from "vitest";
import { buildIncidentHuntQuery, buildSoarPlan, classifySoarAction } from "../lib/soar";
import type { Playbook, SocIncident } from "../lib/types";

const incident: SocIncident = {
  id: "case-1",
  tenantId: "tenant-a",
  number: "SOC-00001",
  title: "Encoded PowerShell",
  severity: "high",
  priority: "P2",
  status: "investigating",
  tags: [],
  tlp: "amber",
  pap: "green",
  classification: "undetermined",
  mitreTechniques: ["T1059.001"],
  observables: [],
  linkedHosts: ["win-01"],
  linkedAlertIds: ["alert-1"],
  kelpieSyncStatus: "not_synced",
  createdAt: "2026-07-11T00:00:00.000Z",
  updatedAt: "2026-07-11T00:00:00.000Z",
  timeline: [],
  tasks: [],
  comments: [],
};

const playbook: Playbook = {
  id: "test-response",
  name: "Test response",
  description: "Test",
  severity: "high",
  agents: ["Investigator", "Responder"],
  triggers: ["test"],
  phases: [
    { name: "Investigate", owner: "Investigator", objective: "Find evidence", actions: ["Check nearby host events", "Correlate ATT&CK techniques"] },
    { name: "Contain", owner: "Responder", objective: "Stop activity", actions: ["Recommend host isolation", "Document the decision"] },
  ],
};

describe("SOAR planning", () => {
  it("classifies investigation and response actions deterministically", () => {
    expect(classifySoarAction("Search endpoint telemetry")).toBe("hunt");
    expect(classifySoarAction("Enrich domain reputation")).toBe("enrichment");
    expect(classifySoarAction("Isolate the affected host")).toBe("response");
    expect(classifySoarAction("Notify the incident commander")).toBe("notification");
  });

  it("approval-gates response actions while planning hunts with case context", () => {
    const plan = buildSoarPlan(playbook, incident);
    expect(plan).toHaveLength(4);
    expect(plan.find((action) => action.action.includes("isolation"))).toMatchObject({ kind: "response", approvalRequired: true, status: "planned" });
    expect(plan[0].input.query).toContain('host="win-01"');
    expect(plan[1].input.query).toContain('mitre="T1059.001"');
  });

  it("builds a severity fallback query for cases without entities", () => {
    expect(buildIncidentHuntQuery("Review evidence", { ...incident, linkedHosts: [], mitreTechniques: [] })).toBe("severity in (high, critical)");
  });
});
