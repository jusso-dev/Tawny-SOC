import { describe, expect, it, vi } from "vitest";
import {
  applySuppressionRules,
  assignAlert,
  assignIncident,
  createIncidentFromAlert,
  enrichAlertWithThreatIntel,
  filterTenantAlerts,
  promoteAlertToKelpie,
  promoteIncidentToKelpie,
  recordDeliveryState,
} from "../lib/soc-workflows";
import type { KelpieIntegrationConfig, SocAlert, ThreatIntelMatch } from "../lib/types";

const actor = { id: "user-1", name: "Analyst One", tenantId: "tenant-a" };

const alert: SocAlert = {
  id: "alert-1",
  source: "tawny",
  kind: "alert",
  title: "Encoded PowerShell",
  severity: "high",
  status: "open",
  timestamp: "2026-05-27T01:00:00.000Z",
  tenantId: "tenant-a",
  agentId: "agent-1",
  hostname: "win-01",
  eventType: "ProcessLaunch",
  payload: { command_line: "powershell.exe -enc AA==", destination_ip: "203.0.113.10" },
  matchedRules: ["tawny-sigma-ps-encoded-command"],
  mitreTechniques: ["T1059.001"],
  confidence: 0.72,
  aiSummary: "Suspicious encoded PowerShell.",
  recommendedPlaybook: "incident-response",
  externalIps: ["203.0.113.10"],
};

const ioc: ThreatIntelMatch = {
  id: "ioc-1",
  type: "ip",
  value: "203.0.113.10",
  sourceFeed: "test feed",
  confidence: 88,
  tags: ["c2"],
  firstSeen: "2026-05-26T01:00:00.000Z",
  lastSeen: "2026-05-27T01:00:00.000Z",
};

const kelpieConfig: KelpieIntegrationConfig = {
  enabled: true,
  baseUrl: "http://kelpie.local",
  tokenConfigured: true,
  dedupeBy: "externalRef",
  syncFields: ["status", "assignee", "severity", "observables", "comments"],
};

describe("SOC workflows", () => {
  it("creates an incident from an alert", () => {
    const incident = createIncidentFromAlert(alert, actor, 41);

    expect(incident.number).toBe("SOC-00042");
    expect(incident.linkedAlertIds).toEqual(["alert-1"]);
    expect(incident.priority).toBe("P2");
    expect(incident.timeline[0].action).toBe("created_incident_from_alert");
  });

  it("assigns alerts and cases with tenant isolation", () => {
    const assigned = assignAlert(alert, "Analyst Two", actor);
    expect(assigned.assignee).toBe("Analyst Two");
    expect(assigned.status).toBe("triaging");

    const incident = createIncidentFromAlert(alert, actor);
    expect(assignIncident(incident, "Analyst Two", actor).assignee).toBe("Analyst Two");
    expect(() => assignAlert({ ...alert, tenantId: "tenant-b" }, "Analyst Two", actor)).toThrow("Cross-tenant");
  });

  it("enriches alerts with threat intel matches", () => {
    const enriched = enrichAlertWithThreatIntel(alert, [ioc]);
    expect(enriched.tiMatches).toHaveLength(1);
    expect(enriched.confidence).toBeGreaterThan(alert.confidence);
  });

  it("promotes an alert to Kelpie with externalRef dedupe", async () => {
    const client = { createAlert: vi.fn(async () => ({ id: "KAL-1", url: "http://kelpie.local/alerts/KAL-1" })), createCase: vi.fn() };
    const delivery = await promoteAlertToKelpie(alert, kelpieConfig, client);

    expect(delivery.state).toBe("delivered");
    expect(client.createAlert).toHaveBeenCalledWith(expect.objectContaining({ externalRef: "tawny-alert-alert-1" }));
  });

  it("creates and syncs Kelpie cases", async () => {
    const incident = createIncidentFromAlert(enrichAlertWithThreatIntel(alert, [ioc]), actor);
    const client = { createAlert: vi.fn(), createCase: vi.fn(async () => ({ id: "KEL-1", url: "http://kelpie.local/cases/KEL-1" })) };
    const synced = await promoteIncidentToKelpie(incident, kelpieConfig, client);

    expect(synced.kelpieSyncStatus).toBe("synced");
    expect(synced.kelpieCaseId).toBe("KEL-1");
    expect(client.createCase).toHaveBeenCalledWith(expect.objectContaining({ externalRef: `tawny-case-${incident.id}` }));
  });

  it("records notification delivery state", () => {
    const failed = recordDeliveryState(undefined, "failed", "timeout");
    const retrying = recordDeliveryState(failed, "retrying");

    expect(failed.error).toBe("timeout");
    expect(retrying.attempts).toBe(2);
  });

  it("filters tenant alerts", () => {
    expect(filterTenantAlerts([alert, { ...alert, id: "alert-2", tenantId: "tenant-b" }], "tenant-a")).toHaveLength(1);
  });

  it("applies suppression rules", () => {
    const suppressed = applySuppressionRules(alert, [
      {
        id: "sup-1",
        tenantId: "tenant-a",
        name: "Suppress noisy host",
        enabled: true,
        host: "win-01",
        reason: "Maintenance window",
      },
    ]);

    expect(suppressed.status).toBe("suppressed");
  });
});
