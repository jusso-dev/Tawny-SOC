import { describe, expect, it } from "vitest";
import { complianceTemplates, hasPermission, integrationHealth, retentionDecision, slaState } from "../lib/governance";

describe("governance helpers", () => {
  it("enforces the RBAC permission matrix", () => {
    expect(hasPermission("owner", "settings.write")).toBe(true);
    expect(hasPermission("auditor", "settings.write")).toBe(false);
    expect(hasPermission("auditor", "report.export")).toBe(true);
  });

  it("preserves legal holds and case evidence during retention decisions", () => {
    const base = { target: "events" as const, hotDays: 30, archiveDays: 90, deleteAfterDays: 365, preserveCaseEvidence: true, legalHold: false };
    expect(retentionDecision(base, "2025-01-01T00:00:00Z", { now: new Date("2026-05-29T00:00:00Z") })).toBe("delete");
    expect(retentionDecision(base, "2025-01-01T00:00:00Z", { linkedToCase: true, now: new Date("2026-05-29T00:00:00Z") })).toBe("preserve");
    expect(retentionDecision({ ...base, legalHold: true }, "2025-01-01T00:00:00Z", { now: new Date("2026-05-29T00:00:00Z") })).toBe("preserve");
  });

  it("covers required compliance frameworks and operational health states", () => {
    expect(complianceTemplates.map((template) => template.id)).toEqual(["pci-dss", "iso-27001", "nist", "soc-2", "essential-eight"]);
    expect(slaState({ severity: "critical", createdAt: "2026-05-29T00:00:00Z", status: "open" }, { critical: 30, high: 120, medium: 480, low: 1440 }, new Date("2026-05-29T00:31:00Z"))).toBe("breached");
    expect(integrationHealth({ state: "delivered", attempts: 1, lastAttemptAt: "2026-05-29T00:00:00Z" }, true, new Date("2026-05-29T01:00:00Z"))).toBe("healthy");
  });
});
