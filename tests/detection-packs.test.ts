import { describe, expect, it } from "vitest";
import {
  runSummaryRules,
  starterDetectionPack,
  validateDetectionPack,
  type DetectionSummaryRule,
} from "../lib/detections";
import type { SocEvent } from "../lib/types";

function event(overrides: Partial<SocEvent>): SocEvent {
  return {
    id: "event",
    source: "connector",
    kind: "telemetry",
    title: "Telemetry event",
    severity: "low",
    status: "open",
    timestamp: "2026-05-29T00:00:00.000Z",
    tenantId: "tenant-a",
    hostname: "win-01",
    eventType: "AuthFailure",
    payload: {},
    matchedRules: [],
    mitreTechniques: [],
    ...overrides,
  };
}

describe("detection packs and summary rules", () => {
  it("validates the starter portable detection pack", () => {
    expect(validateDetectionPack(starterDetectionPack)).toEqual([]);
    expect(starterDetectionPack.repository?.path).toBe("detections/tawny-soc-starter-behavior-pack.json");
    expect(starterDetectionPack.repository?.ciCommand).toContain("pnpm test");
  });

  it("reports invalid pack queries and duplicate ids", () => {
    const issues = validateDetectionPack({
      ...starterDetectionPack,
      detections: [
        {
          id: "duplicate-rule",
          title: "Broken query",
          status: "test",
          severity: "low",
          query: "severity=(high",
          mitreTechniques: [],
        },
      ],
      summaryRules: [
        {
          id: "duplicate-rule",
          name: "Duplicate",
          description: "Duplicate id",
          query: "severity=high",
          groupBy: [],
          windowMinutes: 0,
          threshold: 0,
          severity: "low",
        },
      ],
    });

    expect(issues.map((issue) => issue.path)).toEqual(expect.arrayContaining([
      "detections[0].query",
      "summaryRules[0].id",
      "summaryRules[0].windowMinutes",
      "summaryRules[0].threshold",
    ]));
  });

  it("runs tenant-scoped summary rules for repeated behavior", () => {
    const rule: DetectionSummaryRule = {
      id: "auth-burst",
      name: "Auth burst",
      description: "Repeated failures by user and host",
      query: "type=AuthFailure",
      groupBy: ["user", "host"],
      windowMinutes: 30,
      threshold: 3,
      severity: "medium",
    };
    const records = [
      event({ id: "a-1", timestamp: "2026-05-29T00:00:00.000Z", payload: { user: "alice" } }),
      event({ id: "a-2", timestamp: "2026-05-29T00:05:00.000Z", payload: { user: "alice" } }),
      event({ id: "a-3", timestamp: "2026-05-29T00:10:00.000Z", payload: { user: "alice" } }),
      event({ id: "b-1", tenantId: "tenant-b", timestamp: "2026-05-29T00:11:00.000Z", payload: { user: "alice" } }),
    ];

    const signals = runSummaryRules(records, [rule], { now: "2026-05-29T00:30:00.000Z" });

    expect(signals).toHaveLength(1);
    expect(signals[0]).toMatchObject({
      count: 3,
      groupValues: { user: "alice", host: "win-01" },
      tenantId: "tenant-a",
    });
    expect(signals[0].recordIds).toEqual(["a-1", "a-2", "a-3"]);
    expect(signals[0].reasons).toEqual(expect.arrayContaining(["Threshold: 3"]));
  });

  it("can summarize unique entities instead of raw records", () => {
    const rule: DetectionSummaryRule = {
      id: "rare-destinations",
      name: "Unique destinations",
      description: "Multiple destinations reached by host",
      query: "type=NetworkConnection",
      groupBy: ["host"],
      uniqueField: "payload.destination_ip",
      windowMinutes: 60,
      threshold: 2,
      severity: "medium",
      tenantScoped: false,
    };
    const records = [
      event({ id: "net-1", eventType: "NetworkConnection", payload: { destination_ip: "203.0.113.1" } }),
      event({ id: "net-2", eventType: "NetworkConnection", payload: { destination_ip: "203.0.113.2" } }),
      event({ id: "net-3", eventType: "NetworkConnection", payload: { destination_ip: "203.0.113.2" } }),
    ];

    const signals = runSummaryRules(records, [rule], { now: "2026-05-29T00:30:00.000Z" });

    expect(signals).toHaveLength(1);
    expect(signals[0].uniqueCount).toBe(2);
    expect(signals[0].tenantId).toBe("*");
  });
});
