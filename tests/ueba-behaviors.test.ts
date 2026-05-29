import { describe, expect, it } from "vitest";
import {
  buildBehaviorRecords,
  summarizeBehaviorEntities,
} from "../lib/ueba";
import type { SocEvent } from "../lib/types";

function event(overrides: Partial<SocEvent>): SocEvent {
  return {
    id: "event-1",
    source: "connector",
    kind: "telemetry",
    title: "Telemetry event",
    severity: "low",
    status: "open",
    timestamp: "2026-05-29T00:00:00.000Z",
    tenantId: "tenant-a",
    hostname: "win-01",
    eventType: "ProcessLaunch",
    payload: {},
    matchedRules: [],
    mitreTechniques: [],
    ...overrides,
  };
}

describe("UEBA behavior records", () => {
  it("converts process telemetry into explainable analyst behavior", () => {
    const behaviors = buildBehaviorRecords([
      event({
        id: "ps-1",
        severity: "high",
        payload: {
          user: "alice",
          command_line: "powershell.exe -NoP -enc SQBFAFgA",
          image: "powershell.exe",
        },
        matchedRules: ["tawny-sigma-ps-encoded-command"],
        mitreTechniques: ["T1059.001"],
      }),
    ]);

    const process = behaviors.find((behavior) => behavior.category === "process");
    expect(process).toMatchObject({
      actor: { kind: "user", value: "alice" },
      behavior: "suspicious_process_execution",
      target: { kind: "process", value: "powershell.exe" },
    });
    expect(process?.riskScore).toBeGreaterThanOrEqual(80);
    expect(process?.reasons).toEqual(expect.arrayContaining([
      "Command line matched suspicious marker: powershell",
      "Command line matched suspicious marker: encoded command",
    ]));

    const detectionContext = behaviors.find((behavior) => behavior.category === "threat_intel");
    expect(detectionContext?.reasons.join(" ")).toContain("tawny-sigma-ps-encoded-command");
  });

  it("extracts authentication and network behavior without hiding evidence", () => {
    const behaviors = buildBehaviorRecords([
      event({
        id: "auth-1",
        eventType: "AuthFailure",
        title: "Failed authentication",
        payload: {
          user: "bob",
          source_ip: "198.51.100.5",
          outcome: "failure",
        },
      }),
      event({
        id: "fw-1",
        eventType: "FirewallDeny",
        hostname: "fw-01",
        payload: {
          src: "10.0.0.5",
          dst: "203.0.113.10",
          dpt: 443,
          action: "deny",
        },
      }),
    ]);

    expect(behaviors.map((behavior) => behavior.category)).toEqual(expect.arrayContaining(["authentication", "network"]));
    expect(behaviors.find((behavior) => behavior.category === "authentication")?.summary).toContain("bob failed authentication");
    const firewallBehavior = behaviors.find((behavior) => behavior.category === "network" && behavior.sourceEventIds.includes("fw-1"));
    expect(firewallBehavior?.reasons).toEqual(expect.arrayContaining([
      "Destination IP observed: 203.0.113.10",
      "Destination port observed: 443",
    ]));
  });

  it("summarizes entity risk inside tenant boundaries", () => {
    const behaviors = buildBehaviorRecords([
      event({ id: "a-1", tenantId: "tenant-a", payload: { user: "alice", command_line: "powershell.exe -enc SQBFAFgA" } }),
      event({ id: "a-2", tenantId: "tenant-a", eventType: "AuthFailure", payload: { user: "alice", outcome: "failure" } }),
      event({ id: "b-1", tenantId: "tenant-b", eventType: "AuthFailure", payload: { user: "alice", outcome: "failure" } }),
    ]);

    const summaries = summarizeBehaviorEntities(behaviors);
    const tenantA = summaries.find((summary) => summary.tenantId === "tenant-a" && summary.entity.value === "alice");
    const tenantB = summaries.find((summary) => summary.tenantId === "tenant-b" && summary.entity.value === "alice");

    expect(tenantA?.behaviorCount).toBeGreaterThan(tenantB?.behaviorCount ?? 0);
    expect(tenantA?.sourceEventIds).toEqual(expect.arrayContaining(["a-1", "a-2"]));
    expect(tenantB?.sourceEventIds).toEqual(["b-1"]);
  });
});
