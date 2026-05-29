import { describe, expect, it } from "vitest";
import {
  isScheduledDetectionDue,
  runScheduledQueryDetection,
  runSequenceDetection,
  runThresholdDetection,
} from "../lib/correlation";
import type { SocEvent } from "../lib/types";

function event(overrides: Partial<SocEvent>): SocEvent {
  return {
    id: "event",
    source: "tawny",
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

describe("correlation helpers", () => {
  it("detects threshold matches inside a sliding multi-event window", () => {
    const records = [
      event({ id: "auth-1", timestamp: "2026-05-29T00:00:00.000Z", payload: { user: "alice" } }),
      event({ id: "auth-2", timestamp: "2026-05-29T00:02:00.000Z", payload: { user: "alice" } }),
      event({ id: "auth-3", timestamp: "2026-05-29T00:04:00.000Z", payload: { user: "alice" } }),
      event({ id: "auth-4", timestamp: "2026-05-29T00:11:00.000Z", payload: { user: "alice" } }),
    ];

    const matches = runThresholdDetection(records, {
      id: "three-failures",
      query: "eventType=AuthFailure",
      threshold: 3,
      windowMs: 5 * 60 * 1000,
      groupBy: ["host", "payload.user"],
    });

    expect(matches).toHaveLength(1);
    expect(matches[0].eventIds).toEqual(["auth-1", "auth-2", "auth-3"]);
    expect(matches[0].groupValues).toMatchObject({ tenantId: "tenant-a", host: "win-01", "payload.user": "alice" });
  });

  it("keeps threshold matches tenant-scoped by default", () => {
    const records = [
      event({ id: "tenant-a-1", timestamp: "2026-05-29T00:00:00.000Z", tenantId: "tenant-a", payload: { user: "alice" } }),
      event({ id: "tenant-a-2", timestamp: "2026-05-29T00:01:00.000Z", tenantId: "tenant-a", payload: { user: "alice" } }),
      event({ id: "tenant-b-1", timestamp: "2026-05-29T00:02:00.000Z", tenantId: "tenant-b", payload: { user: "alice" } }),
    ];

    const rule = {
      id: "tenant-boundary",
      query: "eventType=AuthFailure",
      threshold: 3,
      windowMs: 5 * 60 * 1000,
      groupBy: ["host", "payload.user"],
    };

    expect(runThresholdDetection(records, rule)).toHaveLength(0);
    expect(runThresholdDetection(records, { ...rule, tenantScoped: false })).toHaveLength(1);
  });

  it("matches sequences from out-of-order input without crossing tenants", () => {
    const success = event({
      id: "success-1",
      timestamp: "2026-05-29T00:03:00.000Z",
      eventType: "AuthSuccess",
      payload: { user: "alice" },
    });
    const failure = event({
      id: "failure-1",
      timestamp: "2026-05-29T00:00:00.000Z",
      eventType: "AuthFailure",
      payload: { user: "alice" },
    });
    const otherTenantSuccess = event({
      id: "tenant-b-success",
      tenantId: "tenant-b",
      timestamp: "2026-05-29T00:01:00.000Z",
      eventType: "AuthSuccess",
      payload: { user: "alice" },
    });

    const matches = runSequenceDetection([success, otherTenantSuccess, failure], {
      id: "failure-then-success",
      windowMs: 5 * 60 * 1000,
      groupBy: ["host", "payload.user"],
      stages: [
        { id: "failed-login", query: "eventType=AuthFailure" },
        { id: "successful-login", query: "eventType=AuthSuccess" },
      ],
    });

    expect(matches).toHaveLength(1);
    expect(matches[0].eventIds).toEqual(["failure-1", "success-1"]);
    expect(matches[0].stages.map((stage) => stage.stageId)).toEqual(["failed-login", "successful-login"]);
  });

  it("runs scheduled query detections over lookback windows", () => {
    const records = [
      event({ id: "new-high-1", severity: "high", timestamp: "2026-05-29T00:50:00.000Z", eventType: "ProcessLaunch" }),
      event({ id: "new-high-2", severity: "high", timestamp: "2026-05-29T00:55:00.000Z", eventType: "ProcessLaunch" }),
      event({ id: "old-high", severity: "high", timestamp: "2026-05-29T00:10:00.000Z", eventType: "ProcessLaunch" }),
      event({ id: "tenant-b-high", tenantId: "tenant-b", severity: "high", timestamp: "2026-05-29T00:56:00.000Z", eventType: "ProcessLaunch" }),
    ];

    const run = runScheduledQueryDetection(records, {
      id: "recent-high-processes",
      query: "severity=high and eventType=ProcessLaunch",
      lookbackMs: 15 * 60 * 1000,
      threshold: 2,
      intervalMs: 5 * 60 * 1000,
      lastRunAt: "2026-05-29T00:50:00.000Z",
    }, { now: "2026-05-29T01:00:00.000Z" });

    expect(run.due).toBe(true);
    expect(run.recordCount).toBe(3);
    expect(run.matches).toHaveLength(1);
    expect(run.matches[0].eventIds).toEqual(["new-high-1", "new-high-2"]);
    expect(isScheduledDetectionDue({ intervalMs: 5 * 60 * 1000, lastRunAt: "2026-05-29T00:58:00.000Z" }, "2026-05-29T01:00:00.000Z")).toBe(false);
  });
});
