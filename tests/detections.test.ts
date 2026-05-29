import { describe, expect, it } from "vitest";
import {
  applyDetectionStatus,
  canTransitionDetectionStatus,
  filterDetectionsForEvaluation,
  normalizeDetectionStatus,
  runDetectionTest,
  runDetectionTests,
} from "../lib/detections";
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
    eventType: "ProcessLaunch",
    payload: {},
    matchedRules: [],
    mitreTechniques: [],
    ...overrides,
  };
}

describe("detection lifecycle", () => {
  it("normalizes lifecycle statuses and enforces transitions", () => {
    expect(normalizeDetectionStatus("stable")).toBe("enabled");
    expect(normalizeDetectionStatus("experimental")).toBe("test");
    expect(canTransitionDetectionStatus("test", "enabled")).toBe(true);
    expect(canTransitionDetectionStatus("enabled", "draft")).toBe(false);

    const enabled = applyDetectionStatus(
      { id: "det-1", status: "test" },
      "enabled",
      { now: "2026-05-29T00:00:00.000Z" },
    );

    expect(enabled.status).toBe("enabled");
    expect(enabled.enabledAt).toBe("2026-05-29T00:00:00.000Z");
    expect(() => applyDetectionStatus(enabled, "draft")).toThrow("cannot transition");
  });

  it("filters active production rules separately from test-mode rules", () => {
    const detections = [
      { id: "draft", status: "draft" },
      { id: "test", status: "test" },
      { id: "enabled", status: "enabled" },
      { id: "disabled", status: "disabled" },
      { id: "deprecated", status: "deprecated" },
    ];

    expect(filterDetectionsForEvaluation(detections, "production").map((item) => item.id)).toEqual(["enabled"]);
    expect(filterDetectionsForEvaluation(detections, "test").map((item) => item.id)).toEqual(["draft", "test", "enabled"]);
  });
});

describe("detection test runner", () => {
  const records = [
    event({
      id: "encoded-ps",
      payload: { command_line: "powershell.exe -NoP -enc SQBFAFgA" },
      matchedRules: ["tawny-sigma-ps-encoded-command"],
    }),
    event({
      id: "benign-cmd",
      payload: { command_line: "cmd.exe /c whoami" },
    }),
    event({
      id: "other-tenant-ps",
      tenantId: "tenant-b",
      payload: { command_line: "powershell.exe -enc SQBFAFgA" },
    }),
  ];

  it("runs sample events and compares expected match ids", () => {
    const result = runDetectionTest({
      id: "encoded-powershell-query",
      status: "test",
      query: '"powershell.exe" and payload.command_line:*-enc*',
    }, {
      name: "encoded powershell samples",
      tenantId: "tenant-a",
      records,
      expectedMatchIds: ["encoded-ps"],
      expectedNonMatchIds: ["benign-cmd"],
    });

    expect(result.passed).toBe(true);
    expect(result.actualMatchIds).toEqual(["encoded-ps"]);
    expect(result.missingMatchIds).toEqual([]);
    expect(result.unexpectedMatchIds).toEqual([]);
  });

  it("reports failed expectations and skips disabled detections", () => {
    const failed = runDetectionTest({
      id: "overbroad-process-query",
      status: "enabled",
      query: "eventType=ProcessLaunch",
    }, {
      records: records.slice(0, 2),
      expectedMatchIds: ["encoded-ps"],
      expectedNonMatchIds: ["benign-cmd"],
    });

    expect(failed.passed).toBe(false);
    expect(failed.unexpectedMatchIds).toEqual(["benign-cmd"]);

    const suite = runDetectionTests({
      id: "disabled-query",
      status: "disabled",
      query: '"powershell.exe"',
    }, [
      { records, expectedMatchIds: [] },
    ]);

    expect(suite.passed).toBe(true);
    expect(suite.results[0].skipped).toBe(true);
  });
});
