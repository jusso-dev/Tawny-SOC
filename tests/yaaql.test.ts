import { describe, expect, it } from "vitest";
import type { SocAlert, SocEvent } from "../lib/types";
import { filterWithYaaql, quoteYaaqlValue } from "../lib/yaaql";

const dnsEvent: SocEvent = {
  id: "event-1",
  source: "tawny",
  kind: "telemetry",
  title: "Suspicious DNS Query Shape",
  severity: "medium",
  status: "open",
  timestamp: "2026-05-27T08:34:03.079Z",
  tenantId: "tenant-a",
  agentId: "agent-1",
  hostname: "mac-design-04",
  eventType: "DnsQuery",
  payload: { query_name: "a83kdl29dls02ka9sldk20v.example" },
  matchedRules: ["tawny-sigma-suspicious-dns-dga-shape"],
  mitreTechniques: ["T1071.004", "T1568"],
};

const powershellAlert: SocAlert = {
  id: "alert-1",
  source: "tawny",
  kind: "alert",
  title: "PowerShell Encoded Command Execution",
  severity: "high",
  status: "open",
  timestamp: "2026-05-27T08:26:03.079Z",
  tenantId: "tenant-a",
  agentId: "agent-2",
  hostname: "win-eng-11",
  eventType: "ProcessLaunch",
  payload: {
    alert: {
      command_line: "powershell.exe -NoP -enc SQBFAFgA",
      destination_ip: "203.0.113.10",
    },
  },
  matchedRules: ["tawny-sigma-ps-encoded-command"],
  mitreTechniques: ["T1059.001", "T1027"],
  confidence: 0.81,
  aiSummary: "Encoded PowerShell execution.",
  recommendedPlaybook: "incident-response",
};

const records: SocEvent[] = [dnsEvent, powershellAlert];

describe("YAAQL", () => {
  it("matches field aliases, booleans, and wildcards", () => {
    const result = filterWithYaaql(records, "kind:alert and host:win-* and eventType=ProcessLaunch");

    expect(result.error).toBeUndefined();
    expect(result.records.map((record) => record.id)).toEqual(["alert-1"]);
  });

  it("matches quoted free text and payload paths", () => {
    const result = filterWithYaaql(records, '"powershell.exe" and payload.alert.command_line:*enc*');

    expect(result.records.map((record) => record.id)).toEqual(["alert-1"]);
  });

  it("supports in lists and existence checks", () => {
    const result = filterWithYaaql(records, "severity in (medium, high) and has:domain");

    expect(result.records.map((record) => record.id)).toEqual(["event-1"]);
  });

  it("supports negation and grouped or expressions", () => {
    const result = filterWithYaaql(records, "not (eventType=DnsQuery or severity=critical)");

    expect(result.records.map((record) => record.id)).toEqual(["alert-1"]);
  });

  it("supports numeric and timestamp comparisons", () => {
    const result = filterWithYaaql(records, "confidence>=0.8 and timestamp>=2026-05-27T08:00:00Z");

    expect(result.records.map((record) => record.id)).toEqual(["alert-1"]);
  });

  it("returns parser errors without throwing", () => {
    const result = filterWithYaaql(records, 'host:"win-eng-11');

    expect(result.records).toHaveLength(0);
    expect(result.error).toContain("Unclosed quote");
  });

  it("quotes values for host pivots", () => {
    expect(quoteYaaqlValue('win "eng"')).toBe('"win \\"eng\\""');
  });
});
