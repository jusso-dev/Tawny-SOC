import { describe, expect, it } from "vitest";
import type { SocEvent } from "../lib/types";
import {
  createSearchPlan,
  decodeSearchCursor,
  MAX_SEARCH_LIMIT,
  searchRecords,
  serializeSearchExport,
  serializeSearchResultsToCsv,
  serializeSearchResultsToJson,
} from "../lib/search";

function record(overrides: Partial<SocEvent> & Pick<SocEvent, "id" | "timestamp">): SocEvent {
  const { id, timestamp, ...rest } = overrides;

  return {
    agentId: "agent-1",
    eventType: "ProcessLaunch",
    hostname: "win-alpha",
    id,
    kind: "telemetry",
    matchedRules: [],
    mitreTechniques: [],
    os: "macOS",
    payload: {},
    severity: "medium",
    source: "tawny",
    status: "open",
    tenantId: "tenant-a",
    timestamp,
    title: "Generic event",
    ...rest,
  };
}

const records: SocEvent[] = [
  record({
    eventType: "ProcessLaunch",
    hostname: "win-alpha",
    id: "alert-z",
    kind: "alert",
    matchedRules: ["rule-ps"],
    mitreTechniques: ["T1059.001"],
    payload: { command_line: "powershell.exe -enc SQBFAFgA" },
    severity: "high",
    timestamp: "2026-05-27T10:00:00.000Z",
    title: "PowerShell, encoded command",
  }),
  record({
    eventType: "DnsQuery",
    hostname: "mac-c",
    id: "event-c",
    matchedRules: ["rule-dns"],
    payload: { query_name: "c.example.test" },
    timestamp: "2026-05-27T09:00:00.000Z",
    title: "Suspicious DNS shape C",
  }),
  record({
    eventType: "DnsQuery",
    hostname: "mac-b",
    id: "event-b",
    matchedRules: ["rule-dns"],
    payload: { query_name: "b.example.test" },
    timestamp: "2026-05-27T09:00:00.000Z",
    title: "Suspicious DNS shape B",
  }),
  record({
    eventType: "FileWrite",
    hostname: "mac-a",
    id: "event-a",
    payload: { path: "/tmp/dropper" },
    timestamp: "2026-05-27T08:00:00.000Z",
    title: "Older event",
  }),
];

describe("search planning and execution", () => {
  it("produces deterministic timestamp and id ordering regardless of input order", () => {
    const first = searchRecords([records[2], records[0], records[3], records[1]], { limit: 10 });
    const second = searchRecords([...records].reverse(), { limit: 10 });

    expect(first.ok).toBe(true);
    expect(first.records.map((item) => item.id)).toEqual(["alert-z", "event-c", "event-b", "event-a"]);
    expect(second.records.map((item) => item.id)).toEqual(first.records.map((item) => item.id));
  });

  it("uses a stable cursor so new earlier records do not shift the next page", () => {
    const firstPage = searchRecords(records, { limit: 2 });

    expect(firstPage.records.map((item) => item.id)).toEqual(["alert-z", "event-c"]);
    expect(firstPage.pageInfo.hasNextPage).toBe(true);
    expect(firstPage.pageInfo.nextCursor).toBeDefined();

    const cursor = firstPage.pageInfo.nextCursor ?? "";
    const decoded = decodeSearchCursor(cursor);
    expect(decoded.ok && decoded.cursor.id).toBe("event-c");

    const withNewerRecord = [
      record({
        id: "alert-new",
        kind: "alert",
        severity: "critical",
        timestamp: "2026-05-27T11:00:00.000Z",
        title: "New alert after page one",
      }),
      ...records,
    ];
    const secondPage = searchRecords(withNewerRecord, { cursor, limit: 2 });

    expect(secondPage.ok).toBe(true);
    expect(secondPage.records.map((item) => item.id)).toEqual(["event-b", "event-a"]);
    expect(secondPage.pageInfo.hasNextPage).toBe(false);
  });

  it("applies dataset scope, clamped limits, and inclusive time bounds before YAAQL", () => {
    const planned = createSearchPlan({
      dataset: "events",
      from: "2026-05-27T09:00:00.000Z",
      limit: "5000",
      q: "type=DnsQuery",
      to: "2026-05-27T10:00:00.000Z",
    });

    expect(planned.ok).toBe(true);
    if (!planned.ok) return;
    expect(planned.plan.limit).toBe(MAX_SEARCH_LIMIT);
    expect(planned.plan.scope).toBe("telemetry");
    expect(planned.warnings[0]).toContain("clamped");

    const result = searchRecords(records, {
      dataset: "events",
      from: "2026-05-27T09:00:00.000Z",
      limit: "5000",
      q: "type=DnsQuery",
      to: "2026-05-27T10:00:00.000Z",
    });

    expect(result.ok).toBe(true);
    expect(result.records.map((item) => item.id)).toEqual(["event-c", "event-b"]);
    expect(result.totalMatched).toBe(2);
  });

  it("supports relative search ranges anchored to the supplied clock", () => {
    const result = searchRecords(records, {
      now: "2026-05-27T10:30:00.000Z",
      range: "90m",
    });

    expect(result.ok).toBe(true);
    expect(result.plan?.timeRange).toEqual({
      from: "2026-05-27T09:00:00.000Z",
      label: "last 90m",
      to: "2026-05-27T10:30:00.000Z",
    });
    expect(result.records.map((item) => item.id)).toEqual(["alert-z", "event-c", "event-b"]);
  });

  it("returns invalid YAAQL queries as search errors without throwing", () => {
    const result = searchRecords(records, { q: 'host:"win-alpha' });

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("invalid_query");
    expect(result.error?.message).toContain("Unclosed quote");
    expect(result.records).toEqual([]);
  });

  it("serializes bounded result sets to JSON and CSV exports", () => {
    const result = searchRecords(records, { dataset: "alerts", q: "severity=high" });

    expect(result.ok).toBe(true);
    expect(result.plan).toBeDefined();
    if (!result.plan) return;

    const json = serializeSearchResultsToJson(result.records, result.plan, {
      exportedAt: "2026-05-28T00:00:00.000Z",
      includePayload: false,
    });
    const parsed = JSON.parse(json) as { dataset: string; exportedAt: string; records: Array<Record<string, unknown>>; resultCount: number };

    expect(parsed.dataset).toBe("alerts");
    expect(parsed.exportedAt).toBe("2026-05-28T00:00:00.000Z");
    expect(parsed.resultCount).toBe(1);
    expect(parsed.records[0].id).toBe("alert-z");
    expect(parsed.records[0].payload).toBeUndefined();

    const csv = serializeSearchResultsToCsv(result.records, result.plan);
    expect(csv.split("\n")[0]).toContain("id,timestamp,kind,severity");
    expect(csv).toContain('"PowerShell, encoded command"');
    expect(csv).toContain('"{""command_line"":""powershell.exe -enc SQBFAFgA""}"');

    const envelope = serializeSearchExport(result.records, result.plan, "csv");
    expect(envelope.contentType).toBe("text/csv; charset=utf-8");
    expect(envelope.filenameExtension).toBe("csv");
  });
});
