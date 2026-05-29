import { filterWithYaaql } from "./yaaql";
import { ruleMatchesPayload } from "./sigma";
import type { SigmaRule, SocEvent } from "./types";

export * from "./correlation/index";

export type CorrelationRule =
  | {
      id: string;
      title: string;
      tenantId?: string;
      kind: "threshold";
      query?: string;
      groupBy: "hostname" | "agentId" | "eventType" | "ruleId" | "tenantId";
      threshold: number;
      windowMinutes: number;
    }
  | {
      id: string;
      title: string;
      tenantId?: string;
      kind: "sequence";
      entity: "hostname" | "agentId" | "tenantId";
      eventTypes: string[];
      windowMinutes: number;
    }
  | {
      id: string;
      title: string;
      tenantId?: string;
      kind: "scheduled-query";
      query: string;
      windowMinutes: number;
      threshold?: number;
    };

export type CorrelationMatch = {
  ruleId: string;
  title: string;
  entity?: string;
  eventIds: string[];
  count: number;
  firstSeen: string;
  lastSeen: string;
};

export type DetectionLifecycleStatus = "draft" | "test" | "enabled" | "disabled" | "deprecated";

export type DetectionTestCase = {
  name: string;
  event: SocEvent;
  shouldMatch: boolean;
};

export function evaluateCorrelationRules(rules: CorrelationRule[], records: SocEvent[], now = new Date()): CorrelationMatch[] {
  return rules.flatMap((rule) => {
    const scoped = records
      .filter((record) => !rule.tenantId || record.tenantId === rule.tenantId)
      .filter((record) => withinWindow(record.timestamp, now, rule.windowMinutes))
      .sort(compareAsc);

    if (rule.kind === "threshold") return evaluateThreshold(rule, scoped);
    if (rule.kind === "sequence") return evaluateSequence(rule, scoped);
    return evaluateScheduledQuery(rule, scoped);
  });
}

export function canTransitionDetection(from: DetectionLifecycleStatus, to: DetectionLifecycleStatus) {
  const allowed: Record<DetectionLifecycleStatus, DetectionLifecycleStatus[]> = {
    draft: ["test", "disabled", "deprecated"],
    test: ["draft", "enabled", "disabled", "deprecated"],
    enabled: ["test", "disabled", "deprecated"],
    disabled: ["draft", "test", "enabled", "deprecated"],
    deprecated: [],
  };
  return allowed[from].includes(to);
}

export function runDetectionTests(rule: SigmaRule, cases: DetectionTestCase[]) {
  const results = cases.map((testCase) => {
    const matched = ruleMatchesPayload(rule, testCase.event.payload, testCase.event.eventType, testCase.event.ruleId);
    return {
      name: testCase.name,
      matched,
      passed: matched === testCase.shouldMatch,
      eventId: testCase.event.id,
    };
  });
  return {
    passed: results.every((result) => result.passed),
    total: results.length,
    failed: results.filter((result) => !result.passed).length,
    results,
  };
}

function evaluateThreshold(rule: Extract<CorrelationRule, { kind: "threshold" }>, records: SocEvent[]): CorrelationMatch[] {
  const filtered = rule.query ? filterWithYaaql(records, rule.query).records : records;
  const groups = groupBy(filtered, (record) => valueFor(record, rule.groupBy));
  return [...groups.entries()].flatMap(([entity, events]) => {
    if (events.length < rule.threshold) return [];
    return [match(rule.id, rule.title, entity, events)];
  });
}

function evaluateSequence(rule: Extract<CorrelationRule, { kind: "sequence" }>, records: SocEvent[]): CorrelationMatch[] {
  const groups = groupBy(records, (record) => valueFor(record, rule.entity));
  return [...groups.entries()].flatMap(([entity, events]) => {
    const matched: SocEvent[] = [];
    let cursor = 0;
    for (const event of events) {
      if ((event.eventType ?? event.kind) === rule.eventTypes[cursor]) {
        matched.push(event);
        cursor += 1;
      }
      if (cursor === rule.eventTypes.length) return [match(rule.id, rule.title, entity, matched)];
    }
    return [];
  });
}

function evaluateScheduledQuery(rule: Extract<CorrelationRule, { kind: "scheduled-query" }>, records: SocEvent[]): CorrelationMatch[] {
  const result = filterWithYaaql(records, rule.query);
  if (result.error || result.records.length < (rule.threshold ?? 1)) return [];
  return [match(rule.id, rule.title, undefined, result.records)];
}

function match(ruleId: string, title: string, entity: string | undefined, events: SocEvent[]): CorrelationMatch {
  return {
    ruleId,
    title,
    entity,
    eventIds: events.map((event) => event.id),
    count: events.length,
    firstSeen: events[0]?.timestamp ?? new Date().toISOString(),
    lastSeen: events.at(-1)?.timestamp ?? new Date().toISOString(),
  };
}

function groupBy<T>(items: T[], keyFor: (item: T) => string) {
  const groups = new Map<string, T[]>();
  for (const item of items) {
    const key = keyFor(item);
    groups.set(key, [...groups.get(key) ?? [], item]);
  }
  return groups;
}

function valueFor(record: SocEvent, key: "hostname" | "agentId" | "eventType" | "ruleId" | "tenantId") {
  return record[key] ?? "unknown";
}

function withinWindow(timestamp: string, now: Date, windowMinutes: number) {
  const time = Date.parse(timestamp);
  return Number.isFinite(time) && time >= now.getTime() - windowMinutes * 60_000 && time <= now.getTime();
}

function compareAsc(a: SocEvent, b: SocEvent) {
  return Date.parse(a.timestamp) - Date.parse(b.timestamp) || a.id.localeCompare(b.id);
}
