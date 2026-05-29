import type { Severity, SocEvent } from "../types";
import { filterWithYaaql } from "../yaaql";

type Scalar = string | number | boolean;

export type CorrelationRecordPredicate<T extends SocEvent = SocEvent> = (record: T) => boolean;
export type CorrelationGroupBy<T extends SocEvent = SocEvent> =
  | string
  | ((record: T) => string | number | boolean | null | undefined);

export type CorrelationClause<T extends SocEvent = SocEvent> = {
  query?: string;
  predicate?: CorrelationRecordPredicate<T>;
  tenantId?: string;
  kinds?: SocEvent["kind"][];
  eventTypes?: string[];
  severities?: Severity[];
  ruleIds?: string[];
};

export type CorrelationMatchType = "threshold" | "sequence" | "scheduled_query";

export type CorrelationMatch<T extends SocEvent = SocEvent> = {
  id: string;
  ruleId: string;
  type: CorrelationMatchType;
  title?: string;
  tenantId?: string;
  groupKey: string;
  groupValues: Record<string, string>;
  startedAt: string;
  endedAt: string;
  count: number;
  eventIds: string[];
  records: T[];
  reason: string;
};

export type ThresholdDetectionRule<T extends SocEvent = SocEvent> = CorrelationClause<T> & {
  id: string;
  title?: string;
  threshold: number;
  windowMs: number;
  groupBy?: CorrelationGroupBy<T> | Array<CorrelationGroupBy<T>>;
  tenantScoped?: boolean;
  allowOverlappingMatches?: boolean;
  maxMatches?: number;
};

export type SequenceStage<T extends SocEvent = SocEvent> = CorrelationClause<T> & {
  id: string;
  title?: string;
  maxGapMs?: number;
};

export type SequenceDetectionRule<T extends SocEvent = SocEvent> = CorrelationClause<T> & {
  id: string;
  title?: string;
  stages: Array<SequenceStage<T>>;
  windowMs: number;
  groupBy?: CorrelationGroupBy<T> | Array<CorrelationGroupBy<T>>;
  tenantScoped?: boolean;
  allowOverlappingMatches?: boolean;
  maxMatches?: number;
};

export type SequenceCorrelationMatch<T extends SocEvent = SocEvent> = CorrelationMatch<T> & {
  type: "sequence";
  stages: Array<{
    stageId: string;
    title?: string;
    eventId: string;
    timestamp: string;
  }>;
};

export type ScheduledQueryDetectionRule<T extends SocEvent = SocEvent> = CorrelationClause<T> & {
  id: string;
  title?: string;
  query: string;
  lookbackMs: number;
  intervalMs?: number;
  lastRunAt?: string;
  threshold?: number;
  groupBy?: CorrelationGroupBy<T> | Array<CorrelationGroupBy<T>>;
  tenantScoped?: boolean;
  maxMatches?: number;
};

export type ScheduledQueryRun<T extends SocEvent = SocEvent> = {
  ruleId: string;
  title?: string;
  due: boolean;
  ranAt: string;
  lookbackStart: string;
  lookbackEnd: string;
  recordCount: number;
  records: T[];
  matches: Array<CorrelationMatch<T>>;
  error?: string;
};

type TimedRecord<T extends SocEvent> = {
  record: T;
  time: number;
};

type GroupedTimedRecords<T extends SocEvent> = {
  key: string;
  label: string;
  values: Record<string, string>;
  records: Array<TimedRecord<T>>;
};

const FIELD_ALIASES: Record<string, string[]> = {
  agent: ["agentId"],
  command: ["commandLine", "command_line"],
  commandline: ["commandLine", "command_line"],
  event: ["eventType"],
  host: ["hostname"],
  hostname: ["hostname"],
  kind: ["kind"],
  rule: ["ruleId", "matchedRules"],
  rules: ["matchedRules"],
  severity: ["severity"],
  tenant: ["tenantId"],
  tenantid: ["tenantId"],
  time: ["timestamp"],
  timestamp: ["timestamp"],
  type: ["eventType"],
  user: ["user", "username", "account", "subjectUserName", "subject_user_name"],
};

export function runThresholdDetection<T extends SocEvent>(
  records: T[],
  rule: ThresholdDetectionRule<T>,
): Array<CorrelationMatch<T>> {
  assertPositiveNumber(rule.threshold, "threshold");
  assertPositiveNumber(rule.windowMs, "windowMs");

  const matches: Array<CorrelationMatch<T>> = [];
  const groups = groupTimedRecords(sortTimedRecords(selectCorrelationRecords(records, rule)), rule);
  const maxMatches = rule.maxMatches ?? Number.POSITIVE_INFINITY;

  for (const group of groups) {
    let left = 0;

    for (let right = 0; right < group.records.length && matches.length < maxMatches; right += 1) {
      while (left <= right && group.records[right].time - group.records[left].time > rule.windowMs) {
        left += 1;
      }

      const window = group.records.slice(left, right + 1);
      if (window.length < rule.threshold) continue;

      const windowRecords = window.map((item) => item.record);
      matches.push(makeCorrelationMatch(rule, "threshold", group, windowRecords, `${window.length} records matched in ${rule.windowMs}ms.`));

      if (rule.allowOverlappingMatches) {
        left += 1;
      } else {
        left = right + 1;
      }
    }
  }

  return matches;
}

export function runSequenceDetection<T extends SocEvent>(
  records: T[],
  rule: SequenceDetectionRule<T>,
): Array<SequenceCorrelationMatch<T>> {
  assertPositiveNumber(rule.windowMs, "windowMs");
  if (rule.stages.length < 2) throw new Error("Sequence detections require at least two stages.");

  const matches: Array<SequenceCorrelationMatch<T>> = [];
  const groups = groupTimedRecords(sortTimedRecords(selectCorrelationRecords(records, rule)), rule);
  const maxMatches = rule.maxMatches ?? Number.POSITIVE_INFINITY;

  for (const group of groups) {
    for (let startIndex = 0; startIndex < group.records.length && matches.length < maxMatches; startIndex += 1) {
      const first = group.records[startIndex];
      const firstStage = rule.stages[0];
      if (!recordMatchesClause(first.record, firstStage)) continue;

      const stagedRecords: Array<{ stage: SequenceStage<T>; item: TimedRecord<T>; index: number }> = [
        { stage: firstStage, item: first, index: startIndex },
      ];
      let cursor = startIndex + 1;
      let failed = false;

      for (let stageIndex = 1; stageIndex < rule.stages.length; stageIndex += 1) {
        const stage = rule.stages[stageIndex];
        const previous = stagedRecords[stagedRecords.length - 1];
        let found: { item: TimedRecord<T>; index: number } | undefined;

        for (let index = cursor; index < group.records.length; index += 1) {
          const candidate = group.records[index];
          if (candidate.time - first.time > rule.windowMs) break;
          if (stage.maxGapMs !== undefined && candidate.time - previous.item.time > stage.maxGapMs) break;
          if (!recordMatchesClause(candidate.record, stage)) continue;

          found = { item: candidate, index };
          break;
        }

        if (!found) {
          failed = true;
          break;
        }

        stagedRecords.push({ stage, item: found.item, index: found.index });
        cursor = found.index + 1;
      }

      if (failed) continue;

      const sequenceRecords = stagedRecords.map((item) => item.item.record);
      matches.push({
        ...makeCorrelationMatch(rule, "sequence", group, sequenceRecords, `${rule.stages.length} stages matched in ${rule.windowMs}ms.`),
        type: "sequence",
        stages: stagedRecords.map(({ stage, item }) => ({
          stageId: stage.id,
          title: stage.title,
          eventId: item.record.id,
          timestamp: item.record.timestamp,
        })),
      });

      if (!rule.allowOverlappingMatches) {
        startIndex = stagedRecords[stagedRecords.length - 1].index;
      }
    }
  }

  return matches;
}

export function isScheduledDetectionDue(
  rule: Pick<ScheduledQueryDetectionRule, "intervalMs" | "lastRunAt">,
  now: Date | string = new Date(),
) {
  if (!rule.intervalMs || !rule.lastRunAt) return true;
  assertPositiveNumber(rule.intervalMs, "intervalMs");

  const lastRun = Date.parse(rule.lastRunAt);
  const nowTime = instantMs(now, "now");
  if (!Number.isFinite(lastRun)) return true;

  return lastRun + rule.intervalMs <= nowTime;
}

export function runScheduledQueryDetection<T extends SocEvent>(
  records: T[],
  rule: ScheduledQueryDetectionRule<T>,
  options: { now?: Date | string; force?: boolean } = {},
): ScheduledQueryRun<T> {
  assertPositiveNumber(rule.lookbackMs, "lookbackMs");
  const nowTime = instantMs(options.now ?? new Date(), "now");
  const lookbackStart = nowTime - rule.lookbackMs;
  const ranAt = new Date(nowTime).toISOString();
  const baseRun = {
    ruleId: rule.id,
    title: rule.title,
    ranAt,
    lookbackStart: new Date(lookbackStart).toISOString(),
    lookbackEnd: ranAt,
  };
  const due = options.force === true || isScheduledDetectionDue(rule, ranAt);

  if (!due) {
    return {
      ...baseRun,
      due,
      recordCount: 0,
      records: [],
      matches: [],
    };
  }

  const selected = selectCorrelationRecords(records, { ...rule, query: undefined })
    .filter((item) => {
      const time = timestampMs(item.timestamp);
      return time !== undefined && time >= lookbackStart && time <= nowTime;
    });
  const queryResult = filterWithYaaql(selected, rule.query);

  if (queryResult.error) {
    return {
      ...baseRun,
      due,
      recordCount: 0,
      records: [],
      matches: [],
      error: queryResult.error,
    };
  }

  const threshold = rule.threshold ?? 1;
  assertPositiveNumber(threshold, "threshold");

  const groups = groupTimedRecords(sortTimedRecords(queryResult.records), rule);
  const maxMatches = rule.maxMatches ?? Number.POSITIVE_INFINITY;
  const matches: Array<CorrelationMatch<T>> = [];

  for (const group of groups) {
    if (matches.length >= maxMatches) break;
    if (group.records.length < threshold) continue;

    const groupRecords = group.records.map((item) => item.record);
    matches.push(makeCorrelationMatch(rule, "scheduled_query", group, groupRecords, `${groupRecords.length} records matched scheduled query.`));
  }

  return {
    ...baseRun,
    due,
    recordCount: queryResult.records.length,
    records: queryResult.records,
    matches,
  };
}

export function runScheduledQueryDetections<T extends SocEvent>(
  records: T[],
  rules: Array<ScheduledQueryDetectionRule<T>>,
  options: { now?: Date | string; force?: boolean } = {},
) {
  return rules.map((rule) => runScheduledQueryDetection(records, rule, options));
}

export function selectCorrelationRecords<T extends SocEvent>(
  records: T[],
  clause: CorrelationClause<T>,
): T[] {
  const scoped = records.filter((record) => recordMatchesStaticClause(record, clause));
  if (!clause.query?.trim()) return scoped;

  const result = filterWithYaaql(scoped, clause.query);
  if (result.error) return [];
  return result.records;
}

export function getCorrelationFieldValues(record: SocEvent, field: string): string[] {
  const aliases = (FIELD_ALIASES[normalizeName(field)] ?? [field]).map(normalizePath);
  const fieldIsPath = field.includes(".");

  const values = flattenValues(record)
    .filter(({ path }) => {
      const normalizedPath = normalizePath(path);
      if (fieldIsPath) return aliases.includes(normalizedPath);

      const lastSegment = normalizeName(path.split(".").at(-1) ?? path);
      return aliases.some((alias) => normalizedPath === alias || (!alias.includes(".") && lastSegment === alias));
    })
    .map(({ value }) => String(value));

  return [...new Set(values)].sort();
}

function recordMatchesClause<T extends SocEvent>(record: T, clause: CorrelationClause<T>) {
  return selectCorrelationRecords([record], clause).length === 1;
}

function recordMatchesStaticClause<T extends SocEvent>(record: T, clause: CorrelationClause<T>) {
  if (clause.tenantId !== undefined && record.tenantId !== clause.tenantId) return false;
  if (clause.kinds?.length && !clause.kinds.includes(record.kind)) return false;
  if (clause.severities?.length && !clause.severities.includes(record.severity)) return false;
  if (clause.eventTypes?.length && !clause.eventTypes.some((eventType) => sameText(eventType, record.eventType))) return false;
  if (clause.ruleIds?.length && !recordMatchesRuleIds(record, clause.ruleIds)) return false;
  if (clause.predicate && !clause.predicate(record)) return false;
  return true;
}

function recordMatchesRuleIds(record: SocEvent, ruleIds: string[]) {
  const actual = new Set([record.ruleId, ...record.matchedRules].filter((value): value is string => Boolean(value)));
  return ruleIds.some((ruleId) => actual.has(ruleId));
}

function sameText(left: string, right: string | undefined) {
  return left.toLowerCase() === String(right ?? "").toLowerCase();
}

function sortTimedRecords<T extends SocEvent>(records: T[]): Array<TimedRecord<T>> {
  return records
    .map((record) => ({ record, time: timestampMs(record.timestamp) }))
    .filter((item): item is TimedRecord<T> => item.time !== undefined)
    .sort((left, right) => left.time - right.time || left.record.id.localeCompare(right.record.id));
}

function groupTimedRecords<T extends SocEvent>(
  records: Array<TimedRecord<T>>,
  rule: {
    groupBy?: CorrelationGroupBy<T> | Array<CorrelationGroupBy<T>>;
    tenantScoped?: boolean;
  },
): Array<GroupedTimedRecords<T>> {
  const groups = new Map<string, GroupedTimedRecords<T>>();

  for (const item of records) {
    const grouping = groupingForRecord(item.record, rule);
    const group = groups.get(grouping.key) ?? {
      key: grouping.key,
      label: grouping.label,
      values: grouping.values,
      records: [],
    };

    group.records.push(item);
    groups.set(grouping.key, group);
  }

  return [...groups.values()];
}

function groupingForRecord<T extends SocEvent>(
  record: T,
  rule: {
    groupBy?: CorrelationGroupBy<T> | Array<CorrelationGroupBy<T>>;
    tenantScoped?: boolean;
  },
) {
  const values: Record<string, string> = {};
  const parts: string[] = [];

  if (rule.tenantScoped !== false) {
    values.tenantId = record.tenantId ?? "";
    parts.push(`tenantId=${values.tenantId || "unknown"}`);
  }

  const groupBy = Array.isArray(rule.groupBy) ? rule.groupBy : rule.groupBy ? [rule.groupBy] : [];
  groupBy.forEach((item, index) => {
    const label = typeof item === "string" ? item : `group${index + 1}`;
    const value = typeof item === "string"
      ? getCorrelationFieldValues(record, item).join("|") || "unknown"
      : String(item(record) ?? "unknown");

    values[label] = value;
    parts.push(`${label}=${value}`);
  });

  const keyParts = parts.length ? parts : ["all"];
  return {
    key: keyParts.join("\u001f"),
    label: keyParts.join(" "),
    values,
  };
}

function makeCorrelationMatch<T extends SocEvent>(
  rule: { id: string; title?: string; tenantScoped?: boolean },
  type: CorrelationMatchType,
  group: GroupedTimedRecords<T>,
  records: T[],
  reason: string,
): CorrelationMatch<T> {
  const startedAt = records[0]?.timestamp ?? "";
  const endedAt = records[records.length - 1]?.timestamp ?? startedAt;
  const eventIds = records.map((record) => record.id);

  return {
    id: `${type}:${rule.id}:${eventIds.join(",")}`,
    ruleId: rule.id,
    type,
    title: rule.title,
    tenantId: rule.tenantScoped === false ? undefined : records[0]?.tenantId,
    groupKey: group.label,
    groupValues: group.values,
    startedAt,
    endedAt,
    count: records.length,
    eventIds,
    records,
    reason,
  };
}

function timestampMs(value: string) {
  const time = Date.parse(value);
  return Number.isFinite(time) ? time : undefined;
}

function instantMs(value: Date | string, name: string) {
  const time = value instanceof Date ? value.getTime() : Date.parse(value);
  if (!Number.isFinite(time)) throw new Error(`${name} must be a valid timestamp.`);
  return time;
}

function assertPositiveNumber(value: number, name: string) {
  if (!Number.isFinite(value) || value <= 0) throw new Error(`${name} must be greater than zero.`);
}

function normalizeName(value: string) {
  return value.toLowerCase().replace(/[\s_-]/g, "");
}

function normalizePath(value: string) {
  return value.split(".").map(normalizeName).join(".");
}

function flattenValues(value: unknown, path = "", output: Array<{ path: string; value: Scalar }> = [], depth = 0) {
  if (value === null || value === undefined || depth > 8) return output;

  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    if (path) output.push({ path, value });
    return output;
  }

  if (Array.isArray(value)) {
    for (const item of value) flattenValues(item, path, output, depth + 1);
    return output;
  }

  if (typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      flattenValues(child, path ? `${path}.${key}` : key, output, depth + 1);
    }
  }

  return output;
}
