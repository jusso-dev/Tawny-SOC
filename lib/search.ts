import type { SocEvent } from "./types";
import { filterWithYaaql } from "./yaaql";

export const DEFAULT_SEARCH_LIMIT = 100;
export const MAX_SEARCH_LIMIT = 1000;

export type SearchConcreteDataset = "alerts" | "telemetry";
export type SearchDatasetScope = "all" | SearchConcreteDataset;
export type SearchExportFormat = "csv" | "json";
export type SearchOrderDirection = "asc" | "desc";

export type SearchErrorCode =
  | "invalid_cursor"
  | "invalid_dataset"
  | "invalid_limit"
  | "invalid_order"
  | "invalid_query"
  | "invalid_time_range";

export type SearchError = {
  code: SearchErrorCode;
  field?: string;
  message: string;
};

export type SearchTimeRange = {
  from?: string;
  label?: string;
  to?: string;
};

export type SearchCursorPayload = {
  id: string;
  order: SearchOrderDirection;
  timestamp: string;
  v: 1;
};

export type SearchPlanInput = {
  cursor?: unknown;
  dataset?: unknown;
  end?: unknown;
  from?: unknown;
  limit?: unknown;
  now?: unknown;
  order?: unknown;
  q?: unknown;
  query?: unknown;
  range?: unknown;
  scope?: unknown;
  since?: unknown;
  start?: unknown;
  to?: unknown;
};

export type SearchPlanOptions = {
  defaultDataset?: SearchDatasetScope;
  defaultLimit?: number;
  defaultOrder?: SearchOrderDirection;
  maxLimit?: number;
  now?: Date;
};

export type SearchPlan = {
  datasets: SearchConcreteDataset[];
  kinds: Array<SocEvent["kind"]>;
  limit: number;
  maxLimit: number;
  order: SearchOrderDirection;
  query: string;
  scope: SearchDatasetScope;
  timeRange: SearchTimeRange;
  cursor?: SearchCursorPayload;
};

export type SearchPlanResult =
  | { ok: true; plan: SearchPlan; warnings: string[] }
  | { ok: false; error: SearchError; warnings: string[] };

export type SearchPageInfo = {
  hasNextPage: boolean;
  limit: number;
  order: SearchOrderDirection;
  returnedCount: number;
  cursor?: string;
  nextCursor?: string;
};

export type SearchExecutionResult<T extends SocEvent> = {
  ok: boolean;
  pageInfo: SearchPageInfo;
  records: T[];
  totalMatched: number;
  warnings: string[];
  error?: SearchError;
  plan?: SearchPlan;
};

export type SearchExportResult = {
  body: string;
  contentType: string;
  filenameExtension: SearchExportFormat;
};

export type SearchExportOptions = {
  exportedAt?: Date | string;
  includePayload?: boolean;
};

export type SavedHuntSearchMetadata = {
  createdAt: string;
  id: string;
  name: string;
  query: string;
  updatedAt: string;
  dataset?: SearchDatasetScope;
  defaultLimit?: number;
  description?: string;
  lastRunAt?: string;
  ownerId?: string;
  tags?: string[];
  tenantId?: string;
  timeRange?: SearchTimeRange;
};

export type SearchJobMetadata = {
  createdAt: string;
  id: string;
  plan: SearchPlan;
  status: "planned" | "running" | "completed" | "failed" | "cancelled";
  completedAt?: string;
  createdBy?: string;
  error?: SearchError;
  resultCount?: number;
  startedAt?: string;
};

type FieldParseResult<T> =
  | { ok: true; value: T; warning?: string }
  | { ok: false; error: SearchError };

type TimeRangeParseResult =
  | { ok: true; timeRange: SearchTimeRange }
  | { ok: false; error: SearchError };

export type SearchCursorDecodeResult =
  | { ok: true; cursor: SearchCursorPayload }
  | { ok: false; error: SearchError };

const DATASET_ALIASES: Record<string, SearchConcreteDataset[] | "all"> = {
  alert: ["alerts"],
  alerts: ["alerts"],
  all: "all",
  event: ["telemetry"],
  events: ["telemetry"],
  telemetry: ["telemetry"],
};

const CSV_COLUMNS: Array<{
  header: string;
  value: (record: SocEvent) => unknown;
}> = [
  { header: "id", value: (record) => record.id },
  { header: "timestamp", value: (record) => record.timestamp },
  { header: "kind", value: (record) => record.kind },
  { header: "severity", value: (record) => record.severity },
  { header: "status", value: (record) => record.status },
  { header: "tenantId", value: (record) => record.tenantId },
  { header: "source", value: (record) => record.source },
  { header: "agentId", value: (record) => record.agentId },
  { header: "hostname", value: (record) => record.hostname },
  { header: "eventType", value: (record) => record.eventType },
  { header: "title", value: (record) => record.title },
  { header: "matchedRules", value: (record) => record.matchedRules },
  { header: "mitreTechniques", value: (record) => record.mitreTechniques },
  { header: "payload", value: (record) => record.payload },
];

export function searchInputFromParams(params: URLSearchParams): SearchPlanInput {
  return {
    cursor: params.get("cursor"),
    dataset: params.get("dataset"),
    end: params.get("end"),
    from: params.get("from"),
    limit: params.get("limit"),
    order: params.get("order"),
    q: params.get("q"),
    range: params.get("range"),
    scope: params.get("scope"),
    since: params.get("since"),
    start: params.get("start"),
    to: params.get("to"),
  };
}

export function createSearchPlan(input: SearchPlanInput = {}, options: SearchPlanOptions = {}): SearchPlanResult {
  const warnings: string[] = [];
  const maxLimit = normalizeMaxLimit(options.maxLimit);
  const defaultLimit = clampLimit(options.defaultLimit ?? DEFAULT_SEARCH_LIMIT, maxLimit);
  const nowResult = parseDateInput(options.now ?? input.now ?? new Date(), "now");
  if (!nowResult.ok) return { ok: false, error: nowResult.error, warnings };

  const datasetResult = parseDatasetScope(input.dataset ?? input.scope, options.defaultDataset ?? "all");
  if (!datasetResult.ok) return { ok: false, error: datasetResult.error, warnings };

  const orderResult = parseOrder(input.order, options.defaultOrder ?? "desc");
  if (!orderResult.ok) return { ok: false, error: orderResult.error, warnings };

  const limitResult = parseLimit(input.limit, defaultLimit, maxLimit);
  if (!limitResult.ok) return { ok: false, error: limitResult.error, warnings };
  if (limitResult.warning) warnings.push(limitResult.warning);

  const timeRangeResult = parseTimeRange(input, nowResult.value);
  if (!timeRangeResult.ok) return { ok: false, error: timeRangeResult.error, warnings };

  const cursorValue = firstString(input.cursor)?.trim();
  const cursorResult = cursorValue ? decodeSearchCursor(cursorValue) : undefined;
  if (cursorResult && !cursorResult.ok) return { ok: false, error: cursorResult.error, warnings };
  if (cursorResult?.ok && cursorResult.cursor.order !== orderResult.value) {
    return {
      ok: false,
      error: {
        code: "invalid_cursor",
        field: "cursor",
        message: `Cursor was created for ${cursorResult.cursor.order} ordering, but the request uses ${orderResult.value} ordering.`,
      },
      warnings,
    };
  }

  const datasets = datasetResult.value;
  return {
    ok: true,
    plan: {
      cursor: cursorResult?.ok ? cursorResult.cursor : undefined,
      datasets,
      kinds: datasets.map((dataset) => dataset === "alerts" ? "alert" : "telemetry"),
      limit: limitResult.value,
      maxLimit,
      order: orderResult.value,
      query: (firstString(input.q) ?? firstString(input.query) ?? "").trim(),
      scope: datasetScopeFor(datasets),
      timeRange: timeRangeResult.timeRange,
    },
    warnings,
  };
}

export function searchRecords<T extends SocEvent>(
  records: T[],
  input: SearchPlanInput = {},
  options: SearchPlanOptions = {},
): SearchExecutionResult<T> {
  const planned = createSearchPlan(input, options);
  if (!planned.ok) {
    return {
      error: planned.error,
      ok: false,
      pageInfo: emptyPageInfo(options.defaultOrder ?? "desc"),
      records: [],
      totalMatched: 0,
      warnings: planned.warnings,
    };
  }

  return {
    ...executeSearchPlan(records, planned.plan),
    warnings: planned.warnings,
  };
}

export function executeSearchPlan<T extends SocEvent>(records: T[], plan: SearchPlan): SearchExecutionResult<T> {
  const scopedRecords = records
    .filter((record) => plan.kinds.includes(record.kind))
    .filter((record) => recordWithinTimeRange(record, plan.timeRange));
  const yaaqlResult = filterWithYaaql(scopedRecords, plan.query);

  if (yaaqlResult.error) {
    return {
      error: {
        code: "invalid_query",
        field: "q",
        message: yaaqlResult.error,
      },
      ok: false,
      pageInfo: emptyPageInfo(plan.order, plan.limit, encodeCursorMaybe(plan.cursor)),
      plan,
      records: [],
      totalMatched: 0,
      warnings: [],
    };
  }

  const orderedRecords = [...yaaqlResult.records].sort((left, right) => compareSearchRecords(left, right, plan.order));
  const afterCursor = plan.cursor
    ? orderedRecords.filter((record) => compareRecordToCursor(record, plan.cursor as SearchCursorPayload, plan.order) > 0)
    : orderedRecords;
  const pageRecords = afterCursor.slice(0, plan.limit);
  const hasNextPage = afterCursor.length > plan.limit;
  const lastRecord = pageRecords.at(-1);
  const nextCursor = hasNextPage && lastRecord
    ? encodeSearchCursor(cursorForRecord(lastRecord, plan.order))
    : undefined;

  return {
    ok: true,
    pageInfo: {
      cursor: encodeCursorMaybe(plan.cursor),
      hasNextPage,
      limit: plan.limit,
      nextCursor,
      order: plan.order,
      returnedCount: pageRecords.length,
    },
    plan,
    records: pageRecords,
    totalMatched: orderedRecords.length,
    warnings: [],
  };
}

export function compareSearchRecords(left: SocEvent, right: SocEvent, order: SearchOrderDirection = "desc") {
  return compareSearchKeys(
    { id: left.id, timestamp: left.timestamp },
    { id: right.id, timestamp: right.timestamp },
    order,
  );
}

export function cursorForRecord(record: SocEvent, order: SearchOrderDirection): SearchCursorPayload {
  return {
    id: record.id,
    order,
    timestamp: record.timestamp,
    v: 1,
  };
}

export function encodeSearchCursor(cursor: SearchCursorPayload): string {
  return base64UrlEncode(JSON.stringify(cursor));
}

export function decodeSearchCursor(value: string): SearchCursorDecodeResult {
  try {
    const parsed = JSON.parse(base64UrlDecode(value)) as Partial<SearchCursorPayload>;
    if (
      parsed.v !== 1
      || typeof parsed.id !== "string"
      || !parsed.id.trim()
      || typeof parsed.timestamp !== "string"
      || !Number.isFinite(Date.parse(parsed.timestamp))
      || (parsed.order !== "asc" && parsed.order !== "desc")
    ) {
      return {
        ok: false,
        error: {
          code: "invalid_cursor",
          field: "cursor",
          message: "Cursor is not a valid Tawny search cursor.",
        },
      };
    }

    return {
      ok: true,
      cursor: {
        id: parsed.id,
        order: parsed.order,
        timestamp: parsed.timestamp,
        v: 1,
      },
    };
  } catch {
    return {
      ok: false,
      error: {
        code: "invalid_cursor",
        field: "cursor",
        message: "Cursor could not be decoded.",
      },
    };
  }
}

export function serializeSearchExport<T extends SocEvent>(
  records: T[],
  plan: SearchPlan,
  format: SearchExportFormat,
  options: SearchExportOptions = {},
): SearchExportResult {
  if (format === "csv") {
    return {
      body: serializeSearchResultsToCsv(records, plan, options),
      contentType: "text/csv; charset=utf-8",
      filenameExtension: "csv",
    };
  }

  return {
    body: serializeSearchResultsToJson(records, plan, options),
    contentType: "application/json; charset=utf-8",
    filenameExtension: "json",
  };
}

export function serializeSearchResultsToJson<T extends SocEvent>(
  records: T[],
  plan: SearchPlan,
  options: SearchExportOptions = {},
) {
  return `${JSON.stringify({
    dataset: plan.scope,
    exportedAt: exportedAt(options.exportedAt),
    limit: plan.limit,
    order: plan.order,
    query: plan.query,
    resultCount: records.length,
    timeRange: plan.timeRange,
    records: options.includePayload === false ? records.map(withoutPayload) : records,
  }, null, 2)}\n`;
}

export function serializeSearchResultsToCsv<T extends SocEvent>(
  records: T[],
  _plan: SearchPlan,
  options: SearchExportOptions = {},
) {
  const columns = options.includePayload === false
    ? CSV_COLUMNS.filter((column) => column.header !== "payload")
    : CSV_COLUMNS;
  const rows = [
    columns.map((column) => csvCell(column.header)).join(","),
    ...records.map((record) => columns.map((column) => csvCell(column.value(record))).join(",")),
  ];

  return `${rows.join("\n")}\n`;
}

function parseDatasetScope(value: unknown, defaultDataset: SearchDatasetScope): FieldParseResult<SearchConcreteDataset[]> {
  const rawValues = valuesFromUnknown(value);
  const requested = rawValues.length ? rawValues : [defaultDataset];
  const datasets = new Set<SearchConcreteDataset>();

  for (const raw of requested) {
    const normalized = raw.toLowerCase().trim();
    const aliased = DATASET_ALIASES[normalized];
    if (!aliased) {
      return {
        ok: false,
        error: {
          code: "invalid_dataset",
          field: "dataset",
          message: `Unsupported dataset scope "${raw}". Use all, alerts, or telemetry.`,
        },
      };
    }

    if (aliased === "all") {
      datasets.add("alerts");
      datasets.add("telemetry");
    } else {
      for (const dataset of aliased) datasets.add(dataset);
    }
  }

  return {
    ok: true,
    value: orderedDatasets(datasets),
  };
}

function parseOrder(value: unknown, defaultOrder: SearchOrderDirection): FieldParseResult<SearchOrderDirection> {
  const raw = firstString(value)?.trim().toLowerCase();
  if (!raw) return { ok: true, value: defaultOrder };
  if (raw === "asc" || raw === "desc") return { ok: true, value: raw };
  return {
    ok: false,
    error: {
      code: "invalid_order",
      field: "order",
      message: `Unsupported search ordering "${raw}". Use asc or desc.`,
    },
  };
}

function parseLimit(value: unknown, defaultLimit: number, maxLimit: number): FieldParseResult<number> {
  const raw = firstString(value)?.trim();
  if (!raw) return { ok: true, value: defaultLimit };

  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < 1) {
    return {
      ok: false,
      error: {
        code: "invalid_limit",
        field: "limit",
        message: "Search limit must be a positive integer.",
      },
    };
  }

  if (parsed > maxLimit) {
    return {
      ok: true,
      value: maxLimit,
      warning: `Search limit ${parsed} exceeded the maximum and was clamped to ${maxLimit}.`,
    };
  }

  return { ok: true, value: parsed };
}

function parseTimeRange(input: SearchPlanInput, now: Date): TimeRangeParseResult {
  const fromValue = firstDefined(input.from, input.start);
  const toValue = firstDefined(input.to, input.end);
  const rangeValue = firstString(input.range)?.trim();
  const sinceValue = firstString(input.since)?.trim();

  if (rangeValue && (fromValue !== undefined || sinceValue)) {
    return {
      ok: false,
      error: {
        code: "invalid_time_range",
        field: "range",
        message: "Use either range or from/start/since for a search window, not both.",
      },
    };
  }

  let from: Date | undefined;
  let to: Date | undefined;
  let label: string | undefined;

  if (rangeValue) {
    const duration = parseDurationMillis(rangeValue);
    if (!duration) {
      return {
        ok: false,
        error: {
          code: "invalid_time_range",
          field: "range",
          message: `Unsupported time range "${rangeValue}". Use values like 15m, 24h, 7d, or 2w.`,
        },
      };
    }

    const toResult = toValue === undefined ? { ok: true as const, value: now } : parseDateInput(toValue, "to");
    if (!toResult.ok) return { ok: false, error: toResult.error };
    to = toResult.value;
    from = new Date(to.getTime() - duration);
    label = `last ${rangeValue}`;
  } else {
    if (sinceValue && fromValue === undefined) {
      const duration = parseDurationMillis(sinceValue);
      if (duration) {
        from = new Date(now.getTime() - duration);
        label = `since ${sinceValue}`;
      } else {
        const sinceResult = parseDateInput(sinceValue, "since");
        if (!sinceResult.ok) return { ok: false, error: sinceResult.error };
        from = sinceResult.value;
      }
    } else if (fromValue !== undefined) {
      const fromResult = parseDateInput(fromValue, "from");
      if (!fromResult.ok) return { ok: false, error: fromResult.error };
      from = fromResult.value;
    }

    if (toValue !== undefined) {
      const toResult = parseDateInput(toValue, "to");
      if (!toResult.ok) return { ok: false, error: toResult.error };
      to = toResult.value;
    }
  }

  if (from && to && from.getTime() > to.getTime()) {
    return {
      ok: false,
      error: {
        code: "invalid_time_range",
        field: "from",
        message: "Search time range start must be before or equal to the end.",
      },
    };
  }

  return {
    ok: true,
    timeRange: {
      from: from?.toISOString(),
      label,
      to: to?.toISOString(),
    },
  };
}

function parseDateInput(value: unknown, field: string): FieldParseResult<Date> {
  if (value instanceof Date) {
    if (Number.isFinite(value.getTime())) return { ok: true, value };
    return invalidDate(field);
  }

  const raw = firstString(value)?.trim();
  if (!raw) return invalidDate(field);

  const parsed = new Date(raw);
  if (!Number.isFinite(parsed.getTime())) return invalidDate(field);
  return { ok: true, value: parsed };
}

function invalidDate(field: string): FieldParseResult<Date> {
  return {
    ok: false,
    error: {
      code: "invalid_time_range",
      field,
      message: `Search time field "${field}" must be an ISO-8601 timestamp or date.`,
    },
  };
}

function parseDurationMillis(value: string) {
  const match = value.match(/^(\d+)\s*(m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days|w|week|weeks)$/i);
  if (!match) return undefined;
  const amount = Number(match[1]);
  if (!Number.isSafeInteger(amount) || amount < 1) return undefined;
  const unit = match[2].toLowerCase();
  const minute = 60_000;
  if (unit.startsWith("m")) return amount * minute;
  if (unit.startsWith("h")) return amount * 60 * minute;
  if (unit.startsWith("d")) return amount * 24 * 60 * minute;
  return amount * 7 * 24 * 60 * minute;
}

function recordWithinTimeRange(record: SocEvent, timeRange: SearchTimeRange) {
  if (!timeRange.from && !timeRange.to) return true;

  const timestamp = Date.parse(record.timestamp);
  if (!Number.isFinite(timestamp)) return false;

  if (timeRange.from && timestamp < Date.parse(timeRange.from)) return false;
  if (timeRange.to && timestamp > Date.parse(timeRange.to)) return false;
  return true;
}

function compareRecordToCursor(record: SocEvent, cursor: SearchCursorPayload, order: SearchOrderDirection) {
  return compareSearchKeys(
    { id: record.id, timestamp: record.timestamp },
    { id: cursor.id, timestamp: cursor.timestamp },
    order,
  );
}

function compareSearchKeys(
  left: Pick<SearchCursorPayload, "id" | "timestamp">,
  right: Pick<SearchCursorPayload, "id" | "timestamp">,
  order: SearchOrderDirection,
) {
  const leftTime = timestampMs(left.timestamp);
  const rightTime = timestampMs(right.timestamp);
  const direction = order === "asc" ? 1 : -1;
  const timeComparison = leftTime === rightTime ? 0 : leftTime > rightTime ? 1 : -1;
  if (timeComparison !== 0) return timeComparison * direction;
  return left.id.localeCompare(right.id) * direction;
}

function cursorKey(cursor: SearchCursorPayload) {
  return {
    id: cursor.id,
    order: cursor.order,
    timestamp: cursor.timestamp,
    v: 1 as const,
  };
}

function encodeCursorMaybe(cursor?: SearchCursorPayload) {
  return cursor ? encodeSearchCursor(cursorKey(cursor)) : undefined;
}

function emptyPageInfo(order: SearchOrderDirection, limit = 0, cursor?: string): SearchPageInfo {
  return {
    cursor,
    hasNextPage: false,
    limit,
    order,
    returnedCount: 0,
  };
}

function timestampMs(value: string) {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function datasetScopeFor(datasets: SearchConcreteDataset[]): SearchDatasetScope {
  return datasets.length === 2 ? "all" : datasets[0] ?? "all";
}

function orderedDatasets(datasets: Set<SearchConcreteDataset>): SearchConcreteDataset[] {
  return (["alerts", "telemetry"] as const).filter((dataset) => datasets.has(dataset));
}

function valuesFromUnknown(value: unknown): string[] {
  if (value === undefined || value === null) return [];
  if (Array.isArray(value)) return value.flatMap(valuesFromUnknown);
  return String(value)
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function firstDefined(...values: unknown[]) {
  return values.find((value) => value !== undefined && value !== null && firstString(value) !== "");
}

function firstString(value: unknown): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (Array.isArray(value)) return firstString(value[0]);
  if (value instanceof Date) return value.toISOString();
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return undefined;
}

function normalizeMaxLimit(value: number | undefined): number {
  if (value === undefined || !Number.isInteger(value) || value < 1) return MAX_SEARCH_LIMIT;
  return value;
}

function clampLimit(value: number, maxLimit: number) {
  if (!Number.isInteger(value) || value < 1) return DEFAULT_SEARCH_LIMIT;
  return Math.min(value, maxLimit);
}

function withoutPayload<T extends SocEvent>(record: T) {
  const { payload: _payload, ...rest } = record;
  return rest;
}

function exportedAt(value: Date | string | undefined) {
  if (value instanceof Date) return value.toISOString();
  if (typeof value === "string" && value.trim()) return new Date(value).toISOString();
  return new Date().toISOString();
}

function csvCell(value: unknown) {
  const text = scalarForExport(value);
  if (/[",\n\r]/.test(text)) return `"${text.replace(/"/g, "\"\"")}"`;
  return text;
}

function scalarForExport(value: unknown): string {
  if (value === undefined || value === null) return "";
  if (Array.isArray(value)) return value.join("; ");
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function base64UrlEncode(value: string) {
  return Buffer.from(value, "utf8").toString("base64url");
}

function base64UrlDecode(value: string) {
  return Buffer.from(value, "base64url").toString("utf8");
}
