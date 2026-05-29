export type RetentionDataset =
  | "events"
  | "alerts"
  | "incidents"
  | "evidence"
  | "audit_logs"
  | "delivery_logs"
  | "threat_intel";

export type RetentionAction = "retain" | "archive" | "delete" | "preserve_legal_hold";

export type RetentionPolicy = {
  dataset: RetentionDataset;
  label: string;
  archiveAfterDays?: number;
  deleteAfterDays: number;
  legalHoldPreserves: boolean;
};

export type RetainableRecord = {
  id: string;
  dataset: RetentionDataset;
  createdAt: string;
  updatedAt?: string;
  closedAt?: string;
  observedAt?: string;
  legalHold?: boolean;
  legalHoldUntil?: string;
  legalHoldReason?: string;
};

export type RetentionDecision = {
  recordId: string;
  dataset: RetentionDataset;
  action: RetentionAction;
  reason: string;
  anchorAt: string;
  archiveAt?: string;
  deleteAt: string;
  ageDays: number;
  daysUntilAction: number;
};

export const DEFAULT_RETENTION_POLICIES: Record<RetentionDataset, RetentionPolicy> = {
  events: {
    dataset: "events",
    label: "Raw telemetry and normalized events",
    archiveAfterDays: 90,
    deleteAfterDays: 730,
    legalHoldPreserves: true,
  },
  alerts: {
    dataset: "alerts",
    label: "Alert records and triage metadata",
    archiveAfterDays: 180,
    deleteAfterDays: 1095,
    legalHoldPreserves: true,
  },
  incidents: {
    dataset: "incidents",
    label: "Incident cases, timelines, tasks, and comments",
    archiveAfterDays: 365,
    deleteAfterDays: 2555,
    legalHoldPreserves: true,
  },
  evidence: {
    dataset: "evidence",
    label: "Incident evidence and chain of custody records",
    archiveAfterDays: 365,
    deleteAfterDays: 2555,
    legalHoldPreserves: true,
  },
  audit_logs: {
    dataset: "audit_logs",
    label: "Administrative and security audit logs",
    archiveAfterDays: 365,
    deleteAfterDays: 2555,
    legalHoldPreserves: true,
  },
  delivery_logs: {
    dataset: "delivery_logs",
    label: "Integration delivery attempts and errors",
    archiveAfterDays: 90,
    deleteAfterDays: 365,
    legalHoldPreserves: true,
  },
  threat_intel: {
    dataset: "threat_intel",
    label: "Threat intelligence indicators and feed state",
    archiveAfterDays: 90,
    deleteAfterDays: 365,
    legalHoldPreserves: true,
  },
};

export function resolveRetentionPolicy(
  dataset: RetentionDataset,
  overrides: Partial<Record<RetentionDataset, Partial<RetentionPolicy>>> = {},
): RetentionPolicy {
  return {
    ...DEFAULT_RETENTION_POLICIES[dataset],
    ...overrides[dataset],
    dataset,
  };
}

export function calculateRetentionDecision(
  record: RetainableRecord,
  policy = resolveRetentionPolicy(record.dataset),
  now = new Date(),
): RetentionDecision {
  const anchor = retentionAnchor(record);
  const archiveAt = policy.archiveAfterDays === undefined ? undefined : addDays(anchor, policy.archiveAfterDays);
  const deleteAt = addDays(anchor, policy.deleteAfterDays);
  const ageDays = wholeDaysBetween(anchor, now);

  if (policy.legalHoldPreserves && isLegalHoldActive(record, now)) {
    return {
      recordId: record.id,
      dataset: record.dataset,
      action: "preserve_legal_hold",
      reason: record.legalHoldReason ?? "Record is under legal hold and must not be archived or deleted.",
      anchorAt: anchor.toISOString(),
      archiveAt: archiveAt?.toISOString(),
      deleteAt: deleteAt.toISOString(),
      ageDays,
      daysUntilAction: 0,
    };
  }

  if (now.getTime() >= deleteAt.getTime()) {
    return {
      recordId: record.id,
      dataset: record.dataset,
      action: "delete",
      reason: `${policy.label} exceeded delete retention of ${policy.deleteAfterDays} days.`,
      anchorAt: anchor.toISOString(),
      archiveAt: archiveAt?.toISOString(),
      deleteAt: deleteAt.toISOString(),
      ageDays,
      daysUntilAction: 0,
    };
  }

  if (archiveAt && now.getTime() >= archiveAt.getTime()) {
    return {
      recordId: record.id,
      dataset: record.dataset,
      action: "archive",
      reason: `${policy.label} exceeded hot retention of ${policy.archiveAfterDays} days.`,
      anchorAt: anchor.toISOString(),
      archiveAt: archiveAt.toISOString(),
      deleteAt: deleteAt.toISOString(),
      ageDays,
      daysUntilAction: wholeDaysBetween(now, deleteAt),
    };
  }

  const nextActionAt = archiveAt ?? deleteAt;
  return {
    recordId: record.id,
    dataset: record.dataset,
    action: "retain",
    reason: `${policy.label} remains inside active retention.`,
    anchorAt: anchor.toISOString(),
    archiveAt: archiveAt?.toISOString(),
    deleteAt: deleteAt.toISOString(),
    ageDays,
    daysUntilAction: wholeDaysBetween(now, nextActionAt),
  };
}

export function retentionSweepPlan(
  records: RetainableRecord[],
  overrides: Partial<Record<RetentionDataset, Partial<RetentionPolicy>>> = {},
  now = new Date(),
): RetentionDecision[] {
  return records.map((record) => calculateRetentionDecision(record, resolveRetentionPolicy(record.dataset, overrides), now));
}

export function isLegalHoldActive(record: RetainableRecord, now = new Date()): boolean {
  if (record.legalHold) return true;
  if (!record.legalHoldUntil) return false;
  const holdUntil = Date.parse(record.legalHoldUntil);
  return Number.isFinite(holdUntil) && holdUntil >= now.getTime();
}

function retentionAnchor(record: RetainableRecord): Date {
  const preferred = record.closedAt ?? record.updatedAt ?? record.observedAt ?? record.createdAt;
  const parsed = new Date(preferred);
  if (Number.isNaN(parsed.getTime())) return new Date(0);
  return parsed;
}

function addDays(value: Date, days: number): Date {
  return new Date(value.getTime() + days * 24 * 60 * 60_000);
}

function wholeDaysBetween(start: Date, end: Date): number {
  return Math.max(0, Math.ceil((end.getTime() - start.getTime()) / (24 * 60 * 60_000)));
}
