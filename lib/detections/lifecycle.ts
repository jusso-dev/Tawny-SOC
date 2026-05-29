import type { SigmaRule } from "../types";

export const detectionLifecycleStatuses = ["draft", "test", "enabled", "disabled", "deprecated"] as const;

export type DetectionLifecycleStatus = typeof detectionLifecycleStatuses[number];
export type DetectionEvaluationMode = "production" | "test";

export type DetectionLifecycleMetadata = {
  status: DetectionLifecycleStatus;
  updatedAt?: string;
  enabledAt?: string;
  disabledAt?: string;
  deprecatedAt?: string;
};

const lifecycleStatusSet = new Set<string>(detectionLifecycleStatuses);

export const detectionStatusTransitions: Record<DetectionLifecycleStatus, DetectionLifecycleStatus[]> = {
  draft: ["test", "disabled", "deprecated"],
  test: ["draft", "enabled", "disabled", "deprecated"],
  enabled: ["disabled", "deprecated"],
  disabled: ["draft", "test", "enabled", "deprecated"],
  deprecated: [],
};

export function normalizeDetectionStatus(value: unknown, fallback: DetectionLifecycleStatus = "draft"): DetectionLifecycleStatus {
  const normalized = String(value ?? "").toLowerCase();
  if (lifecycleStatusSet.has(normalized)) return normalized as DetectionLifecycleStatus;
  if (normalized === "stable") return "enabled";
  if (normalized === "experimental") return "test";
  return fallback;
}

export function lifecycleStatusForSigma(rule: Pick<SigmaRule, "status">, options: { disabled?: boolean } = {}) {
  if (options.disabled) return "disabled";
  return normalizeDetectionStatus(rule.status, "test");
}

export function isDetectionActiveStatus(status: unknown) {
  return normalizeDetectionStatus(status) === "enabled";
}

export function isDetectionTestableStatus(status: unknown) {
  const normalized = normalizeDetectionStatus(status);
  return normalized === "draft" || normalized === "test" || normalized === "enabled";
}

export function isDetectionEditableStatus(status: unknown) {
  const normalized = normalizeDetectionStatus(status);
  return normalized === "draft" || normalized === "test" || normalized === "disabled";
}

export function shouldEvaluateDetectionStatus(status: unknown, mode: DetectionEvaluationMode = "production") {
  const normalized = normalizeDetectionStatus(status);
  if (mode === "test") return isDetectionTestableStatus(normalized);
  return normalized === "enabled";
}

export function canTransitionDetectionStatus(from: unknown, to: unknown) {
  const current = normalizeDetectionStatus(from);
  const next = normalizeDetectionStatus(to);
  return current === next || detectionStatusTransitions[current].includes(next);
}

export function applyDetectionStatus<T extends object>(
  detection: T & { status?: unknown },
  nextStatus: DetectionLifecycleStatus,
  options: { now?: Date | string; enforceTransition?: boolean } = {},
): T & DetectionLifecycleMetadata {
  const current = normalizeDetectionStatus(detection.status);
  if (options.enforceTransition !== false && !canTransitionDetectionStatus(current, nextStatus)) {
    throw new Error(`Detection status cannot transition from ${current} to ${nextStatus}.`);
  }

  const now = instantIso(options.now ?? new Date());
  return {
    ...detection,
    status: nextStatus,
    updatedAt: now,
    ...(nextStatus === "enabled" ? { enabledAt: now } : {}),
    ...(nextStatus === "disabled" ? { disabledAt: now } : {}),
    ...(nextStatus === "deprecated" ? { deprecatedAt: now } : {}),
  };
}

export function filterDetectionsForEvaluation<T extends { status?: unknown }>(
  detections: T[],
  mode: DetectionEvaluationMode = "production",
) {
  return detections.filter((detection) => shouldEvaluateDetectionStatus(detection.status, mode));
}

function instantIso(value: Date | string) {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new Error("now must be a valid timestamp.");
  return date.toISOString();
}
