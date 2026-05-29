import type { IntegrationDelivery } from "../types";

export type IntegrationHealthStatus = "healthy" | "degraded" | "failing" | "paused" | "not_configured";

export type IntegrationHealthInput = {
  id: string;
  label: string;
  enabled: boolean;
  configured: boolean;
  deliveries?: IntegrationDelivery[];
  staleAfterMinutes?: number;
  failureThreshold?: number;
};

export type IntegrationHealth = {
  id: string;
  label: string;
  status: IntegrationHealthStatus;
  reason: string;
  lastAttemptAt?: string;
  consecutiveFailures: number;
};

const HEALTH_RANK: Record<IntegrationHealthStatus, number> = {
  healthy: 0,
  degraded: 1,
  paused: 2,
  not_configured: 3,
  failing: 4,
};

export function calculateIntegrationHealth(input: IntegrationHealthInput, now = new Date()): IntegrationHealth {
  if (!input.enabled) {
    return baseHealth(input, "paused", "Integration is disabled.");
  }

  if (!input.configured) {
    return baseHealth(input, "not_configured", "Integration is enabled but missing endpoint or credentials.");
  }

  const deliveries = [...(input.deliveries ?? [])].sort((a, b) => Date.parse(b.lastAttemptAt) - Date.parse(a.lastAttemptAt));
  if (!deliveries.length) {
    return baseHealth(input, "degraded", "Integration has no recorded delivery checks.");
  }

  const latest = deliveries[0];
  const consecutiveFailures = countConsecutiveFailures(deliveries);
  const staleAfterMinutes = input.staleAfterMinutes ?? 60;
  const failureThreshold = input.failureThreshold ?? 3;
  const lastAttemptAt = latest.lastAttemptAt;

  if (consecutiveFailures >= failureThreshold) {
    return {
      ...baseHealth(input, "failing", `${consecutiveFailures} consecutive delivery failures require remediation.`),
      lastAttemptAt,
      consecutiveFailures,
    };
  }

  if (latest.state === "failed" || latest.state === "retrying") {
    return {
      ...baseHealth(input, "degraded", latest.error ?? `Latest delivery is ${latest.state}.`),
      lastAttemptAt,
      consecutiveFailures,
    };
  }

  if (latest.state === "queued") {
    return {
      ...baseHealth(input, "degraded", "Latest delivery is still queued."),
      lastAttemptAt,
      consecutiveFailures,
    };
  }

  if (isStale(latest.lastAttemptAt, staleAfterMinutes, now)) {
    return {
      ...baseHealth(input, "degraded", `No successful delivery check within ${staleAfterMinutes} minutes.`),
      lastAttemptAt,
      consecutiveFailures,
    };
  }

  return {
    ...baseHealth(input, "healthy", "Latest delivery check succeeded."),
    lastAttemptAt,
    consecutiveFailures,
  };
}

export function calculateIntegrationFleetHealth(results: IntegrationHealth[]): {
  status: IntegrationHealthStatus;
  counts: Record<IntegrationHealthStatus, number>;
} {
  const counts = {
    healthy: 0,
    degraded: 0,
    failing: 0,
    paused: 0,
    not_configured: 0,
  } satisfies Record<IntegrationHealthStatus, number>;

  for (const result of results) counts[result.status] += 1;

  const status = results.length
    ? results.map((result) => result.status).sort((a, b) => HEALTH_RANK[b] - HEALTH_RANK[a])[0]
    : "not_configured";

  return { status, counts };
}

function baseHealth(input: IntegrationHealthInput, status: IntegrationHealthStatus, reason: string): IntegrationHealth {
  return {
    id: input.id,
    label: input.label,
    status,
    reason,
    consecutiveFailures: 0,
  };
}

function countConsecutiveFailures(deliveries: IntegrationDelivery[]): number {
  let count = 0;
  for (const delivery of deliveries) {
    if (delivery.state !== "failed" && delivery.state !== "retrying") break;
    count += 1;
  }
  return count;
}

function isStale(value: string, staleAfterMinutes: number, now: Date): boolean {
  const lastAttempt = Date.parse(value);
  if (!Number.isFinite(lastAttempt)) return true;
  return now.getTime() - lastAttempt > staleAfterMinutes * 60_000;
}
