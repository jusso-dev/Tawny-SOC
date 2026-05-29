import cron from "node-cron";

type JobStatus = {
  name: string;
  schedule: string;
  lastRunAt?: string;
  lastCompletedAt?: string;
  lastStatus: "idle" | "running" | "succeeded" | "failed";
  lastError?: string;
};

const globalKey = "__tawnySocCron";
const state = (globalThis as unknown as Record<string, { started?: boolean; statuses: Map<string, JobStatus> }>);
state[globalKey] ??= { statuses: new Map() };

const jobDefinitions = [
  {
    name: "soc-retention-sweep",
    schedule: "15 3 * * *",
    run: async () => {
      const { deleteExpiredThreatIntelIndicators } = await import("@/lib/store");
      await deleteExpiredThreatIntelIndicators();
    },
  },
];

export function startCronJobs() {
  const registry = state[globalKey];
  if (registry.started) return;
  registry.started = true;

  for (const job of jobDefinitions) {
    registry.statuses.set(job.name, {
      name: job.name,
      schedule: job.schedule,
      lastStatus: "idle",
    });

    if (!cron.validate(job.schedule)) {
      registry.statuses.set(job.name, {
        name: job.name,
        schedule: job.schedule,
        lastStatus: "failed",
        lastError: "Invalid cron schedule.",
      });
      continue;
    }

    cron.schedule(job.schedule, () => void runJob(job.name), {
      timezone: process.env.CRON_TIMEZONE ?? "UTC",
    });
  }
}

export async function runJob(name: string) {
  const job = jobDefinitions.find((item) => item.name === name);
  if (!job) throw new Error(`Unknown cron job: ${name}`);

  const status = state[globalKey].statuses.get(name) ?? {
    name,
    schedule: job.schedule,
    lastStatus: "idle" as const,
  };
  state[globalKey].statuses.set(name, {
    ...status,
    lastRunAt: new Date().toISOString(),
    lastStatus: "running",
    lastError: undefined,
  });

  try {
    await job.run();
    state[globalKey].statuses.set(name, {
      ...status,
      lastRunAt: new Date().toISOString(),
      lastCompletedAt: new Date().toISOString(),
      lastStatus: "succeeded",
    });
  } catch (err) {
    state[globalKey].statuses.set(name, {
      ...status,
      lastRunAt: new Date().toISOString(),
      lastCompletedAt: new Date().toISOString(),
      lastStatus: "failed",
      lastError: err instanceof Error ? err.message : "Unknown error",
    });
  }
}

export function getJobStatuses() {
  return [...state[globalKey].statuses.values()];
}
