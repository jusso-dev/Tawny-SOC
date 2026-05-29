import type { IncidentStatus, SocIncident, SocTimelineItem } from "../types";

export type IncidentLifecyclePhase = "intake" | "triage" | "investigation" | "containment" | "recovery" | "closure";

export type IncidentEvidenceType =
  | "log"
  | "pcap"
  | "screenshot"
  | "file"
  | "memory"
  | "disk"
  | "comment"
  | "external_case";

export type IncidentEvidenceRecord = {
  id: string;
  incidentId: string;
  type: IncidentEvidenceType;
  title: string;
  source: string;
  collectedAt: string;
  collectedBy: string;
  hash?: string;
  legalHold: boolean;
  chainOfCustody: Array<{
    actor: string;
    action: "collected" | "transferred" | "reviewed" | "sealed";
    at: string;
    detail: string;
  }>;
};

export type IncidentSlaPolicy = Record<SocIncident["priority"], {
  containWithinMinutes: number;
  atRiskThresholdMinutes: number;
}>;

export type IncidentSlaState = {
  state: "within" | "at_risk" | "breached" | "met" | "not_applicable";
  priority: SocIncident["priority"];
  targetAt?: string;
  minutesRemaining?: number;
  breachedByMinutes?: number;
  reason: string;
};

export const INCIDENT_PHASE_BY_STATUS: Record<IncidentStatus, IncidentLifecyclePhase> = {
  new: "intake",
  open: "intake",
  triaging: "triage",
  investigating: "investigation",
  contained: "containment",
  eradicated: "recovery",
  recovered: "recovery",
  closed: "closure",
};

export const INCIDENT_STATUS_TRANSITIONS: Record<IncidentStatus, readonly IncidentStatus[]> = {
  new: ["open", "triaging", "closed"],
  open: ["triaging", "investigating", "closed"],
  triaging: ["investigating", "contained", "closed"],
  investigating: ["contained", "closed"],
  contained: ["eradicated", "recovered", "closed"],
  eradicated: ["recovered", "closed"],
  recovered: ["closed"],
  closed: ["open"],
};

export const DEFAULT_INCIDENT_SLA_POLICY: IncidentSlaPolicy = {
  P1: { containWithinMinutes: 30, atRiskThresholdMinutes: 10 },
  P2: { containWithinMinutes: 120, atRiskThresholdMinutes: 30 },
  P3: { containWithinMinutes: 480, atRiskThresholdMinutes: 60 },
  P4: { containWithinMinutes: 1440, atRiskThresholdMinutes: 120 },
};

export function canTransitionIncidentStatus(from: IncidentStatus, to: IncidentStatus): boolean {
  if (from === to) return true;
  return INCIDENT_STATUS_TRANSITIONS[from].includes(to);
}

export function incidentLifecyclePhase(status: IncidentStatus): IncidentLifecyclePhase {
  return INCIDENT_PHASE_BY_STATUS[status];
}

export function calculateIncidentSlaState(
  incident: Pick<SocIncident, "priority" | "status" | "createdAt" | "timeline">,
  policy: IncidentSlaPolicy = DEFAULT_INCIDENT_SLA_POLICY,
  now = new Date(),
): IncidentSlaState {
  const priorityPolicy = policy[incident.priority];
  if (!priorityPolicy) {
    return {
      state: "not_applicable",
      priority: incident.priority,
      reason: `No SLA policy is configured for ${incident.priority}.`,
    };
  }

  if (isContainmentMet(incident.status, incident.timeline)) {
    return {
      state: "met",
      priority: incident.priority,
      reason: "Incident reached containment or a later lifecycle state.",
    };
  }

  const startedAt = new Date(incident.createdAt);
  if (Number.isNaN(startedAt.getTime())) {
    return {
      state: "not_applicable",
      priority: incident.priority,
      reason: "Incident creation time is invalid.",
    };
  }

  const target = new Date(startedAt.getTime() + priorityPolicy.containWithinMinutes * 60_000);
  const minutesRemaining = Math.floor((target.getTime() - now.getTime()) / 60_000);

  if (minutesRemaining < 0) {
    return {
      state: "breached",
      priority: incident.priority,
      targetAt: target.toISOString(),
      breachedByMinutes: Math.abs(minutesRemaining),
      reason: `Containment target of ${priorityPolicy.containWithinMinutes} minutes was missed.`,
    };
  }

  if (minutesRemaining <= priorityPolicy.atRiskThresholdMinutes) {
    return {
      state: "at_risk",
      priority: incident.priority,
      targetAt: target.toISOString(),
      minutesRemaining,
      reason: "Containment target is approaching.",
    };
  }

  return {
    state: "within",
    priority: incident.priority,
    targetAt: target.toISOString(),
    minutesRemaining,
    reason: "Incident remains within containment SLA.",
  };
}

export function createIncidentEvidenceRecord(input: {
  id: string;
  incidentId: string;
  type: IncidentEvidenceType;
  title: string;
  source: string;
  collectedAt: string;
  collectedBy: string;
  hash?: string;
  legalHold?: boolean;
}): IncidentEvidenceRecord {
  return {
    id: input.id,
    incidentId: input.incidentId,
    type: input.type,
    title: input.title,
    source: input.source,
    collectedAt: input.collectedAt,
    collectedBy: input.collectedBy,
    hash: input.hash,
    legalHold: input.legalHold ?? false,
    chainOfCustody: [
      {
        actor: input.collectedBy,
        action: "collected",
        at: input.collectedAt,
        detail: `Collected ${input.type} evidence from ${input.source}.`,
      },
    ],
  };
}

function isContainmentMet(status: IncidentStatus, timeline: readonly SocTimelineItem[]): boolean {
  if (["contained", "eradicated", "recovered", "closed"].includes(status)) return true;
  return timeline.some((item) => item.action === "case_contained" || item.action === "contained_incident");
}
