import type { IntegrationDelivery, Severity, SocIncident } from "@/lib/types";

export type SocRole = "owner" | "admin" | "analyst" | "responder" | "threat_hunter" | "detection_engineer" | "auditor" | "viewer" | "member";

export type SocPermission =
  | "alert.assign"
  | "alert.dismiss"
  | "alert.suppress"
  | "case.write"
  | "case.close"
  | "detection.write"
  | "integration.write"
  | "report.export"
  | "settings.write"
  | "user.admin";

export type RetentionTarget = "events" | "alerts" | "cases" | "audit" | "threatIntel" | "integrationLogs";

export type RetentionPolicy = {
  target: RetentionTarget;
  hotDays: number;
  archiveDays: number;
  deleteAfterDays: number;
  preserveCaseEvidence: boolean;
  legalHold: boolean;
};

export type ComplianceFrameworkId = "pci-dss" | "iso-27001" | "nist" | "soc-2" | "essential-eight";

export type ComplianceReportTemplate = {
  id: ComplianceFrameworkId;
  name: string;
  evidence: string[];
  sections: string[];
};

export const permissionMatrix: Record<SocRole, SocPermission[]> = {
  owner: ["alert.assign", "alert.dismiss", "alert.suppress", "case.write", "case.close", "detection.write", "integration.write", "report.export", "settings.write", "user.admin"],
  admin: ["alert.assign", "alert.dismiss", "alert.suppress", "case.write", "case.close", "detection.write", "integration.write", "report.export", "settings.write", "user.admin"],
  analyst: ["alert.assign", "alert.dismiss", "case.write", "report.export"],
  responder: ["alert.assign", "case.write", "case.close"],
  threat_hunter: ["alert.assign", "case.write", "report.export"],
  detection_engineer: ["alert.assign", "alert.suppress", "detection.write", "report.export"],
  auditor: ["report.export"],
  viewer: [],
  member: ["alert.assign", "case.write"],
};

export const complianceTemplates: ComplianceReportTemplate[] = [
  {
    id: "pci-dss",
    name: "PCI-DSS",
    sections: ["Authentication events", "Privileged access", "Change monitoring", "Incident response evidence"],
    evidence: ["audit_logs", "alerts", "cases", "access_reviews"],
  },
  {
    id: "iso-27001",
    name: "ISO 27001",
    sections: ["Security monitoring", "Incident management", "Access control", "Supplier integrations"],
    evidence: ["alerts", "case_timelines", "settings_changes", "integration_health"],
  },
  {
    id: "nist",
    name: "NIST CSF / 800-53",
    sections: ["Identify", "Protect", "Detect", "Respond", "Recover"],
    evidence: ["detections", "threat_intel", "cases", "playbook_runs", "audit_logs"],
  },
  {
    id: "soc-2",
    name: "SOC 2",
    sections: ["Security controls", "Availability monitoring", "Change management", "Incident evidence"],
    evidence: ["audit_logs", "reports", "alerts", "integration_delivery"],
  },
  {
    id: "essential-eight",
    name: "Essential Eight",
    sections: ["Application control", "Patch applications", "Restrict admin privileges", "Logging and monitoring"],
    evidence: ["detections", "alerts", "asset_events", "case_evidence"],
  },
];

export function hasPermission(role: string | undefined, permission: SocPermission) {
  const normalized = normalizeRole(role);
  return permissionMatrix[normalized].includes(permission);
}

export function requirePermission(role: string | undefined, permission: SocPermission) {
  if (!hasPermission(role, permission)) throw new Error(`Missing permission: ${permission}`);
}

export function normalizeRole(role: string | undefined): SocRole {
  if (!role) return "member";
  if (role === "admin" || role === "owner" || role === "member") return role;
  if (role in permissionMatrix) return role as SocRole;
  return "member";
}

export function retentionDecision(policy: RetentionPolicy, recordCreatedAt: string, options: { linkedToCase?: boolean; now?: Date } = {}) {
  if (policy.legalHold) return "preserve";
  if (policy.preserveCaseEvidence && options.linkedToCase) return "preserve";
  const ageDays = ageInDays(recordCreatedAt, options.now ?? new Date());
  if (ageDays >= policy.deleteAfterDays) return "delete";
  if (ageDays >= policy.archiveDays) return "archive";
  if (ageDays >= policy.hotDays) return "warm";
  return "hot";
}

export function slaState(incident: Pick<SocIncident, "severity" | "createdAt" | "status">, slaMinutes: Record<Severity, number>, now = new Date()) {
  if (incident.status === "closed") return "closed";
  const limit = slaMinutes[incident.severity] ?? slaMinutes.low;
  const elapsed = (now.getTime() - Date.parse(incident.createdAt)) / 60_000;
  if (elapsed > limit) return "breached";
  if (elapsed > limit * 0.8) return "at_risk";
  return "within_sla";
}

export function integrationHealth(delivery: Pick<IntegrationDelivery, "state" | "lastAttemptAt" | "attempts"> | undefined, enabled: boolean, now = new Date()) {
  if (!enabled) return "disabled";
  if (!delivery) return "untested";
  if (delivery.state === "failed") return "failed";
  if (delivery.state === "retrying") return "degraded";
  const ageHours = (now.getTime() - Date.parse(delivery.lastAttemptAt)) / 3_600_000;
  return ageHours > 24 ? "stale" : "healthy";
}

function ageInDays(value: string, now: Date) {
  return Math.max(0, (now.getTime() - Date.parse(value)) / 86_400_000);
}
