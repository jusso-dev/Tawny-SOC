export type ComplianceFrameworkId = "pci-dss" | "iso-27001" | "nist-csf" | "soc-2" | "essential-eight";

export type ComplianceCapability =
  | "access-control"
  | "incident-lifecycle"
  | "evidence"
  | "logging-monitoring"
  | "retention"
  | "integration-health"
  | "report-export";

export type ComplianceEvidenceType =
  | "rbac_matrix"
  | "incident_timeline"
  | "sla_summary"
  | "evidence_inventory"
  | "retention_decisions"
  | "integration_health"
  | "audit_log"
  | "detection_coverage"
  | "exception_register";

export type ComplianceReportSection = {
  id: string;
  title: string;
  objective: string;
  controlRefs: string[];
  capabilities: ComplianceCapability[];
  evidence: ComplianceEvidenceType[];
};

export type ComplianceReportTemplate = {
  id: ComplianceFrameworkId;
  name: string;
  version: string;
  sourceUrl: string;
  cadence: "monthly" | "quarterly" | "annual" | "on-demand";
  sections: ComplianceReportSection[];
};

export const REQUIRED_COMPLIANCE_CAPABILITIES: ComplianceCapability[] = [
  "access-control",
  "incident-lifecycle",
  "evidence",
  "logging-monitoring",
  "retention",
  "integration-health",
  "report-export",
];

export const COMPLIANCE_REPORT_TEMPLATES: Record<ComplianceFrameworkId, ComplianceReportTemplate> = {
  "pci-dss": {
    id: "pci-dss",
    name: "PCI DSS Assessment Evidence Pack",
    version: "PCI DSS v4.0.1",
    sourceUrl: "https://blog.pcisecuritystandards.org/just-published-pci-dss-v4-0-1",
    cadence: "quarterly",
    sections: [
      section("pci-access", "Access control and authentication", "Show least-privilege access for SOC actions and administrative changes.", ["Req. 7", "Req. 8"], ["access-control"], ["rbac_matrix", "audit_log"]),
      section("pci-log-review", "Logging and monitoring", "Summarize alert telemetry, detection coverage, and analyst review evidence.", ["Req. 10"], ["logging-monitoring", "evidence"], ["detection_coverage", "incident_timeline", "audit_log"]),
      section("pci-incident-response", "Incident response readiness", "Report case lifecycle, SLA performance, playbook actions, and retained evidence.", ["Req. 12.10"], ["incident-lifecycle", "evidence", "report-export"], ["incident_timeline", "sla_summary", "evidence_inventory"]),
      section("pci-retention", "Retention and legal hold", "Demonstrate retention decisions for payment-impacting alerts, logs, and incident evidence.", ["Req. 3", "Req. 10"], ["retention", "evidence"], ["retention_decisions", "exception_register"]),
      section("pci-third-party", "Integration and third-party evidence flow", "Track SIEM forwarding, case sync, and failed delivery remediation.", ["Req. 12.8"], ["integration-health", "report-export"], ["integration_health", "audit_log"]),
    ],
  },
  "iso-27001": {
    id: "iso-27001",
    name: "ISO/IEC 27001 ISMS Security Operations Report",
    version: "ISO/IEC 27001:2022",
    sourceUrl: "https://www.iso.org/standard/27001",
    cadence: "quarterly",
    sections: [
      section("iso-governance", "ISMS governance and measurement", "Provide management-system evidence for security operations objectives, metrics, and review inputs.", ["Clause 6", "Clause 8", "Clause 9"], ["report-export", "evidence"], ["sla_summary", "audit_log", "exception_register"]),
      section("iso-access", "Identity and access controls", "Map SOC role permissions to approved access and privileged actions.", ["Annex A 5.15", "Annex A 5.16", "Annex A 8.2"], ["access-control"], ["rbac_matrix", "audit_log"]),
      section("iso-detect", "Logging, monitoring, and event assessment", "Show how logs, detections, and integration checks support operational monitoring.", ["Annex A 8.15", "Annex A 8.16"], ["logging-monitoring", "integration-health"], ["detection_coverage", "integration_health"]),
      section("iso-respond", "Information security incident management", "Summarize case states, timelines, evidence, and post-incident actions.", ["Annex A 5.24", "Annex A 5.25", "Annex A 5.26", "Annex A 5.27", "Annex A 5.28"], ["incident-lifecycle", "evidence"], ["incident_timeline", "sla_summary", "evidence_inventory"]),
      section("iso-records", "Records retention", "Demonstrate preservation, disposal, and legal hold decisions for SOC records.", ["Annex A 5.33"], ["retention"], ["retention_decisions", "exception_register"]),
    ],
  },
  "nist-csf": {
    id: "nist-csf",
    name: "NIST CSF Security Operations Profile",
    version: "CSF 2.0",
    sourceUrl: "https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20",
    cadence: "quarterly",
    sections: [
      section("nist-govern", "Govern", "Summarize risk ownership, policy decisions, RBAC guardrails, and reporting commitments.", ["GV"], ["access-control", "report-export"], ["rbac_matrix", "audit_log", "exception_register"]),
      section("nist-identify", "Identify", "Map assets, alerts, and integration dependencies that shape SOC operating risk.", ["ID"], ["integration-health", "logging-monitoring"], ["integration_health", "detection_coverage"]),
      section("nist-protect", "Protect", "Show least-privilege access, retention safeguards, and evidence protection.", ["PR"], ["access-control", "retention", "evidence"], ["rbac_matrix", "retention_decisions", "evidence_inventory"]),
      section("nist-detect", "Detect", "Report detection coverage, alert queues, and stale telemetry.", ["DE"], ["logging-monitoring", "integration-health"], ["detection_coverage", "integration_health"]),
      section("nist-respond", "Respond", "Report incident lifecycle, containment SLA state, and response evidence.", ["RS"], ["incident-lifecycle", "evidence"], ["incident_timeline", "sla_summary"]),
      section("nist-recover", "Recover", "Summarize closure, recovery actions, and retained lessons learned.", ["RC"], ["incident-lifecycle", "report-export"], ["incident_timeline", "evidence_inventory"]),
    ],
  },
  "soc-2": {
    id: "soc-2",
    name: "SOC 2 Trust Services Security Operations Report",
    version: "2017 TSC with revised points of focus 2022",
    sourceUrl: "https://www.aicpa.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022",
    cadence: "quarterly",
    sections: [
      section("soc2-cc6", "Logical access", "Evidence least-privilege roles and privileged SOC actions.", ["CC6"], ["access-control"], ["rbac_matrix", "audit_log"]),
      section("soc2-cc7-detect", "System operations and detection", "Show anomaly detection, security-event assessment, and integration delivery health.", ["CC7.1", "CC7.2", "CC7.3"], ["logging-monitoring", "integration-health"], ["detection_coverage", "integration_health"]),
      section("soc2-cc7-respond", "Incident response", "Report incident classification, containment progress, tasks, comments, and evidence custody.", ["CC7.4", "CC7.5"], ["incident-lifecycle", "evidence"], ["incident_timeline", "sla_summary", "evidence_inventory"]),
      section("soc2-cc8", "Change and configuration evidence", "Summarize detection rule and integration configuration changes.", ["CC8"], ["report-export", "integration-health"], ["audit_log", "integration_health"]),
      section("soc2-cc9", "Risk mitigation and retention", "Track exceptions, legal hold, and retention decisions for SOC records.", ["CC9"], ["retention", "evidence"], ["retention_decisions", "exception_register"]),
    ],
  },
  "essential-eight": {
    id: "essential-eight",
    name: "Essential Eight SOC Readiness Report",
    version: "Maturity Model November 2023",
    sourceUrl: "https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/essential-eight/essential-eight-maturity-model",
    cadence: "quarterly",
    sections: [
      section("e8-application-control", "Application control and hardening signals", "Summarize detections and exceptions for unauthorized application execution.", ["Application control", "User application hardening"], ["logging-monitoring", "evidence"], ["detection_coverage", "exception_register"]),
      section("e8-patching", "Patch and vulnerability response", "Report security events and incidents tied to patch exposure and remediation evidence.", ["Patch applications", "Patch operating systems"], ["incident-lifecycle", "evidence"], ["incident_timeline", "evidence_inventory"]),
      section("e8-macros", "Macro and script abuse monitoring", "Show alert coverage for macro, script, and command-line abuse.", ["Configure Microsoft Office macro settings"], ["logging-monitoring"], ["detection_coverage"]),
      section("e8-admin", "Administrative privileges and access control", "Map privileged SOC actions to roles and audit trail evidence.", ["Restrict administrative privileges"], ["access-control", "report-export"], ["rbac_matrix", "audit_log"]),
      section("e8-mfa", "Multi-factor authentication monitoring", "Summarize MFA-related detections, incidents, and exceptions.", ["Multi-factor authentication"], ["logging-monitoring", "incident-lifecycle"], ["detection_coverage", "incident_timeline"]),
      section("e8-backups", "Backup and retained evidence", "Show evidence preservation, legal hold, and recovery-supporting retention decisions.", ["Regular backups"], ["retention", "integration-health", "evidence"], ["retention_decisions", "integration_health", "evidence_inventory"]),
    ],
  },
};

export function listComplianceReportTemplates(): ComplianceReportTemplate[] {
  return Object.values(COMPLIANCE_REPORT_TEMPLATES);
}

export function getComplianceReportTemplate(id: ComplianceFrameworkId): ComplianceReportTemplate {
  return COMPLIANCE_REPORT_TEMPLATES[id];
}

export function validateComplianceTemplateCoverage(template: ComplianceReportTemplate): ComplianceCapability[] {
  const present = new Set(template.sections.flatMap((section) => section.capabilities));
  return REQUIRED_COMPLIANCE_CAPABILITIES.filter((capability) => !present.has(capability));
}

function section(
  id: string,
  title: string,
  objective: string,
  controlRefs: string[],
  capabilities: ComplianceCapability[],
  evidence: ComplianceEvidenceType[],
): ComplianceReportSection {
  return { id, title, objective, controlRefs, capabilities, evidence };
}
