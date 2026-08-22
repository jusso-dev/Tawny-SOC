export const socAgentIds = [
  "triage",
  "investigator",
  "threat_hunter",
  "correlator",
  "responder",
  "reporter",
  "mitre_analyst",
  "forensics",
  "threat_intel",
  "compliance",
  "malware_analyst",
  "network_analyst",
  "auto_responder",
] as const;

export type SocAgentId = typeof socAgentIds[number];

export type SocAgentProfile = {
  id: SocAgentId;
  name: string;
  initials: string;
  color: string;
  description: string;
  specialization: string;
  tools: string[];
  maxTokens: number;
  deepReasoning: boolean;
  methodology: string[];
};

export const socAgentProfiles: SocAgentProfile[] = [
  {
    id: "triage", name: "Triage Agent", initials: "TR", color: "#ff6b6b",
    description: "Rapid alert assessment, false-positive filtering, and priority decisions.", specialization: "Alert triage",
    tools: ["get_alert", "list_related_signals", "create_case"], maxTokens: 2048, deepReasoning: false,
    methodology: ["Assess severity and detection quality", "Classify likely threat category", "Decide escalation with confidence"],
  },
  {
    id: "investigator", name: "Investigation Agent", initials: "IN", color: "#4ecdc4",
    description: "Root-cause analysis, evidence collection, and timeline reconstruction.", specialization: "Deep investigation",
    tools: ["get_alert", "list_related_signals", "search_telemetry"], maxTokens: 4096, deepReasoning: true,
    methodology: ["Collect related evidence", "Reconstruct the timeline", "Identify root cause and blast radius"],
  },
  {
    id: "threat_hunter", name: "Threat Hunter", initials: "TH", color: "#95e1d3",
    description: "Hypothesis-driven hunting across retained tenant telemetry.", specialization: "Proactive threat hunting",
    tools: ["hunt_yaaql", "search_telemetry", "list_related_signals"], maxTokens: 4096, deepReasoning: true,
    methodology: ["State a falsifiable hypothesis", "Define scope and evidence needed", "Return valid YAAQL pivots"],
  },
  {
    id: "correlator", name: "Correlation Agent", initials: "CO", color: "#f38181",
    description: "Cross-signal linking, attack-chain reconstruction, and entity mapping.", specialization: "Signal correlation",
    tools: ["list_related_signals", "search_telemetry", "get_attack_mapping"], maxTokens: 4096, deepReasoning: true,
    methodology: ["Find time and entity overlap", "Map technique progression", "Score correlation strength"],
  },
  {
    id: "responder", name: "Response Agent", initials: "RS", color: "#ff8b94",
    description: "Reversible containment planning with owner-approved destructive actions.", specialization: "Incident response",
    tools: ["get_alert", "list_playbooks", "request_approval"], maxTokens: 3072, deepReasoning: false,
    methodology: ["Assess blast radius", "Plan least-disruptive containment", "Define eradication, recovery, and verification"],
  },
  {
    id: "reporter", name: "Reporting Agent", initials: "RP", color: "#a8e6cf",
    description: "Evidence-grounded executive and technical reporting.", specialization: "Reporting and communication",
    tools: ["get_case", "get_agent_ledger", "get_attack_mapping"], maxTokens: 4096, deepReasoning: false,
    methodology: ["Separate observed facts from inference", "Build chronological narrative", "Tailor actions and impact to audience"],
  },
  {
    id: "mitre_analyst", name: "MITRE ATT&CK Analyst", initials: "MA", color: "#ffd3b6",
    description: "Technique mapping, kill-chain analysis, and coverage-gap identification.", specialization: "ATT&CK analysis",
    tools: ["get_attack_mapping", "list_detection_rules", "get_alert"], maxTokens: 4096, deepReasoning: true,
    methodology: ["Map evidence to specific techniques", "Assess tactic progression", "Identify coverage gaps without inventing evidence"],
  },
  {
    id: "forensics", name: "Forensics Agent", initials: "DF", color: "#ffaaa5",
    description: "Artifact examination, evidence preservation, and chain-of-custody planning.", specialization: "Digital forensics",
    tools: ["get_alert", "search_telemetry", "get_agent_ledger"], maxTokens: 4096, deepReasoning: true,
    methodology: ["Inventory evidence and provenance", "Preserve originals", "Reconstruct a defensible timeline"],
  },
  {
    id: "threat_intel", name: "Threat Intel Agent", initials: "TI", color: "#b4a7d6",
    description: "IOC enrichment, infrastructure overlap, and confidence-scored attribution.", specialization: "Threat intelligence",
    tools: ["lookup_indicators", "get_alert", "hunt_yaaql"], maxTokens: 4096, deepReasoning: true,
    methodology: ["Extract observables", "Compare retained intelligence", "Label attribution confidence and unknowns"],
  },
  {
    id: "compliance", name: "Compliance Agent", initials: "CP", color: "#c7ceea",
    description: "Control mapping, regulatory impact, and audit-ready evidence gaps.", specialization: "Compliance and policy",
    tools: ["get_case", "get_agent_ledger", "generate_compliance_report"], maxTokens: 3072, deepReasoning: false,
    methodology: ["Map evidence to applicable controls", "Identify notification or retention impact", "Record control gaps and owners"],
  },
  {
    id: "malware_analyst", name: "Malware Analyst", initials: "ML", color: "#ff6b9d",
    description: "Static and behavioural artifact assessment, family classification, and IOC extraction.", specialization: "Malware analysis",
    tools: ["get_alert", "lookup_indicators", "search_telemetry"], maxTokens: 4096, deepReasoning: true,
    methodology: ["Inspect available artifact metadata", "Separate static from behavioural evidence", "Extract capabilities and detection opportunities"],
  },
  {
    id: "network_analyst", name: "Network Analyst", initials: "NW", color: "#56ccf2",
    description: "Flow, protocol, beaconing, lateral-movement, and exfiltration analysis.", specialization: "Network security analysis",
    tools: ["search_telemetry", "lookup_indicators", "hunt_yaaql"], maxTokens: 4096, deepReasoning: true,
    methodology: ["Measure timing and traffic shape", "Inspect protocol and destination context", "Map C2, lateral movement, and exfiltration"],
  },
  {
    id: "auto_responder", name: "Auto-Response Agent", initials: "AR", color: "#ff6b6b",
    description: "Confidence-scored response proposals; every containment action remains approval-gated.", specialization: "Autonomous response coordination",
    tools: ["get_alert", "get_agent_ledger", "request_approval"], maxTokens: 3072, deepReasoning: true,
    methodology: ["Corroborate multiple signals", "Prefer surgical reversible actions", "Submit actions for approval with evidence and confidence"],
  },
];

export const socAgentById = Object.fromEntries(socAgentProfiles.map((agent) => [agent.id, agent])) as Record<SocAgentId, SocAgentProfile>;

export function isSocAgentId(value: unknown): value is SocAgentId {
  return typeof value === "string" && socAgentIds.includes(value as SocAgentId);
}
