import { socAgentById, type SocAgentId } from "@/lib/ai/agents/catalog";

export type AgentWorkflowPhase = {
  id: string;
  agent: SocAgentId;
  name: string;
  tools: string[];
  instructions: string;
  fallbackActions: string[];
  approvalRequired?: boolean;
};

export type AgentWorkflow = {
  id: string;
  name: string;
  description: string;
  useCase: string;
  phases: AgentWorkflowPhase[];
};

export const agentWorkflows: AgentWorkflow[] = [
  {
    id: "incident-response", name: "Incident Response", description: "Rapid triage, investigation, governed containment, and audit-ready reporting.", useCase: "Active high-confidence alert requiring end-to-end response.",
    phases: [
      phase("triage", "triage", "Triage and classify", "Classify severity, category, false-positive likelihood, and escalation priority.", ["Score severity and confidence", "Record escalation decision"]),
      phase("investigate", "investigator", "Deep investigation", "Reconstruct timeline, root cause, affected entities, and blast radius from retained evidence.", ["Build evidence timeline", "Identify root cause and affected entities"]),
      phase("respond", "responder", "Contain and recover", "Prepare reversible containment, eradication, recovery, and verification steps. Never claim containment executed.", ["Prepare containment proposal", "Define recovery verification"], true),
      phase("report", "reporter", "Document and report", "Produce an evidence-grounded executive summary and technical investigation record.", ["Draft executive summary", "Document evidence gaps and next actions"]),
    ],
  },
  {
    id: "full-investigation", name: "Full Investigation", description: "Deep evidence gathering, ATT&CK mapping, correlation, response planning, and reporting.", useCase: "Complex or clustered activity requiring full attack-chain analysis.",
    phases: [
      phase("evidence", "investigator", "Evidence gathering", "Collect related alerts and telemetry, entity inventory, and chronological evidence.", ["Inventory entities", "Build initial timeline"]),
      phase("attack-mapping", "mitre_analyst", "ATT&CK mapping", "Map observed behavior to ATT&CK techniques and identify visibility gaps.", ["Map observed techniques", "List coverage gaps"]),
      phase("correlation", "correlator", "Cross-signal correlation", "Link signals by time, entity, and technique progression into a defensible attack chain.", ["Score signal relationships", "Construct attack narrative"]),
      phase("response", "responder", "Response planning", "Prioritize reversible containment across the correlated scope and request approvals.", ["Prioritize containment", "Prepare approval requests"], true),
      phase("report", "reporter", "Comprehensive report", "Assemble findings, unknowns, ATT&CK coverage, response plan, and recommendations.", ["Compile technical report", "State unverified gaps"]),
    ],
  },
  {
    id: "threat-hunt", name: "Threat Hunt", description: "Hypothesis-driven hunt using behavioural, network, malware, and intelligence specialists.", useCase: "Proactive search for activity not yet represented by a confirmed incident.",
    phases: [
      phase("hypothesis", "threat_hunter", "Form and test hypothesis", "State a falsifiable hypothesis and generate bounded YAAQL pivots across retained data.", ["Define hunt scope", "Generate YAAQL pivots"]),
      phase("network", "network_analyst", "Analyse network behavior", "Measure beaconing, protocol anomalies, lateral movement, and exfiltration evidence.", ["Measure connection patterns", "Identify network pivots"]),
      phase("malware", "malware_analyst", "Examine artifacts", "Assess available artifact evidence, capabilities, family indicators, and detection opportunities.", ["Classify available artifacts", "Extract behavioural indicators"]),
      phase("intel", "threat_intel", "Enrich observables", "Enrich supplied observables from retained intelligence and label unknowns and attribution confidence.", ["Assess IOC reputation", "Identify infrastructure overlap"]),
      phase("report", "reporter", "Hunt report", "Resolve each hypothesis as supported, refuted, or inconclusive and document visibility limits.", ["Resolve hypothesis", "Recommend new detections"]),
    ],
  },
  {
    id: "forensic-analysis", name: "Forensic Analysis", description: "Evidence preservation, malware and network examination, and defensible reporting.", useCase: "Post-incident analysis requiring chain-of-custody and legal-grade separation of fact from inference.",
    phases: [
      phase("acquire", "forensics", "Acquire and preserve", "Build an evidence inventory, provenance record, and defensible master timeline.", ["Record evidence provenance", "Build custody-aware timeline"]),
      phase("malware", "malware_analyst", "Malware deep-dive", "Assess available artifacts without presenting unavailable dynamic analysis as completed.", ["Assess static evidence", "Record missing analysis capabilities"]),
      phase("network", "network_analyst", "Network forensics", "Quantify network behavior, external communications, lateral movement, and exfiltration evidence.", ["Quantify communication timeline", "Extract network indicators"]),
      phase("report", "reporter", "Forensic report", "Produce an audit-ready report that separates observed evidence, inference, and unexamined sources.", ["Compile forensic report", "Document evidence limitations"]),
    ],
  },
  {
    id: "compliance-review", name: "Compliance Review", description: "Investigation evidence mapped to control, notification, and audit obligations.", useCase: "Incident or control failure requiring regulatory and audit assessment.",
    phases: [
      phase("evidence", "investigator", "Collect compliance evidence", "Collect incident facts, affected assets, data types, decisions, and response timestamps.", ["Inventory evidence", "Identify affected data and systems"]),
      phase("controls", "compliance", "Map controls and obligations", "Map evidence to relevant control families and identify notification, retention, and ownership gaps.", ["Map applicable controls", "Flag notification and evidence gaps"]),
      phase("report", "reporter", "Audit package", "Create a concise audit record with facts, control findings, owners, and remediation dates.", ["Draft audit record", "Assign remediation evidence"]),
    ],
  },
  {
    id: "autonomous-containment", name: "Autonomous Containment", description: "Fast multi-signal validation and approval-gated containment proposals.", useCase: "Critical alert needing immediate coordination without bypassing human control.",
    phases: [
      phase("triage", "triage", "Rapid validation", "Confirm severity, scope, and false-positive risk using supplied evidence.", ["Validate threat confidence", "Set response priority"]),
      phase("correlate", "correlator", "Corroborate signals", "Require multi-signal corroboration and map affected entities before action.", ["Correlate independent signals", "Estimate blast radius"]),
      phase("propose", "auto_responder", "Propose containment", "Choose the narrowest reversible actions and submit each as approval-required. Never execute containment.", ["Prepare surgical action proposal", "Attach confidence and evidence"], true),
      phase("verify", "responder", "Plan verification", "Define pre-action target validation, rollback, and post-action verification.", ["Verify target immediately before approval", "Define rollback and success checks"], true),
    ],
  },
];

export const defaultAgentWorkflowId = "incident-response";

export function getAgentWorkflow(id: string) {
  return agentWorkflows.find((workflow) => workflow.id === id);
}

function phase(id: string, agent: SocAgentId, name: string, instructions: string, fallbackActions: string[], approvalRequired = false): AgentWorkflowPhase {
  return { id, agent, name, tools: [...socAgentById[agent].tools], instructions, fallbackActions, approvalRequired };
}
