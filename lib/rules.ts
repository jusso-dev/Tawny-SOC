import type { Playbook, SigmaRule } from "@/lib/types";

export const sigmaRules: SigmaRule[] = [
  {
    id: "tawny-sigma-ps-encoded-command",
    title: "PowerShell Encoded Command Execution",
    status: "stable",
    severity: "high",
    source: "Tawny starter pack, patterned after Sigma/Security-Detections-MCP coverage for T1059.001",
    logsource: { product: "windows", category: "process_creation" },
    mitreTechniques: ["T1059.001", "T1027"],
    tags: ["attack.execution", "attack.defense-evasion", "windows", "powershell"],
    description: "Detects PowerShell launched with encoded command switches commonly used to hide payloads.",
    falsePositives: ["Administrative scripts that legitimately pass encoded commands."],
    detection: {
      selection_image: { Image: ["*\\powershell.exe", "*\\pwsh.exe"] },
      selection_flags: { CommandLine: ["*-enc *", "*-encodedcommand *", "*/encodedcommand *"] },
      condition: "selection_image and selection_flags",
    },
    sigma: `title: PowerShell Encoded Command Execution
id: tawny-sigma-ps-encoded-command
status: stable
description: Detects PowerShell launched with encoded command switches.
logsource:
  product: windows
  category: process_creation
detection:
  selection_image:
    Image|endswith:
      - '\\powershell.exe'
      - '\\pwsh.exe'
  selection_flags:
    CommandLine|contains:
      - '-enc '
      - '-encodedcommand '
      - '/encodedcommand '
  condition: selection_image and selection_flags
level: high
tags:
  - attack.t1059.001
  - attack.t1027`,
  },
  {
    id: "tawny-sigma-lolbin-mshta-script",
    title: "MSHTA Script Proxy Execution",
    status: "stable",
    severity: "high",
    source: "Tawny starter pack, patterned after public Sigma LOLBin detections",
    logsource: { product: "windows", category: "process_creation" },
    mitreTechniques: ["T1218.005", "T1059"],
    tags: ["attack.defense-evasion", "attack.execution", "lolbin", "windows"],
    description: "Detects mshta.exe executing inline script or remote content, a frequent script proxy technique.",
    falsePositives: ["Legacy enterprise applications that still use HTA content."],
    detection: {
      selection_image: { Image: "*\\mshta.exe" },
      selection_suspicious: { CommandLine: ["*http://*", "*https://*", "*javascript:*", "*vbscript:*"] },
      condition: "selection_image and selection_suspicious",
    },
    sigma: `title: MSHTA Script Proxy Execution
id: tawny-sigma-lolbin-mshta-script
status: stable
logsource:
  product: windows
  category: process_creation
detection:
  selection_image:
    Image|endswith: '\\mshta.exe'
  selection_suspicious:
    CommandLine|contains:
      - 'http://'
      - 'https://'
      - 'javascript:'
      - 'vbscript:'
  condition: selection_image and selection_suspicious
level: high
tags:
  - attack.t1218.005
  - attack.t1059`,
  },
  {
    id: "tawny-sigma-linux-shell-curl-pipe",
    title: "Shell Download Piped To Interpreter",
    status: "test",
    severity: "medium",
    source: "Tawny starter pack for Linux endpoint telemetry",
    logsource: { product: "linux", category: "process_creation" },
    mitreTechniques: ["T1059.004", "T1105"],
    tags: ["attack.execution", "attack.command-and-control", "linux"],
    description: "Detects curl or wget output piped into a shell or interpreter.",
    falsePositives: ["Bootstrap scripts in development workstations or CI hosts."],
    detection: {
      selection_download: { CommandLine: ["*curl *|*sh*", "*wget *|*sh*", "*curl *|*python*", "*wget *|*python*"] },
      condition: "selection_download",
    },
    sigma: `title: Shell Download Piped To Interpreter
id: tawny-sigma-linux-shell-curl-pipe
status: test
logsource:
  product: linux
  category: process_creation
detection:
  selection_download:
    CommandLine|contains:
      - 'curl '
      - 'wget '
    CommandLine|contains:
      - '| sh'
      - '| bash'
      - '| python'
  condition: selection_download
level: medium
tags:
  - attack.t1059.004
  - attack.t1105`,
  },
  {
    id: "tawny-sigma-macos-launch-agent-persistence",
    title: "macOS LaunchAgent Persistence Path Write",
    status: "test",
    severity: "medium",
    source: "Tawny starter pack for macOS file telemetry",
    logsource: { product: "macos", category: "file_event" },
    mitreTechniques: ["T1543.001"],
    tags: ["attack.persistence", "macos"],
    description: "Detects writes into common LaunchAgent and LaunchDaemon persistence directories.",
    falsePositives: ["Legitimate software installers and MDM enrollment tasks."],
    detection: {
      selection_path: {
        TargetFilename: [
          "*/Library/LaunchAgents/*.plist",
          "*/Library/LaunchDaemons/*.plist",
          "*/Users/*/Library/LaunchAgents/*.plist",
        ],
      },
      condition: "selection_path",
    },
    sigma: `title: macOS LaunchAgent Persistence Path Write
id: tawny-sigma-macos-launch-agent-persistence
status: test
logsource:
  product: macos
  category: file_event
detection:
  selection_path:
    TargetFilename|contains:
      - '/Library/LaunchAgents/'
      - '/Library/LaunchDaemons/'
      - '/Users/'
  condition: selection_path
level: medium
tags:
  - attack.t1543.001`,
  },
  {
    id: "tawny-sigma-suspicious-dns-dga-shape",
    title: "Suspicious DNS Query Shape",
    status: "experimental",
    severity: "medium",
    source: "Tawny starter pack for DNS telemetry",
    logsource: { product: "tawny", category: "dns" },
    mitreTechniques: ["T1071.004", "T1568"],
    tags: ["attack.command-and-control", "dns", "hunting"],
    description: "Flags long, high-entropy looking DNS labels that may indicate generated domains or tunneled content.",
    falsePositives: ["CDN cache keys, tracking domains, and SaaS telemetry endpoints."],
    detection: {
      selection_dns: { QueryName: ["regex:[a-z0-9]{22,}\\.[a-z]{2,}"] },
      condition: "selection_dns",
    },
    sigma: `title: Suspicious DNS Query Shape
id: tawny-sigma-suspicious-dns-dga-shape
status: experimental
logsource:
  product: tawny
  category: dns
detection:
  selection_dns:
    QueryName|re: '[a-z0-9]{22,}\\.[a-z]{2,}'
  condition: selection_dns
level: medium
tags:
  - attack.t1071.004
  - attack.t1568`,
  },
  {
    id: "tawny-sigma-credential-dump-artifact",
    title: "Credential Dumping Artifact Access",
    status: "stable",
    severity: "critical",
    source: "Tawny starter pack, patterned after Sigma credential access coverage",
    logsource: { product: "windows", category: "process_creation" },
    mitreTechniques: ["T1003", "T1003.001"],
    tags: ["attack.credential-access", "windows"],
    description: "Detects common credential dumping strings in process command lines.",
    falsePositives: ["Security tools testing credential access detections."],
    detection: {
      selection: { CommandLine: ["*lsass*dmp*", "*procdump*lsass*", "*sekurlsa::*", "*comsvcs.dll*MiniDump*"] },
      condition: "selection",
    },
    sigma: `title: Credential Dumping Artifact Access
id: tawny-sigma-credential-dump-artifact
status: stable
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - 'lsass'
      - 'procdump'
      - 'sekurlsa::'
      - 'MiniDump'
  condition: selection
level: critical
tags:
  - attack.t1003
  - attack.t1003.001`,
  },
];

export const playbooks: Playbook[] = [
  {
    id: "incident-response",
    name: "Incident Response",
    description: "Rapid triage, investigation, containment planning, and analyst-ready reporting for a live alert.",
    severity: "critical",
    agents: ["Triage", "Investigator", "Responder", "Reporter"],
    triggers: ["critical alert", "confirmed malware", "active C2", "ransomware behavior"],
    phases: [
      {
        name: "Triage and classify",
        owner: "Triage",
        objective: "Validate the alert, severity, false-positive likelihood, and affected entities.",
        actions: ["Review matching rule evidence", "Check nearby host events", "Assign priority and category"],
      },
      {
        name: "Investigate root cause",
        owner: "Investigator",
        objective: "Build a timeline and determine the initial vector.",
        actions: ["Pivot by host, user, IP, hash", "Correlate ATT&CK techniques", "Collect supporting telemetry"],
      },
      {
        name: "Contain",
        owner: "Responder",
        objective: "Prepare reversible containment actions with confidence scores.",
        actions: ["Recommend host isolation if confidence is high", "List network and identity blocks", "Record approval state"],
      },
      {
        name: "Report",
        owner: "Reporter",
        objective: "Produce an audit-ready summary with evidence and rule improvement notes.",
        actions: ["Summarize impact", "List actions taken", "Add detection tuning recommendations"],
      },
    ],
  },
  {
    id: "full-investigation",
    name: "Full Investigation",
    description: "Deep-dive workflow with ATT&CK mapping, cross-signal correlation, and detection gap review.",
    severity: "high",
    agents: ["Investigator", "MITRE Analyst", "Correlator", "Responder", "Reporter"],
    triggers: ["clustered alerts", "lateral movement", "multi-stage activity", "executive report needed"],
    phases: [
      {
        name: "Evidence gathering",
        owner: "Investigator",
        objective: "Collect all events, entities, and telemetry around the alert window.",
        actions: ["Build entity inventory", "Find related events", "Normalize evidence timestamps"],
      },
      {
        name: "ATT&CK mapping",
        owner: "MITRE Analyst",
        objective: "Map observed behavior to techniques and identify missing coverage.",
        actions: ["Map rule tags", "Score kill-chain progression", "Recommend new Sigma coverage"],
      },
      {
        name: "Correlation",
        owner: "Correlator",
        objective: "Group related alerts by entity, time, and technique.",
        actions: ["Score alert relationships", "Build attack narrative", "Suggest case grouping"],
      },
      {
        name: "Response planning",
        owner: "Responder",
        objective: "Plan containment and recovery steps across the full blast radius.",
        actions: ["Prioritize affected hosts", "Draft containment plan", "Define recovery monitoring"],
      },
    ],
  },
  {
    id: "threat-hunt",
    name: "Threat Hunt",
    description: "Hypothesis-driven hunt across endpoint telemetry, DNS, process events, and known detection patterns.",
    severity: "medium",
    agents: ["Threat Hunter", "Network Analyst", "Threat Intel", "Reporter"],
    triggers: ["hunt hypothesis", "IOC validation", "coverage gap", "suspicious infrastructure"],
    phases: [
      {
        name: "Form hypothesis",
        owner: "Threat Hunter",
        objective: "Define scope, time range, and the suspicious behavior to hunt.",
        actions: ["Choose ATT&CK technique", "Select data sources", "Generate hunt query"],
      },
      {
        name: "Analyze network signals",
        owner: "Network Analyst",
        objective: "Check DNS and network telemetry for C2, beaconing, or lateral movement.",
        actions: ["Review DNS shape", "Inspect destination rarity", "Find repeated intervals"],
      },
      {
        name: "Enrich IOCs",
        owner: "Threat Intel",
        objective: "Attach reputation and campaign context to discovered indicators.",
        actions: ["Extract IPs, domains, hashes", "Prioritize known-bad indicators", "List blocks and watch items"],
      },
      {
        name: "Hunt report",
        owner: "Reporter",
        objective: "State whether the hypothesis is confirmed, refuted, or inconclusive.",
        actions: ["Summarize evidence", "List IOCs", "Recommend detection changes"],
      },
    ],
  },
];

export const agents = [
  { name: "Triage", mode: "Fast", role: "Severity scoring, false-positive checks, escalation decisions" },
  { name: "Investigator", mode: "Deep", role: "Evidence collection, timelines, root-cause analysis" },
  { name: "Threat Hunter", mode: "Deep", role: "Hypothesis generation, anomaly discovery, Sigma gap checks" },
  { name: "MITRE Analyst", mode: "Deep", role: "Technique mapping, coverage rollups, detection templates" },
  { name: "Correlator", mode: "Deep", role: "Campaign linking across host, time, and technique signals" },
  { name: "Responder", mode: "Fast", role: "Containment plans, approval requests, blast-radius notes" },
  { name: "Reporter", mode: "Balanced", role: "Executive summaries and technical incident reports" },
];
