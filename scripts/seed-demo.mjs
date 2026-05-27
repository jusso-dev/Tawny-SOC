import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

const runtimeDir = path.join(process.cwd(), "data", "runtime");

const now = new Date();
const iso = (minutesAgo) => new Date(now.getTime() - minutesAgo * 60000).toISOString();

const alerts = [
  {
    id: "alert-9001",
    source: "tawny",
    kind: "alert",
    title: "Credential Dumping Artifact Access",
    severity: "critical",
    status: "open",
    timestamp: iso(6),
    tenantId: "demo-tenant",
    agentId: "demo-agent-01",
    hostname: "win-finance-07",
    os: "Windows",
    eventType: "ProcessLaunch",
    telemetryId: 41012,
    alertId: 9001,
    ruleId: "tawny-sigma-credential-dump-artifact",
    payload: {
      alert: {
        command_line: "rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 652 C:\\Temp\\lsass.dmp full",
        user: "FINANCE\\riley",
        process: "rundll32.exe",
        file_hash: "0f343b0931126a20f133d67c2b018a3b58f1d7d3f52e6f01dcf45d8aa0b8b2f1",
      },
    },
    matchedRules: ["tawny-sigma-credential-dump-artifact"],
    mitreTechniques: ["T1003", "T1003.001"],
    confidence: 0.88,
    aiSummary:
      "Credential Dumping Artifact Access on win-finance-07: behavior mapped to T1003 and T1003.001. Review neighboring Tawny telemetry before containment.",
    recommendedPlaybook: "incident-response",
  },
  {
    id: "alert-9002",
    source: "tawny",
    kind: "alert",
    title: "PowerShell Encoded Command Execution",
    severity: "high",
    status: "open",
    timestamp: iso(19),
    tenantId: "demo-tenant",
    agentId: "demo-agent-02",
    hostname: "win-eng-11",
    os: "Windows",
    eventType: "ProcessLaunch",
    telemetryId: 41022,
    alertId: 9002,
    ruleId: "tawny-sigma-ps-encoded-command",
    payload: {
      alert: {
        command_line: "powershell.exe -NoP -enc SQBFAFgA -w hidden",
        user: "ENG\\mika",
        process: "powershell.exe",
        destination_ip: "185.199.110.153",
      },
    },
    matchedRules: ["tawny-sigma-ps-encoded-command"],
    mitreTechniques: ["T1059.001", "T1027"],
    confidence: 0.81,
    aiSummary:
      "PowerShell Encoded Command Execution on win-eng-11: matched encoded PowerShell execution. Pivot to parent process and user context.",
    recommendedPlaybook: "incident-response",
  },
];

const events = [
  {
    id: "event-41050",
    source: "tawny",
    kind: "telemetry",
    title: "Suspicious DNS Query Shape",
    severity: "medium",
    status: "open",
    timestamp: iso(11),
    tenantId: "demo-tenant",
    agentId: "demo-agent-03",
    hostname: "mac-design-04",
    os: "Macos",
    eventType: "DnsQuery",
    telemetryId: 41050,
    payload: {
      query_name: "a83kdl29dls02ka9sldk20v.example",
      user: "DESIGN\\alex",
      process: "mDNSResponder",
    },
    matchedRules: ["tawny-sigma-suspicious-dns-dga-shape"],
    mitreTechniques: ["T1071.004", "T1568"],
  },
];

await mkdir(runtimeDir, { recursive: true });
await writeFile(path.join(runtimeDir, "alerts.json"), `${JSON.stringify(alerts, null, 2)}\n`, "utf8");
await writeFile(path.join(runtimeDir, "events.json"), `${JSON.stringify(events, null, 2)}\n`, "utf8");

console.log(`Seeded ${alerts.length} alerts and ${events.length} events.`);
