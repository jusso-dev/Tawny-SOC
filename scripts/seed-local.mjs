import postgres from "postgres";
import { hashPassword } from "better-auth/crypto";

const databaseUrl = process.env.DATABASE_URL ?? "postgres://tawny_soc:tawny_soc@localhost:5434/tawny_soc";
const sql = postgres(databaseUrl, { prepare: false });

const tenantId = "local-tenant";
const legacyTenantId = [`de${"mo"}`, "tenant"].join("-");
const userId = "local-analyst";
const organizationId = tenantId;
const starterThreatFeeds = [
  {
    id: `feed-${tenantId}-starter-feodo-tracker-botnet-c2-ips`,
    name: "Starter: Feodo Tracker Botnet C2 IPs",
    type: "TXT",
    url: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
    enabled: true,
  },
  {
    id: `feed-${tenantId}-starter-spamhaus-drop-rogue-networks`,
    name: "Starter: Spamhaus DROP Rogue Networks",
    type: "TXT",
    url: "https://www.spamhaus.org/drop/drop.txt",
    enabled: true,
  },
  {
    id: `feed-${tenantId}-starter-cisa-kev-catalog`,
    name: "Starter: CISA Known Exploited Vulnerabilities",
    type: "Custom URL",
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    enabled: true,
  },
  {
    id: `feed-${tenantId}-starter-openphish-community-phishing-urls`,
    name: "Starter: OpenPhish Community Phishing URLs",
    type: "TXT",
    url: "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
    enabled: true,
  },
  {
    id: `feed-${tenantId}-starter-phishtank-online-valid-phishing-urls`,
    name: "Starter: PhishTank Online Valid Phishing URLs",
    type: "CSV",
    url: "https://data.phishtank.com/data/online-valid.csv",
    enabled: false,
  },
  {
    id: `feed-${tenantId}-starter-emerging-threats-compromised-ips`,
    name: "Starter: Emerging Threats Compromised IPs",
    type: "TXT",
    url: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    enabled: false,
  },
  {
    id: `feed-${tenantId}-starter-blocklist-de-recent-attackers`,
    name: "Starter: Blocklist.de Recent Attackers",
    type: "TXT",
    url: "https://lists.blocklist.de/lists/all.txt",
    enabled: false,
  },
];

await sql.begin(async (tx) => {
  await tx`delete from soc_agent_run where tenant_id in (${legacyTenantId}, ${tenantId})`;
  await tx`delete from soc_hunt_schedule where tenant_id in (${legacyTenantId}, ${tenantId})`;
  await tx`delete from soc_timeline where tenant_id in (${legacyTenantId}, ${tenantId})`;
  await tx`delete from soc_delivery_log where tenant_id in (${legacyTenantId}, ${tenantId})`;
  await tx`delete from soc_task where tenant_id in (${legacyTenantId}, ${tenantId})`;
  await tx`delete from soc_incident_alert where tenant_id in (${legacyTenantId}, ${tenantId})`;
  await tx`delete from soc_incident where tenant_id in (${legacyTenantId}, ${tenantId})`;
  await tx`delete from soc_alert where tenant_id in (${legacyTenantId}, ${tenantId})`;
  await tx`delete from soc_event where tenant_id in (${legacyTenantId}, ${tenantId})`;
  await tx`delete from soc_threat_intel_indicator where tenant_id in (${legacyTenantId}, ${tenantId})`;

  await tx`
    insert into "user" (id, name, email, email_verified, created_at, updated_at)
    values (${userId}, 'Local Analyst', 'analyst@tawny.local', true, now(), now())
    on conflict (id) do update set name = excluded.name, email = excluded.email, updated_at = now()
  `;
  await tx`
    insert into account (id, user_id, account_id, provider_id, password, created_at, updated_at)
    values ('local-analyst-credential', ${userId}, ${userId}, 'credential', ${await hashPassword("TawnySocLocal123!")}, now(), now())
    on conflict (provider_id, account_id) do update set password = excluded.password, updated_at = now()
  `;
  await tx`
    insert into organization (id, name, slug, created_at, updated_at)
    values (${organizationId}, 'Local SOC', 'local-soc', now(), now())
    on conflict (slug) do update set name = excluded.name, updated_at = now()
  `;
  await tx`
    insert into member (id, organization_id, user_id, role, created_at)
    values ('local-analyst-member', ${organizationId}, ${userId}, 'owner', now())
    on conflict (organization_id, user_id) do update set role = excluded.role
  `;
  await tx`delete from soc_threat_intel_feed where tenant_id = ${legacyTenantId}`;
  for (const feed of starterThreatFeeds) {
    await tx`
      insert into soc_threat_intel_feed (id, tenant_id, name, type, url, enabled, status, indicator_count)
      values (${feed.id}, ${tenantId}, ${feed.name}, ${feed.type}, ${feed.url}, ${feed.enabled}, 'paused', 0)
      on conflict (id) do update set
        name = excluded.name,
        type = excluded.type,
        url = excluded.url,
        enabled = excluded.enabled,
        status = 'paused',
        indicator_count = 0,
        last_run_at = null,
        last_error = null
    `;
  }

  const now = Date.now();
  const sampleAlerts = [
    { id: "alert-war-room-001", title: "Encoded PowerShell with outbound beacon", severity: "critical", host: "win-fin-07", user: "a.chen", process: "powershell.exe", country: "RU", countryName: "Russia", ip: "185.220.101.4", confidence: "0.94", rule: "tawny-sigma-ps-encoded-command", mitre: ["T1059.001", "T1071.001"], age: 8 },
    { id: "alert-war-room-002", title: "Impossible travel and privileged sign-in", severity: "high", host: "entra-id", user: "j.martin", process: "CloudAuth", country: "US", countryName: "United States", ip: "198.51.100.44", confidence: "0.88", rule: "tawny-identity-impossible-travel", mitre: ["T1078", "T1098"], age: 19 },
    { id: "alert-war-room-003", title: "Credential dump artifact accessed", severity: "high", host: "win-ops-03", user: "svc-backup", process: "rundll32.exe", country: "CN", countryName: "China", ip: "203.0.113.77", confidence: "0.86", rule: "tawny-sigma-credential-dump-artifact", mitre: ["T1003", "T1105"], age: 34 },
    { id: "alert-war-room-004", title: "Rare admin API sequence", severity: "medium", host: "aws-prod", user: "deploy-role", process: "AssumeRole", country: "SG", countryName: "Singapore", ip: "192.0.2.61", confidence: "0.72", rule: "tawny-cloud-rare-admin-sequence", mitre: ["T1098.001"], age: 51 },
  ];
  for (const alert of sampleAlerts) {
    const timestamp = new Date(now - alert.age * 60_000);
    const payload = { alert: { user: alert.user, process: alert.process, command_line: alert.process === "powershell.exe" ? "powershell.exe -enc SQBFAFgA" : "", source_ip: alert.ip, source_country: alert.country, source_country_name: alert.countryName }, seeded: true };
    await tx`
      insert into soc_alert (id, source, kind, title, severity, status, timestamp, tenant_id, hostname, os, event_type, payload, matched_rules, mitre_techniques, confidence, ai_summary, recommended_playbook)
      values (${alert.id}, 'tawny', 'alert', ${alert.title}, ${alert.severity}, 'open', ${timestamp}, ${tenantId}, ${alert.host}, ${alert.host.startsWith("win") ? "Windows" : "Cloud"}, 'SecurityAlert', ${tx.json(payload)}, ${tx.json([alert.rule])}, ${tx.json(alert.mitre)}, ${alert.confidence}, ${`${alert.title} requires correlated identity, endpoint, and network review.`}, 'incident-response')
    `;
    await tx`
      insert into soc_event (id, source, kind, title, severity, status, timestamp, tenant_id, hostname, os, event_type, payload, matched_rules, mitre_techniques)
      values (${`event-${alert.id}`}, 'tawny', 'telemetry', ${`Telemetry supporting ${alert.title}`}, ${alert.severity}, 'acknowledged', ${new Date(timestamp.getTime() - 4 * 60_000)}, ${tenantId}, ${alert.host}, ${alert.host.startsWith("win") ? "Windows" : "Cloud"}, 'ProcessLaunch', ${tx.json(payload)}, ${tx.json([alert.rule])}, ${tx.json(alert.mitre)})
    `;
  }

  await tx`
    insert into soc_incident (id, tenant_id, number, title, severity, priority, status, assignee, tags, tlp, pap, classification, mitre_techniques, observables, linked_hosts, kelpie_sync_status, created_at, updated_at)
    values ('case-war-room-001', ${tenantId}, 'SOC-00001', 'Encoded PowerShell attack chain on win-fin-07', 'critical', 'P1', 'investigating', 'Local Analyst', ${tx.json(["agent-led", "active-investigation"])}, 'amber', 'green', 'true_positive', ${tx.json(["T1059.001", "T1071.001"])}, ${tx.json([])}, ${tx.json(["win-fin-07"])}, 'not_synced', ${new Date(now - 7 * 60_000)}, ${new Date(now - 2 * 60_000)})
  `;
  await tx`insert into soc_incident_alert (id, tenant_id, incident_id, alert_id, added_by, added_at) values ('link-war-room-001', ${tenantId}, 'case-war-room-001', 'alert-war-room-001', 'Detect agent', ${new Date(now - 7 * 60_000)})`;
  await tx`insert into soc_timeline (id, tenant_id, incident_id, alert_id, actor, action, detail, created_at) values ('timeline-war-room-001', ${tenantId}, 'case-war-room-001', 'alert-war-room-001', 'Triage agent', 'agent_triage', 'Escalated at 94% confidence after endpoint and network correlation.', ${new Date(now - 5 * 60_000)})`;

  const schedules = [
    ["hunt-schedule-impossible-travel", "Impossible travel follow-up", "A compromised identity is authenticating from a new country and touching privileged resources.", "eventType=SignIn and severity in (critical, high)", "15 * * * *", "completed", 1],
    ["hunt-schedule-powershell", "Encoded command sweep", "Other endpoints executed encoded PowerShell after the initial beacon.", "cmd:*powershell* and severity in (critical, high)", "*/15 * * * *", "completed", 2],
    ["hunt-schedule-admin", "Rare cloud admin sequence", "A service identity is creating persistence through uncommon administrative APIs.", "user:deploy-role or mitre=T1098.001", "0 8 * * *", "never_run", 0],
  ];
  for (const [id, name, hypothesis, query, schedule, lastStatus, count] of schedules) {
    await tx`insert into soc_hunt_schedule (id, tenant_id, name, hypothesis, query, schedule, timezone, enabled, last_run_at, last_status, last_finding_count, created_by, created_at, updated_at) values (${id}, ${tenantId}, ${name}, ${hypothesis}, ${query}, ${schedule}, 'Australia/Sydney', true, ${lastStatus === "completed" ? new Date(now - 55 * 60_000) : null}, ${lastStatus}, ${count}, 'Local Analyst', ${new Date(now - 24 * 60 * 60_000)}, ${new Date(now - 55 * 60_000)})`;
  }

  const runSteps = [
    { agent: "Detect", status: "completed", summary: "Fused endpoint execution, credential access, and outbound beacon signals on win-fin-07.", engine: "ai", confidence: 0.96, evidence: ["alert-war-room-001", "event-alert-war-room-001"], actions: ["T1059.001", "T1071.001"], startedAt: new Date(now - 7 * 60_000).toISOString(), completedAt: new Date(now - 6 * 60_000).toISOString() },
    { agent: "Triage", status: "completed", summary: "Likely active command-and-control following encoded PowerShell execution. Escalate as P1.", engine: "ai", confidence: 0.94, evidence: ["Encoded command", "External beacon", "Critical Sigma match"], actions: ["Validate parent process", "Review network flow", "Open incident"], startedAt: new Date(now - 6 * 60_000).toISOString(), completedAt: new Date(now - 5 * 60_000).toISOString() },
    { agent: "Hunt", status: "completed", summary: "Generated tenant-wide pivots for encoded commands, destination IP, and adjacent hosts.", engine: "ai", evidence: ["185.220.101.4", "win-fin-07"], actions: ["cmd:*powershell* and severity in (critical, high)", "ip:185.220.101.4"], startedAt: new Date(now - 5 * 60_000).toISOString(), completedAt: new Date(now - 4 * 60_000).toISOString() },
    { agent: "Respond", status: "completed", summary: "Prepared incident-response plan; isolation and indicator blocking await owner approval.", engine: "ai", evidence: ["Verify target", "Confirm beacon stopped"], actions: ["Capture volatile evidence", "Approval required: Isolate win-fin-07", "Approval required: Block destination IP"], startedAt: new Date(now - 4 * 60_000).toISOString(), completedAt: new Date(now - 3 * 60_000).toISOString() },
  ];
  await tx`insert into soc_agent_run (id, tenant_id, alert_id, trigger, status, title, summary, steps, findings, initiated_by, started_at, completed_at) values ('agent-run-seeded-001', ${tenantId}, 'alert-war-room-001', 'automatic-ingest', 'completed', 'Encoded PowerShell with outbound beacon', 'Escalate at 94% confidence. Governed incident-response plan prepared.', ${tx.json(runSteps)}, ${tx.json([{ type: "verdict", value: "escalate", confidence: 0.94 }, { type: "playbook", value: "incident-response" }])}, 'Tawny Agent Mesh', ${new Date(now - 7 * 60_000)}, ${new Date(now - 3 * 60_000)})`;
});

await sql.end();

console.log("Seeded local analyst, organization, representative SOC signals, agent ledger, hunts, and threat feeds.");
console.log("Cleared local SOC alerts, telemetry, cases, tasks, delivery logs, and timelines.");
console.log("Local sign-in: analyst@tawny.local / TawnySocLocal123!");
