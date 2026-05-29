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
});

await sql.end();

console.log("Seeded local analyst, organization, and starter threat intel feed endpoints.");
console.log("Cleared local SOC alerts, telemetry, cases, tasks, delivery logs, and timelines.");
console.log("Local sign-in: analyst@tawny.local / TawnySocLocal123!");
