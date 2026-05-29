# Tawny-SOC

AI-focused SOC/SIEM workspace for Tawny. It receives Tawny alerts and telemetry as an HTTP log sink, enriches records with Sigma-style detections and threat intel context, and presents a modern analyst workspace for triage, cases, detection engineering, playbooks, hunting, and Kelpie handoff.

## Local Development

Run Postgres in Docker, then run the Next.js 16 App Router dashboard with Turbopack via `pnpm dev`.

```bash
pnpm install
docker compose up -d db
pnpm db:migrate
pnpm seed
pnpm dev
```

Open `http://localhost:3001`.

Do not run the web app locally through Docker. The `app` Docker Compose service is behind an explicit profile for container/deployment checks only.

The local seed creates:

- Local tenant: `local-tenant`
- Local analyst: `analyst@tawny.local`
- Local password: `TawnySocLocal123!`
- Starter threat intel feed endpoints, including OpenPhish and PhishTank URL feeds

`pnpm seed` is intended for local reset work. It keeps the local analyst and organization ready, seeds starter threat intel feed endpoints, and clears local SOC alerts, telemetry, cases, tasks, delivery logs, and timelines.

## SIEM Overview

The SOC workspace includes:

- SOC Overview: alert volume, incident volume, open cases, critical/high alerts, affected hosts, queue health, top rules, top MITRE tactics, top users, top processes, top external IPs, trends, and needs-attention items.
- Scalable ingestion: Tawny HTTP ingest, generic JSON, syslog/CEF, Windows Event/Sysmon, AWS CloudTrail, Azure sign-in/activity, Microsoft 365 audit, firewall/network logs, parser normalization, dead-letter tracking, and source health.
- Connector catalog: cloud, identity, SaaS, network, endpoint, and generic connectors with required fields, credential references, safe local test actions, status, schedule, and redaction.
- Alert Queue: severity, confidence, status, rule, source, host, user, process, MITRE, TI hits, assignee, filters, and bulk action controls.
- Alert Detail: summary, evidence, raw JSON, threat intel matches, MITRE mapping, analyst timeline, and actions for case creation, Kelpie promotion, suppression, and response.
- Incidents / Cases: native Tawny-SOC case grouping with priority, lifecycle, assignment, TLP/PAP, classification, observables, linked hosts, linked alerts, SLA state, evidence records, and Kelpie sync state.
- Detection Rules: Sigma-style detection-as-code view with working YAML import, metadata, ATT&CK mapping, test status, current revision, last-triggered state, scheduled detections, multi-event correlation helpers, and tuning actions.
- Threat Intelligence: feed management and searchable, sortable, filterable, paginated IOC browser for STIX, OpenIOC, CSV, TXT, MISP, OTX, URLhaus, and custom URL feeds.
- Playbooks: ordered SOC workflows for malware, suspicious PowerShell, new admin user, suspicious outbound IP, credential theft, host isolation, and suspicious URL style investigations.
- Search / Hunt: YAAQL-powered enterprise hunt workspace for event type, host, user, process, hash, IP, domain, time, and payload-path queries, with examples, field pivots, saved searches, and clickable saved-search loading.
- Integrations: email, Slack, webhook, Microsoft Sentinel, Wazuh, Kelpie, connector health, endpoint/token/credential configuration, delivery tests, and delivery state.
- SOC Settings: split settings subpages for severity mapping, notification routing, suppression, threat intel TTL, case numbering, SLAs, role permissions, team access, API tokens, retention, compliance reports, and audit logs.
- Access and authentication: BetterAuth sign-in/sign-up, team member administration under Settings, tenant invitations, magic-link invite flow, and MFA posture display.
- API tokens: tenant-scoped API keys with role-limited scopes, create/update/revoke/delete workflows, and bearer-token access for ingest and read APIs.
- Governance: RBAC checks, audit log records, evidence tracking, compliance report templates, hot/archive/delete retention policies, and scheduled threat intel/retention cron jobs.

## YAAQL Search Language

Tawny-SOC includes YAAQL, the "Yet Another Annoying Query Language" filter used by the Search / Hunt page and the `q` parameter on `GET /api/events` and `GET /api/alerts`. It is intentionally small and KQL-like so analysts can type one string instead of juggling another pile of vendor-specific search widgets.

YAAQL supports:

- Free text: `"powershell.exe"` searches across the whole normalized record.
- Field contains: `host:win-*`, `title:dns`, `commandLine:powershell`.
- Field exact match: `eventType=ProcessLaunch`, `kind=alert`, `severity=critical`.
- Negation: `status!=suppressed`, `not host:lab-*`.
- Boolean logic: `severity:critical or severity:high`, `kind:alert and host:win-*`.
- Grouping: `(eventType=DnsQuery or has:domain) and severity in (medium, high)`.
- Lists: `severity in (critical, high)`, `rule in (tawny-sigma-ps-encoded-command, tawny-sigma-credential-dump-artifact)`.
- Existence checks: `has:ip`, `has:domain`, `has:hash`, `has:mitre`.
- Numeric and timestamp comparisons: `confidence>=0.8`, `timestamp>=2026-05-27T00:00:00Z`.
- Payload paths: `payload.alert.command_line:powershell`, `payload.query_name:*.example`.

Adjacent terms are treated as `and`, so `host:win-* powershell` is the same as `host:win-* and powershell`. Common aliases are built in for analyst-friendly fields: `host`, `type`, `rule`, `mitre`, `tenant`, `agent`, `cmd`, `ip`, `domain`, `hash`, `user`, and `process`.

## Tawny Integration

Configure Tawny with:

```json
"TawnySoc": {
  "Enabled": true,
  "AlertsEnabled": true,
  "TelemetryEnabled": true,
  "EndpointUrl": "http://localhost:3001/api/ingest/tawny",
  "ApiToken": "",
  "BatchSize": 100,
  "TimeoutSeconds": 10
}
```

For bearer-token protection, create a tenant API token in `Settings -> API tokens` with the `ingest:write` scope, then set `Tawny:TawnySoc:ApiToken` in Tawny. The legacy `TAWNY_SOC_INGEST_TOKEN` environment variable is still supported for simple local collector protection.

`GET /api/events` accepts a session cookie or a bearer token with `events:read`. `GET /api/alerts` accepts a session cookie or a bearer token with `alerts:read`.

## Kelpie Integration

Configure Kelpie from `Integrations`. The database-backed Kelpie settings include base URL, token reference, enablement, dedupe mode, and fields to sync.

Tawny-SOC models Kelpie handoff with:

- Alert promotion to Kelpie inbound alert API using `externalRef`.
- Incident promotion to Kelpie cases using `tawny-case-*` external references.
- Dedupe by `externalRef`.
- Sync status: `not_synced`, `synced`, `failed`, `stale`, `conflict`.
- Delivery logs with retry/error state.

## Threat Intel Setup

Threat intel feed concepts support STIX, OpenIOC, CSV, TXT, MISP, OTX, URLhaus, and custom URL feeds. IOC matches attach to alerts and cases, and the Hunt screen includes a retro-hunt action pattern for searching historical Tawny telemetry by indicator value.

Starter feed endpoints seeded for local development:

- Feodo Tracker Botnet C2 IPs, enabled
- Spamhaus DROP Rogue Networks, enabled
- CISA Known Exploited Vulnerabilities, enabled
- OpenPhish Community Phishing URLs, enabled
- PhishTank Online Valid Phishing URLs, paused by default because the public CSV dump is large and rate-limited
- Emerging Threats Compromised IPs, paused by default
- Blocklist.de Recent Attackers, paused by default

Indicators loaded from feeds receive a configurable default TTL. The default is 7 days and can be changed in `Settings -> Threat intel`. Expired IOCs are excluded from the active indicator table and removed by the scheduled retention sweep.

The Threat Intelligence page is backed by database filters and shows 100 active indicators per page. Search, type filter, source feed filter, sort, and pagination update the URL through Next client routing while the table data stays server-backed.

## Settings And Administration

The Settings root page is a categorized index with tabs for all, operations, access, integrations, and governance. Each settings area also has its own subpage under `/settings/[section]` so administration screens keep the main SOC layout and left navigation.

Available settings sections:

- Severity mapping
- Notification routing
- Suppression rules
- Threat intel TTL
- Case numbering
- SLA rules
- Role permissions
- Team access
- API tokens
- Retention policies
- Compliance reports
- Audit log

## Playbook Model

Playbooks are ordered workflows with phases, owners, objectives, evidence requirements, and optional response actions. Running a playbook against a case creates case tasks in the SOC workflow layer.

## Alert-To-Case Workflow

1. Tawny sends alerts or telemetry to `POST /api/ingest/tawny`.
2. Tawny-SOC maps records to Sigma-style rule context and MITRE techniques.
3. Threat intel enrichment attaches IOC matches and raises confidence.
4. Analysts assign, dismiss, suppress, or promote alerts into native Tawny-SOC cases.
5. Cases track ownership, lifecycle, observables, tasks, comments, and audit timeline.
6. Cases can be promoted or synced to Kelpie while retaining external references.

## Tests

```bash
pnpm typecheck
pnpm lint
pnpm test
pnpm build
```

Current workflow tests cover incident creation from alert, alert/case assignment, TI enrichment, Kelpie alert promotion, Kelpie case sync, notification delivery state, multi-tenant isolation, and suppression behavior.

## Sources And Inspiration

- Vigil-style agents and workflows: `incident-response`, `full-investigation`, and `threat-hunt`.
- Detection engineering model: starter Sigma rules plus `scripts/import-vigil-detection-repos.mjs`, mirroring Vigil's external detection-repository approach.
- Panther, Sentinel, Splunk ES, Falcon Next-Gen SIEM, Elastic Security, and Wazuh product patterns: detection-as-code, cases/incidents, TI enrichment, correlation, hunt/search, automation, and analyst-first triage.
