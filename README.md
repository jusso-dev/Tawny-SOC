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

## SIEM Overview

The SOC workspace includes:

- SOC Overview: alert volume, incident volume, open cases, critical/high alerts, affected hosts, queue health, top rules, top MITRE tactics, top users, top processes, top external IPs, trends, and needs-attention items.
- Alert Queue: severity, confidence, status, rule, source, host, user, process, MITRE, TI hits, assignee, filters, and bulk action controls.
- Alert Detail: summary, evidence, raw JSON, threat intel matches, MITRE mapping, analyst timeline, and actions for case creation, Kelpie promotion, suppression, and response.
- Incidents / Cases: native Tawny-SOC case grouping with priority, lifecycle, assignment, TLP/PAP, classification, observables, linked hosts, linked alerts, and Kelpie sync state.
- Detection Rules: Sigma-style detection-as-code view with YAML, metadata, test status, version-history placeholder, last-triggered state, and tuning actions.
- Threat Intelligence: feed management and IOC browser for STIX, OpenIOC, CSV, TXT, MISP, OTX, URLhaus, and custom URL feeds.
- Playbooks: ordered SOC workflows for malware, suspicious PowerShell, new admin user, suspicious outbound IP, credential theft, host isolation, and suspicious URL style investigations.
- Search / Hunt: query-builder workspace for event type, host, user, process, hash, IP, domain, and time range.
- Integrations: email, Slack, webhook, Microsoft Sentinel, Wazuh, and Kelpie delivery state.
- SOC Settings: severity mapping, routing rules, suppression, case numbering, SLAs, TI feeds, Kelpie sync, and role permissions.

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

Set `TAWNY_SOC_INGEST_TOKEN` in this app and `Tawny:TawnySoc:ApiToken` in Tawny when you want bearer-token protection.

## Kelpie Integration

Set:

```bash
KELPIE_BASE_URL=http://localhost:3000
KELPIE_API_TOKEN=your-kelpie-token
```

Tawny-SOC models Kelpie handoff with:

- Alert promotion to Kelpie inbound alert API using `externalRef`.
- Incident promotion to Kelpie cases using `tawny-case-*` external references.
- Dedupe by `externalRef`.
- Sync status: `not_synced`, `synced`, `failed`, `stale`, `conflict`.
- Delivery logs with retry/error state.

## Threat Intel Setup

Threat intel feed concepts support STIX, OpenIOC, CSV, TXT, MISP, OTX, URLhaus, and custom URL feeds. IOC matches attach to alerts and cases, and the Hunt screen includes a retro-hunt action pattern for searching historical Tawny telemetry by indicator value.

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
