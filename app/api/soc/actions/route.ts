import { randomUUID } from "node:crypto";
import { and, eq } from "drizzle-orm";
import { NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { getConnectorDefinition } from "@/lib/connectors";
import { db, schema } from "@/lib/db/client";
import { complianceTemplates, requirePermission, type ComplianceFrameworkId, type RetentionTarget } from "@/lib/governance";
import type { IngestionSourceType } from "@/lib/ingestion";
import { getSession } from "@/lib/session";
import {
  addIncidentTask,
  assignAlert,
  assignIncident,
  createApiToken,
  createCaseForAlert,
  deleteApiToken,
  generateComplianceReport,
  getKelpieIntegration,
  getKelpieToken,
  listAlerts,
  listIncidents,
  markIncidentKelpieStatus,
  recordDelivery,
  runPlaybookForIncident,
  saveConnectorInstance,
  saveIntegrationChannel,
  saveRetentionPolicy,
  saveKelpieIntegration,
  saveSearch,
  saveSocSetting,
  syncEnabledThreatIntelFeeds,
  testConnectorInstance,
  testIntegrationChannel,
  testThreatIntelFeed,
  updateApiToken,
  updateAlertStatus,
  updateIncidentStatus,
  upsertIngestSource,
  upsertThreatIntelFeed,
  type ApiTokenRole,
  type ApiTokenScope,
  type ApiTokenStatus,
  type IntegrationChannelSetting,
  type SocActor,
} from "@/lib/store";
import { disableSigmaRule, duplicateSigmaRule, importSigmaRule } from "@/lib/sigma";
import { promoteAlertToKelpie, promoteIncidentToKelpie, recordDeliveryState } from "@/lib/soc-workflows";
import type { IntegrationDelivery, KelpieIntegrationConfig, ThreatIntelFeed } from "@/lib/types";

const validChannels: IntegrationDelivery["channel"][] = ["email", "slack", "webhook", "sentinel", "wazuh"];
const validRoles = new Set(["member", "admin", "owner"]);
const validFeedTypes: ThreatIntelFeed["type"][] = ["STIX", "OpenIOC", "CSV", "TXT", "MISP", "OTX", "URLhaus", "Custom URL"];
const validApiTokenScopes = new Set<ApiTokenScope>([
  "ingest:write",
  "events:read",
  "alerts:read",
  "alerts:write",
  "cases:read",
  "cases:write",
  "detections:read",
  "detections:write",
  "threat-intel:read",
  "threat-intel:write",
  "settings:read",
]);

export async function POST(request: Request) {
  const session = await getSession();
  if (!session) return NextResponse.json({ error: "Sign in required." }, { status: 401 });

  const body = await request.json().catch(() => ({}));
  const action = typeof body.action === "string" ? body.action : "";
  const actor = await resolveActor(session);

  try {
    if (action === "assign-alert") {
      requirePermission(actor.role, "alert.assign");
      await assignAlert(required(body.alertId, "alertId"), actor);
      return ok("Alert assigned.");
    }
    if (action === "dismiss-alert") {
      requirePermission(actor.role, "alert.dismiss");
      await updateAlertStatus(required(body.alertId, "alertId"), "dismissed", actor);
      return ok("Alert dismissed.");
    }
    if (action === "suppress-alert") {
      requirePermission(actor.role, "alert.suppress");
      await updateAlertStatus(required(body.alertId, "alertId"), "suppressed", actor, "Suppressed alert and matching rule context.");
      return ok("Alert suppressed.");
    }
    if (action === "create-case") {
      requirePermission(actor.role, "case.write");
      const incident = await createCaseForAlert(required(body.alertId, "alertId"), actor);
      return ok(`Created ${incident.number}.`, { incidentId: incident.id });
    }
    if (action === "send-alert-kelpie") {
      requirePermission(actor.role, "integration.write");
      const alertId = required(body.alertId, "alertId");
      const alert = (await listAlerts()).find((item) => item.id === alertId);
      if (!alert) throw new Error("Alert not found.");
      const config = await getKelpieIntegration(actor.tenantId);
      const token = await getKelpieToken(actor.tenantId);
      const delivery = await promoteAlertToKelpie(alert, config, kelpieClient(config, token));
      await recordDelivery(delivery, actor.tenantId);
      return delivery.state === "delivered" ? ok("Sent alert to Kelpie.") : fail(delivery.error ?? "Kelpie delivery failed.", 400);
    }
    if (action === "assign-incident") {
      requirePermission(actor.role, "case.write");
      await assignIncident(required(body.incidentId, "incidentId"), actor);
      return ok("Case assigned.");
    }
    if (action === "change-incident-state") {
      requirePermission(actor.role, "case.write");
      await updateIncidentStatus(required(body.incidentId, "incidentId"), "investigating", actor);
      return ok("Case state changed.");
    }
    if (action === "add-task") {
      requirePermission(actor.role, "case.write");
      await addIncidentTask(required(body.incidentId, "incidentId"), actor);
      return ok("Task added.");
    }
    if (action === "run-playbook") {
      requirePermission(actor.role, "case.write");
      await runPlaybookForIncident(required(body.incidentId, "incidentId"), typeof body.playbookId === "string" ? body.playbookId : undefined, actor);
      return ok("Playbook tasks created.");
    }
    if (action === "sync-incident-kelpie" || action === "sync-comments") {
      requirePermission(actor.role, "integration.write");
      await syncIncident(required(body.incidentId, "incidentId"), actor);
      return ok(action === "sync-comments" ? "Comments synced to Kelpie." : "Case synced to Kelpie.");
    }
    if (action === "send-test-alert") {
      const config = await getKelpieIntegration(actor.tenantId);
      const token = await getKelpieToken(actor.tenantId);
      const delivery = await sendKelpieTestAlert(config, token, actor.tenantId);
      return delivery.state === "delivered" ? ok("Kelpie test alert delivered.") : fail(delivery.error ?? "Kelpie test failed.", 400);
    }
    if (action === "sync-stale-cases") {
      const incidents = (await listIncidents()).filter((incident) => incident.kelpieSyncStatus === "stale" || incident.kelpieSyncStatus === "failed");
      for (const incident of incidents) await syncIncident(incident.id, actor);
      return ok(`Synced ${incidents.length} stale case${incidents.length === 1 ? "" : "s"}.`);
    }
    if (action === "save-kelpie-config") {
      requirePermission(actor.role, "integration.write");
      await saveKelpieIntegration({
        tenantId: actor.tenantId,
        baseUrl: optionalString(body.baseUrl),
        tokenReference: optionalString(body.tokenReference),
        enabled: Boolean(body.enabled),
        syncFields: parseStringList(body.syncFields),
      });
      return ok("Kelpie integration saved.");
    }
    if (action === "save-integration-channel" || action === "test-integration-channel") {
      requirePermission(actor.role, "integration.write");
      const input = parseIntegrationChannel(body, actor.tenantId);
      if (action === "save-integration-channel") {
        await saveIntegrationChannel(input);
        return ok(`${label(input.channel)} integration saved.`);
      }
      await testIntegrationChannel(input);
      return ok(`${label(input.channel)} test delivered.`);
    }
    if (action === "add-threat-feed") {
      requirePermission(actor.role, "integration.write");
      const name = required(body.name, "name");
      const type = typeof body.type === "string" && validFeedTypes.includes(body.type as ThreatIntelFeed["type"])
        ? body.type as ThreatIntelFeed["type"]
        : "Custom URL";
      await upsertThreatIntelFeed({
        tenantId: actor.tenantId,
        name,
        type,
        url: required(body.url, "url"),
        enabled: Boolean(body.enabled),
      });
      return ok(`Threat feed saved: ${name}.`);
    }
    if (action === "test-threat-feed") {
      requirePermission(actor.role, "integration.write");
      const count = await testThreatIntelFeed(required(body.feedId, "feedId"), actor.tenantId);
      return ok(`Threat feed tested and loaded ${count.toLocaleString()} indicator${count === 1 ? "" : "s"}.`);
    }
    if (action === "sync-enabled-threat-feeds") {
      requirePermission(actor.role, "integration.write");
      const results = await syncEnabledThreatIntelFeeds(actor.tenantId);
      const loaded = results.reduce((total, result) => total + result.count, 0);
      return ok(`Synced ${results.length} feed${results.length === 1 ? "" : "s"} and loaded ${loaded.toLocaleString()} indicators.`);
    }
    if (action === "save-soc-setting") {
      requirePermission(actor.role, "settings.write");
      const settingKey = required(body.settingKey, "settingKey");
      if (!isRecord(body.values)) throw new Error("values must be an object.");
      await saveSocSetting(actor.tenantId, settingKey, body.values);
      return ok("Setting saved.");
    }
    if (action === "save-ingest-source") {
      requirePermission(actor.role, "integration.write");
      const id = await upsertIngestSource({
        tenantId: actor.tenantId,
        name: required(body.name, "name"),
        sourceType: parseSourceType(body.sourceType),
        authMode: optionalString(body.authMode) || "shared-secret",
        parser: optionalString(body.parser) || "generic-json",
      });
      return ok("Ingestion source saved.", { sourceId: id });
    }
    if (action === "save-connector" || action === "test-connector") {
      requirePermission(actor.role, "integration.write");
      const catalogId = required(body.catalogId, "catalogId");
      if (action === "save-connector") {
        const id = await saveConnectorInstance({
          tenantId: actor.tenantId,
          catalogId,
          name: optionalString(body.name),
          enabled: Boolean(body.enabled),
          schedule: optionalString(body.schedule) || "manual",
          config: parseConnectorConfig(body),
          credential: optionalString(body.credential),
        });
        return ok("Connector saved.", { connectorId: id });
      }
      await testConnectorInstance(actor.tenantId, catalogId);
      return ok("Connector configuration passed validation.");
    }
    if (action === "generate-compliance-report") {
      requirePermission(actor.role, "report.export");
      const framework = parseComplianceFramework(body.framework);
      const id = await generateComplianceReport(actor.tenantId, framework, actor);
      return ok("Compliance report generated.", { reportId: id });
    }
    if (action === "save-retention-policy") {
      requirePermission(actor.role, "settings.write");
      await saveRetentionPolicy(actor.tenantId, {
        target: parseRetentionTarget(body.target),
        hotDays: clampDays(body.hotDays, 1, 3650),
        archiveDays: clampDays(body.archiveDays, 1, 3650),
        deleteAfterDays: clampDays(body.deleteAfterDays, 1, 3650),
        preserveCaseEvidence: Boolean(body.preserveCaseEvidence),
        legalHold: Boolean(body.legalHold),
      });
      return ok("Retention policy saved.");
    }
    if (action === "create-api-token") {
      requirePermission(actor.role, "settings.write");
      const result = await createApiToken({
        tenantId: actor.tenantId,
        name: required(body.name, "name"),
        role: parseApiTokenRole(body.role),
        scopes: parseApiTokenScopes(body.scopes),
        expiresAt: parseOptionalDate(body.expiresAt),
        actor,
      });
      return ok("API token created. Copy the secret now.", { token: result.token, tokenId: result.record.id, tokenPrefix: result.record.tokenPrefix });
    }
    if (action === "update-api-token") {
      requirePermission(actor.role, "settings.write");
      await updateApiToken({
        tenantId: actor.tenantId,
        tokenId: required(body.tokenId, "tokenId"),
        name: required(body.name, "name"),
        role: parseApiTokenRole(body.role),
        scopes: parseApiTokenScopes(body.scopes),
        status: parseApiTokenStatus(body.status),
        expiresAt: parseOptionalDate(body.expiresAt),
        actor,
      });
      return ok("API token updated.");
    }
    if (action === "delete-api-token") {
      requirePermission(actor.role, "settings.write");
      await deleteApiToken(actor.tenantId, required(body.tokenId, "tokenId"), actor);
      return ok("API token deleted.");
    }
    if (action === "invite-user") {
      requirePermission(actor.role, "user.admin");
      await inviteUser(request, body, actor);
      return ok("Invitation created and magic link sent.");
    }
    if (action === "add-user") {
      requirePermission(actor.role, "user.admin");
      await addExistingUser(body, actor);
      return ok("User added to the tenant.");
    }
    if (action === "import-sigma") {
      requirePermission(actor.role, "detection.write");
      const rule = await importSigmaRule(required(body.sigma, "sigma"));
      return ok(`Imported ${rule.title}.`);
    }
    if (action === "duplicate-rule") {
      requirePermission(actor.role, "detection.write");
      const rule = await duplicateSigmaRule(required(body.ruleId, "ruleId"));
      return ok(`Duplicated ${rule.title}.`);
    }
    if (action === "disable-rule") {
      requirePermission(actor.role, "detection.write");
      await disableSigmaRule(required(body.ruleId, "ruleId"));
      return ok("Rule disabled.");
    }
    if (action === "save-search") {
      const search = await saveSearch(required(body.query, "query"));
      return ok(`Saved search: ${search.name}.`);
    }
    return fail("Unknown action.", 400);
  } catch (error) {
    return fail(error instanceof Error ? error.message : "Action failed.", 400);
  }
}

async function resolveActor(session: NonNullable<Awaited<ReturnType<typeof getSession>>>): Promise<SocActor> {
  const activeOrganizationId = (session.session as { activeOrganizationId?: string | null }).activeOrganizationId;
  if (activeOrganizationId) {
    const [membership] = await db.select().from(schema.member)
      .where(and(eq(schema.member.userId, session.user.id), eq(schema.member.organizationId, activeOrganizationId)))
      .limit(1);
    return { id: session.user.id, name: session.user.name || session.user.email, tenantId: activeOrganizationId, role: membership?.role ?? "member" };
  }

  const [membership] = await db.select().from(schema.member).where(eq(schema.member.userId, session.user.id)).limit(1);
  return {
    id: session.user.id,
    name: session.user.name || session.user.email,
    tenantId: membership?.organizationId ?? "local-tenant",
    role: membership?.role ?? "member",
  };
}

async function syncIncident(incidentId: string, actor: SocActor) {
  const incident = (await listIncidents()).find((item) => item.id === incidentId);
  if (!incident) throw new Error("Case not found.");
  const config = await getKelpieIntegration(actor.tenantId);
  const token = await getKelpieToken(actor.tenantId);
  const synced = await promoteIncidentToKelpie(incident, config, kelpieClient(config, token));
  const detail = synced.timeline.at(-1)?.detail ?? "Kelpie sync completed.";
  await markIncidentKelpieStatus(incidentId, actor, synced.kelpieSyncStatus, detail, synced.kelpieCaseId, synced.kelpieUrl);
}

async function sendKelpieTestAlert(config: KelpieIntegrationConfig, token: string, tenantId: string) {
  const delivery = recordDeliveryState(undefined, "queued");
  const target = "/api/v1/alerts";
  if (!config.enabled || !config.baseUrl || !token) {
    const failed = { ...delivery, channel: "kelpie" as const, target, state: "failed" as const, error: "Kelpie integration is not fully configured", externalRef: "tawny-test-alert" };
    await recordDelivery(failed, tenantId);
    return failed;
  }
  try {
    const result = await kelpieClient(config, token).createAlert({
      externalRef: "tawny-test-alert",
      title: "Tawny-SOC integration test",
      severity: "low",
      source: "Tawny-SOC",
      tenantId,
    });
    const delivered = { ...delivery, channel: "kelpie" as const, target, state: "delivered" as const, externalRef: result.id };
    await recordDelivery(delivered, tenantId);
    return delivered;
  } catch (error) {
    const failed = { ...delivery, channel: "kelpie" as const, target, state: "failed" as const, error: error instanceof Error ? error.message : "Kelpie test failed.", externalRef: "tawny-test-alert" };
    await recordDelivery(failed, tenantId);
    return failed;
  }
}

function kelpieClient(config: KelpieIntegrationConfig, token: string) {
  const baseUrl = config.baseUrl.replace(/\/$/, "");
  const headers = {
    "content-type": "application/json",
    authorization: `Bearer ${token}`,
  };
  return {
    async createAlert(input: Record<string, unknown>) {
      return sendKelpie(`${baseUrl}/api/v1/alerts`, "POST", headers, input);
    },
    async createCase(input: Record<string, unknown>) {
      return sendKelpie(`${baseUrl}/api/v1/cases`, "POST", headers, input);
    },
    async syncCase(id: string, input: Record<string, unknown>) {
      return sendKelpie(`${baseUrl}/api/v1/cases/${encodeURIComponent(id)}`, "PUT", headers, input);
    },
  };
}

async function sendKelpie(url: string, method: "POST" | "PUT", headers: Record<string, string>, input: Record<string, unknown>) {
  const res = await fetch(url, { method, headers, body: JSON.stringify(input) });
  if (!res.ok) throw new Error(`Kelpie returned HTTP ${res.status}`);
  const body = await res.json().catch(() => ({})) as { id?: string; url?: string };
  return { id: body.id ?? `kelpie-${Date.now()}`, url: body.url };
}

async function inviteUser(request: Request, body: Record<string, unknown>, actor: SocActor) {
  const email = required(body.email, "email").toLowerCase();
  const role = parseRole(body.role);
  const existing = await db.select().from(schema.invitation)
    .where(and(eq(schema.invitation.organizationId, actor.tenantId), eq(schema.invitation.email, email), eq(schema.invitation.status, "pending")))
    .limit(1);
  const invitationId = existing[0]?.id ?? `invite-${randomUUID()}`;
  if (!existing.length) {
    await db.insert(schema.invitation).values({
      id: invitationId,
      organizationId: actor.tenantId,
      email,
      role,
      status: "pending",
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60_000),
      inviterId: actor.id,
      createdAt: new Date(),
    });
  }

  const callbackURL = `/accept-invite?invitationId=${encodeURIComponent(invitationId)}`;
  await auth.api.signInMagicLink({
    headers: request.headers,
    body: {
      email,
      callbackURL,
      newUserCallbackURL: callbackURL,
      errorCallbackURL: "/sign-in",
      metadata: { tenantId: actor.tenantId },
    },
  });
}

async function addExistingUser(body: Record<string, unknown>, actor: SocActor) {
  const email = required(body.email, "email").toLowerCase();
  const role = parseRole(body.role);
  const [user] = await db.select().from(schema.user).where(eq(schema.user.email, email)).limit(1);
  if (!user) throw new Error("No account found for that email. Send an invite instead.");
  await db.insert(schema.member).values({
    id: `member-${randomUUID()}`,
    organizationId: actor.tenantId,
    userId: user.id,
    role,
    createdAt: new Date(),
  }).onConflictDoUpdate({
    target: [schema.member.organizationId, schema.member.userId],
    set: { role },
  });
}

function parseIntegrationChannel(body: Record<string, unknown>, tenantId: string): IntegrationChannelSetting & { tenantId: string } {
  const channel = required(body.channel, "channel") as IntegrationDelivery["channel"];
  if (!validChannels.includes(channel)) throw new Error("Unsupported integration channel.");
  return {
    tenantId,
    channel,
    enabled: Boolean(body.enabled),
    endpoint: optionalString(body.endpoint),
    credential: optionalString(body.credential),
    credentialConfigured: false,
  };
}

function parseSourceType(value: unknown): IngestionSourceType {
  const aliases: Record<string, IngestionSourceType> = {
    "generic-json": "generic_json",
    "generic_json": "generic_json",
    "syslog-cef": "cef",
    "syslog": "syslog",
    "cef": "cef",
    "windows-sysmon": "sysmon",
    "windows_event": "windows_event",
    "sysmon": "sysmon",
    "aws-cloudtrail": "aws_cloudtrail",
    "aws_cloudtrail": "aws_cloudtrail",
    "azure-entra": "azure_signin",
    "azure_signin": "azure_signin",
    "azure_activity": "azure_activity",
    "microsoft-365": "microsoft365_audit",
    "microsoft365_audit": "microsoft365_audit",
    "firewall": "firewall",
  };
  const sourceType = typeof value === "string" ? aliases[value] : undefined;
  return sourceType ?? "generic_json";
}

function parseConnectorConfig(body: Record<string, unknown>) {
  const config: Record<string, unknown> = {};
  const item = typeof body.catalogId === "string" ? getConnectorDefinition(body.catalogId) : undefined;
  if (!item) return config;
  for (const field of [...item.requiredFields, ...item.optionalFields]) {
    const value = body[field.key];
    if (typeof value === "string" && value.trim()) config[field.key] = value.trim();
  }
  return config;
}

function parseComplianceFramework(value: unknown): ComplianceFrameworkId {
  const id = typeof value === "string" ? value : "";
  if (complianceTemplates.some((template) => template.id === id)) return id as ComplianceFrameworkId;
  throw new Error("Unsupported compliance framework.");
}

function parseRetentionTarget(value: unknown): RetentionTarget {
  const id = typeof value === "string" ? value : "";
  const allowed = new Set(["events", "alerts", "cases", "audit", "threatIntel", "integrationLogs"]);
  if (allowed.has(id)) return id as RetentionTarget;
  throw new Error("Unsupported retention target.");
}

function clampDays(value: unknown, min: number, max: number) {
  const days = Number(value);
  if (!Number.isFinite(days)) return min;
  return Math.min(max, Math.max(min, Math.round(days)));
}

function parseRole(value: unknown) {
  const role = typeof value === "string" && validRoles.has(value) ? value : "member";
  return role;
}

function parseApiTokenRole(value: unknown): ApiTokenRole {
  return value === "owner" || value === "admin" || value === "member" ? value : "member";
}

function parseApiTokenStatus(value: unknown): ApiTokenStatus {
  return value === "revoked" ? "revoked" : "active";
}

function parseApiTokenScopes(value: unknown): ApiTokenScope[] {
  const raw = Array.isArray(value) ? value : typeof value === "string" ? value.split(",") : [];
  return raw
    .map((scope) => typeof scope === "string" ? scope.trim() : "")
    .filter((scope): scope is ApiTokenScope => validApiTokenScopes.has(scope as ApiTokenScope))
    .filter((scope, index, all) => all.indexOf(scope) === index);
}

function parseOptionalDate(value: unknown) {
  if (typeof value !== "string" || !value.trim()) return null;
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) throw new Error("Expiry date is invalid.");
  return date;
}

function parseStringList(value: unknown) {
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === "string").map((item) => item.trim()).filter(Boolean);
  return optionalString(value).split(",").map((item) => item.trim()).filter(Boolean);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function optionalString(value: unknown) {
  return typeof value === "string" ? value.trim() : "";
}

function label(value: string) {
  return value.slice(0, 1).toUpperCase() + value.slice(1);
}

function required(value: unknown, name: string) {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${name} is required.`);
  return value.trim();
}

function ok(message: string, extra?: Record<string, unknown>) {
  return NextResponse.json({ ok: true, message, ...extra });
}

function fail(error: string, status: number) {
  return NextResponse.json({ error }, { status });
}
