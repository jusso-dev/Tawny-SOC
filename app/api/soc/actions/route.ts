import { randomUUID } from "node:crypto";
import { and, eq } from "drizzle-orm";
import { NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { db, schema } from "@/lib/db/client";
import { getSession } from "@/lib/session";
import {
  addIncidentTask,
  assignAlert,
  assignIncident,
  createCaseForAlert,
  getKelpieIntegration,
  getKelpieToken,
  listAlerts,
  listIncidents,
  markIncidentKelpieStatus,
  recordDelivery,
  runPlaybookForIncident,
  saveIntegrationChannel,
  saveKelpieIntegration,
  saveSearch,
  saveSocSetting,
  testIntegrationChannel,
  testThreatIntelFeed,
  updateAlertStatus,
  updateIncidentStatus,
  upsertThreatIntelFeed,
  type IntegrationChannelSetting,
  type SocActor,
} from "@/lib/store";
import { disableSigmaRule, duplicateSigmaRule, importSigmaRule } from "@/lib/sigma";
import { promoteAlertToKelpie, promoteIncidentToKelpie, recordDeliveryState } from "@/lib/soc-workflows";
import type { IntegrationDelivery, KelpieIntegrationConfig, ThreatIntelFeed } from "@/lib/types";

const validChannels: IntegrationDelivery["channel"][] = ["email", "slack", "webhook", "sentinel", "wazuh"];
const validRoles = new Set(["member", "admin", "owner"]);
const validFeedTypes: ThreatIntelFeed["type"][] = ["STIX", "OpenIOC", "CSV", "TXT", "MISP", "OTX", "URLhaus", "Custom URL"];

export async function POST(request: Request) {
  const session = await getSession();
  if (!session) return NextResponse.json({ error: "Sign in required." }, { status: 401 });

  const body = await request.json().catch(() => ({}));
  const action = typeof body.action === "string" ? body.action : "";
  const actor = await resolveActor(session);

  try {
    if (action === "assign-alert") {
      await assignAlert(required(body.alertId, "alertId"), actor);
      return ok("Alert assigned.");
    }
    if (action === "dismiss-alert") {
      await updateAlertStatus(required(body.alertId, "alertId"), "dismissed", actor);
      return ok("Alert dismissed.");
    }
    if (action === "suppress-alert") {
      await updateAlertStatus(required(body.alertId, "alertId"), "suppressed", actor, "Suppressed alert and matching rule context.");
      return ok("Alert suppressed.");
    }
    if (action === "create-case") {
      const incident = await createCaseForAlert(required(body.alertId, "alertId"), actor);
      return ok(`Created ${incident.number}.`, { incidentId: incident.id });
    }
    if (action === "send-alert-kelpie") {
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
      await assignIncident(required(body.incidentId, "incidentId"), actor);
      return ok("Case assigned.");
    }
    if (action === "change-incident-state") {
      await updateIncidentStatus(required(body.incidentId, "incidentId"), "investigating", actor);
      return ok("Case state changed.");
    }
    if (action === "add-task") {
      await addIncidentTask(required(body.incidentId, "incidentId"), actor);
      return ok("Task added.");
    }
    if (action === "run-playbook") {
      await runPlaybookForIncident(required(body.incidentId, "incidentId"), typeof body.playbookId === "string" ? body.playbookId : undefined, actor);
      return ok("Playbook tasks created.");
    }
    if (action === "sync-incident-kelpie" || action === "sync-comments") {
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
      const input = parseIntegrationChannel(body, actor.tenantId);
      if (action === "save-integration-channel") {
        await saveIntegrationChannel(input);
        return ok(`${label(input.channel)} integration saved.`);
      }
      await testIntegrationChannel(input);
      return ok(`${label(input.channel)} test delivered.`);
    }
    if (action === "add-threat-feed") {
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
      const count = await testThreatIntelFeed(required(body.feedId, "feedId"), actor.tenantId);
      return ok(`Threat feed tested and loaded ${count.toLocaleString()} indicator${count === 1 ? "" : "s"}.`);
    }
    if (action === "save-soc-setting") {
      const settingKey = required(body.settingKey, "settingKey");
      if (!isRecord(body.values)) throw new Error("values must be an object.");
      await saveSocSetting(actor.tenantId, settingKey, body.values);
      return ok("Setting saved.");
    }
    if (action === "invite-user") {
      await inviteUser(request, body, actor);
      return ok("Invitation created and magic link sent.");
    }
    if (action === "add-user") {
      await addExistingUser(body, actor);
      return ok("User added to the tenant.");
    }
    if (action === "import-sigma") {
      const rule = await importSigmaRule(required(body.sigma, "sigma"));
      return ok(`Imported ${rule.title}.`);
    }
    if (action === "duplicate-rule") {
      const rule = await duplicateSigmaRule(required(body.ruleId, "ruleId"));
      return ok(`Duplicated ${rule.title}.`);
    }
    if (action === "disable-rule") {
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
    return { id: session.user.id, name: session.user.name || session.user.email, tenantId: activeOrganizationId };
  }

  const [membership] = await db.select().from(schema.member).where(eq(schema.member.userId, session.user.id)).limit(1);
  return {
    id: session.user.id,
    name: session.user.name || session.user.email,
    tenantId: membership?.organizationId ?? "local-tenant",
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

function parseRole(value: unknown) {
  const role = typeof value === "string" && validRoles.has(value) ? value : "member";
  return role;
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
