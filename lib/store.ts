import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createHash, randomUUID } from "node:crypto";
import { isIP } from "node:net";
import path from "node:path";
import { and, desc, eq, gt, inArray, isNull, lt, or } from "drizzle-orm";
import { matchRules, normalizeSeverity, topSeverity, triageSummary } from "@/lib/detection";
import { db, schema } from "@/lib/db/client";
import { listSigmaRules } from "@/lib/sigma";
import { createIncidentFromAlert } from "@/lib/soc-workflows";
import { playbooks } from "@/lib/rules";
import type {
  IngestPayload,
  IntegrationDelivery,
  KelpieIntegrationConfig,
  SocAlert,
  SocComment,
  SocEvent,
  SocIncident,
  SocTask,
  SocTimelineItem,
  ThreatIntelFeed,
  ThreatIntelMatch,
} from "@/lib/types";

const runtimeDir = path.join(process.cwd(), "data", "runtime");
const eventsPath = path.join(runtimeDir, "events.json");
const alertsPath = path.join(runtimeDir, "alerts.json");
const savedSearchesPath = path.join(runtimeDir, "saved-searches.json");

export type IntegrationChannelSetting = {
  channel: IntegrationDelivery["channel"];
  enabled: boolean;
  endpoint: string;
  credential: string;
  credentialConfigured: boolean;
};

export type SocSettings = {
  severity: { critical: string; high: string; medium: string; low: string };
  routing: { criticalChannel: string; highChannel: string; defaultAssignee: string };
  suppression: { defaultExpiryHours: number; requireReason: boolean };
  caseNumbering: { prefix: string; nextNumber: number };
  sla: { criticalMinutes: number; highMinutes: number; mediumMinutes: number };
  permissions: { dismissRole: string; suppressRole: string; kelpieRole: string };
  threatIntel: { defaultTtlDays: number };
};

const socSettingsDefaults: SocSettings = {
  severity: { critical: "P1", high: "P2", medium: "P3", low: "P4" },
  routing: { criticalChannel: "", highChannel: "", defaultAssignee: "" },
  suppression: { defaultExpiryHours: 24, requireReason: true },
  caseNumbering: { prefix: "SOC", nextNumber: 1 },
  sla: { criticalMinutes: 30, highMinutes: 120, mediumMinutes: 480 },
  permissions: { dismissRole: "member", suppressRole: "owner", kelpieRole: "owner" },
  threatIntel: { defaultTtlDays: 7 },
};

async function readJson<T>(filePath: string, fallback: T): Promise<T> {
  try {
    const raw = await readFile(filePath, "utf8");
    return JSON.parse(raw) as T;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return fallback;
    throw err;
  }
}

async function writeJson<T>(filePath: string, value: T) {
  await mkdir(runtimeDir, { recursive: true });
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function fromDbEvent(row: typeof schema.socEvent.$inferSelect): SocEvent {
  return {
    id: row.id,
    source: row.source as SocEvent["source"],
    kind: row.kind as SocEvent["kind"],
    title: row.title,
    severity: row.severity,
    status: row.status as SocEvent["status"],
    timestamp: row.timestamp.toISOString(),
    tenantId: row.tenantId ?? undefined,
    agentId: row.agentId ?? undefined,
    hostname: row.hostname ?? undefined,
    os: row.os ?? undefined,
    eventType: row.eventType ?? undefined,
    telemetryId: row.telemetryId ? Number(row.telemetryId) : undefined,
    alertId: row.alertId ? Number(row.alertId) : undefined,
    ruleId: row.ruleId ?? undefined,
    payload: row.payload,
    matchedRules: row.matchedRules,
    mitreTechniques: row.mitreTechniques,
  };
}

function fromDbAlert(row: typeof schema.socAlert.$inferSelect): SocAlert {
  return {
    ...fromDbEvent({
      ...row,
      kind: "alert",
    } as typeof schema.socEvent.$inferSelect),
    kind: "alert",
    confidence: Number(row.confidence),
    aiSummary: row.aiSummary,
    recommendedPlaybook: row.recommendedPlaybook,
    assignee: row.assignee ?? undefined,
  };
}

function fromDbTimeline(row: typeof schema.socTimeline.$inferSelect): SocTimelineItem {
  return {
    id: row.id,
    actor: row.actor,
    action: row.action,
    at: row.createdAt.toISOString(),
    detail: row.detail,
  };
}

function fromDbTask(row: typeof schema.socTask.$inferSelect): SocTask {
  return {
    id: row.id,
    title: row.title,
    owner: row.owner,
    status: row.status as SocTask["status"],
    dueAt: row.dueAt?.toISOString() ?? new Date().toISOString(),
    requiredEvidence: row.requiredEvidence,
    responseAction: row.responseAction ?? undefined,
  };
}

function fromDbComment(row: typeof schema.socComment.$inferSelect): SocComment {
  return {
    id: row.id,
    author: row.author,
    body: row.body,
    createdAt: row.createdAt.toISOString(),
  };
}

function fromDbDelivery(row: typeof schema.socDeliveryLog.$inferSelect): IntegrationDelivery {
  return {
    id: row.id,
    channel: row.channel as IntegrationDelivery["channel"],
    target: row.target,
    state: row.state as IntegrationDelivery["state"],
    attempts: row.attempts,
    lastAttemptAt: row.lastAttemptAt.toISOString(),
    error: row.error ?? undefined,
    externalRef: row.externalRef ?? undefined,
  };
}

function fromDbThreatIntelFeed(row: typeof schema.socThreatIntelFeed.$inferSelect): ThreatIntelFeed {
  return {
    id: row.id,
    name: row.name,
    type: row.type as ThreatIntelFeed["type"],
    url: row.url,
    enabled: row.enabled,
    lastRunAt: row.lastRunAt?.toISOString(),
    status: row.status as ThreatIntelFeed["status"],
    indicatorCount: row.indicatorCount,
    lastError: row.lastError ?? undefined,
  };
}

function fromDbThreatIntelIndicator(row: typeof schema.socThreatIntelIndicator.$inferSelect): ThreatIntelMatch {
  return {
    id: row.id,
    type: row.type as ThreatIntelMatch["type"],
    value: row.value,
    sourceFeed: row.sourceFeed,
    confidence: row.confidence,
    tags: row.tags,
    firstSeen: row.firstSeen.toISOString(),
    lastSeen: row.lastSeen.toISOString(),
    expiry: row.expiresAt?.toISOString(),
  };
}

function id(prefix: string, sourceId?: unknown) {
  const suffix = sourceId ? String(sourceId) : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `${prefix}-${suffix}`;
}

function extractTimestamp(record: Record<string, unknown>, fallback?: string) {
  return String(
    record.created_at
      ?? record.occurred_at
      ?? record.received_at
      ?? fallback
      ?? new Date().toISOString(),
  );
}

function cleanText(value: unknown, fallback: string) {
  const text = typeof value === "string" ? value.trim() : "";
  return text.length > 0 ? text : fallback;
}

export async function listEvents() {
  try {
    const rows = await db.select().from(schema.socEvent).orderBy(desc(schema.socEvent.timestamp)).limit(1000);
    return rows.map(fromDbEvent);
  } catch {
    const events = await readJson<SocEvent[]>(eventsPath, []);
    return events.sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp));
  }
}

export async function listAlerts() {
  try {
    const rows = await db.select().from(schema.socAlert).orderBy(desc(schema.socAlert.timestamp)).limit(500);
    return rows.map(fromDbAlert);
  } catch {
    const alerts = await readJson<SocAlert[]>(alertsPath, []);
    return alerts.sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp));
  }
}

export async function listIncidents() {
  try {
    const rows = await db.select().from(schema.socIncident).orderBy(desc(schema.socIncident.updatedAt)).limit(500);
    if (!rows.length) return [];

    const incidentIds = rows.map((row) => row.id);
    const [links, timelines, tasks, comments] = await Promise.all([
      db.select().from(schema.socIncidentAlert).where(inArray(schema.socIncidentAlert.incidentId, incidentIds)),
      db.select().from(schema.socTimeline).where(inArray(schema.socTimeline.incidentId, incidentIds)).orderBy(desc(schema.socTimeline.createdAt)),
      db.select().from(schema.socTask).where(inArray(schema.socTask.incidentId, incidentIds)),
      db.select().from(schema.socComment).where(inArray(schema.socComment.incidentId, incidentIds)).orderBy(desc(schema.socComment.createdAt)),
    ]);

    return rows.map<SocIncident>((row) => ({
      id: row.id,
      tenantId: row.tenantId,
      number: row.number,
      title: row.title,
      severity: row.severity,
      priority: row.priority as SocIncident["priority"],
      status: row.status,
      assignee: row.assignee ?? undefined,
      tags: row.tags,
      tlp: row.tlp as SocIncident["tlp"],
      pap: row.pap as SocIncident["pap"],
      classification: row.classification as SocIncident["classification"],
      mitreTechniques: row.mitreTechniques,
      observables: row.observables as SocIncident["observables"],
      linkedHosts: row.linkedHosts,
      linkedAlertIds: links.filter((link) => link.incidentId === row.id).map((link) => link.alertId),
      kelpieCaseId: row.kelpieCaseId ?? undefined,
      kelpieUrl: row.kelpieUrl ?? undefined,
      kelpieSyncStatus: row.kelpieSyncStatus,
      createdAt: row.createdAt.toISOString(),
      updatedAt: row.updatedAt.toISOString(),
      timeline: timelines.filter((item) => item.incidentId === row.id).map(fromDbTimeline).reverse(),
      tasks: tasks.filter((task) => task.incidentId === row.id).map(fromDbTask),
      comments: comments.filter((comment) => comment.incidentId === row.id).map(fromDbComment),
    }));
  } catch {
    return [];
  }
}

export async function listDeliveryLog() {
  try {
    const rows = await db.select().from(schema.socDeliveryLog).orderBy(desc(schema.socDeliveryLog.lastAttemptAt)).limit(100);
    return rows.map(fromDbDelivery);
  } catch {
    return [];
  }
}

export async function listThreatIntelFeeds(tenantId: string) {
  try {
    const rows = await db.select().from(schema.socThreatIntelFeed).where(eq(schema.socThreatIntelFeed.tenantId, tenantId)).orderBy(desc(schema.socThreatIntelFeed.lastRunAt));
    return rows.map(fromDbThreatIntelFeed);
  } catch {
    return [];
  }
}

export async function listThreatIntelMatches(tenantId: string) {
  try {
    const rows = await db
      .select()
      .from(schema.socThreatIntelIndicator)
      .where(and(
        eq(schema.socThreatIntelIndicator.tenantId, tenantId),
        or(isNull(schema.socThreatIntelIndicator.expiresAt), gt(schema.socThreatIntelIndicator.expiresAt, new Date())),
      ))
      .orderBy(desc(schema.socThreatIntelIndicator.lastSeen))
      .limit(1000);
    return rows.map(fromDbThreatIntelIndicator);
  } catch {
    return [];
  }
}

export async function deleteExpiredThreatIntelIndicators(tenantId?: string, now = new Date()) {
  const expiredFilter = tenantId
    ? and(eq(schema.socThreatIntelIndicator.tenantId, tenantId), lt(schema.socThreatIntelIndicator.expiresAt, now))
    : lt(schema.socThreatIntelIndicator.expiresAt, now);
  const deleted = await db.delete(schema.socThreatIntelIndicator).where(expiredFilter).returning({ id: schema.socThreatIntelIndicator.id });
  return deleted.length;
}

export async function upsertThreatIntelFeed(input: {
  tenantId: string;
  name: string;
  type: ThreatIntelFeed["type"];
  url: string;
  enabled: boolean;
}) {
  const slug = input.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || randomUUID();
  const id = `feed-${input.tenantId}-${slug}`;
  await db.insert(schema.socThreatIntelFeed).values({
    id,
    tenantId: input.tenantId,
    name: input.name,
    type: input.type,
    url: input.url,
    enabled: input.enabled,
    status: "paused",
    indicatorCount: 0,
  }).onConflictDoUpdate({
    target: schema.socThreatIntelFeed.id,
    set: {
      name: input.name,
      type: input.type,
      url: input.url,
      enabled: input.enabled,
    },
  });
}

export async function testThreatIntelFeed(feedId: string, tenantId: string) {
  const [feed] = await db.select().from(schema.socThreatIntelFeed).where(eq(schema.socThreatIntelFeed.id, feedId)).limit(1);
  if (!feed || feed.tenantId !== tenantId) throw new Error("Threat intel feed not found.");
  const now = new Date();
  try {
    await deleteExpiredThreatIntelIndicators(tenantId, now);
    const ttlDays = await getThreatIntelTtlDays(tenantId);
    const defaultExpiresAt = addDays(now, ttlDays);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    const res = await fetch(feed.url, { method: "GET", signal: controller.signal });
    clearTimeout(timer);
    const body = res.ok ? await res.text().catch(() => "") : "";
    const indicators = res.ok ? parseThreatIntelIndicators(feed, body, now, defaultExpiresAt) : [];
    if (res.ok) {
      await replaceThreatIntelIndicators(feed, indicators);
    }
    await db.update(schema.socThreatIntelFeed).set({
      status: res.ok ? "healthy" : "failed",
      lastRunAt: now,
      lastError: res.ok ? null : `HTTP ${res.status}`,
      indicatorCount: res.ok ? indicators.length : feed.indicatorCount,
    }).where(eq(schema.socThreatIntelFeed.id, feedId));
    if (!res.ok) throw new Error(`Feed returned HTTP ${res.status}.`);
    return indicators.length;
  } catch (error) {
    const detail = error instanceof Error ? error.message : "Feed test failed.";
    await db.update(schema.socThreatIntelFeed).set({ status: "failed", lastRunAt: now, lastError: detail }).where(eq(schema.socThreatIntelFeed.id, feedId));
    throw new Error(detail);
  }
}

export async function getKelpieIntegration(tenantId: string): Promise<KelpieIntegrationConfig> {
  try {
    const [row] = await db.select().from(schema.socKelpieIntegration).where(eq(schema.socKelpieIntegration.tenantId, tenantId)).limit(1);
    if (!row) return { enabled: false, baseUrl: "", tokenConfigured: false, dedupeBy: "externalRef", syncFields: [] };
    return {
      enabled: row.enabled,
      baseUrl: row.baseUrl,
      tokenConfigured: Boolean(row.tokenReference),
      dedupeBy: row.dedupeBy as KelpieIntegrationConfig["dedupeBy"],
      syncFields: row.syncFields,
    };
  } catch {
    return { enabled: false, baseUrl: "", tokenConfigured: false, dedupeBy: "externalRef", syncFields: [] };
  }
}

export async function saveKelpieIntegration(input: {
  tenantId: string;
  baseUrl: string;
  tokenReference: string;
  enabled: boolean;
  syncFields: string[];
}) {
  const [existing] = await db.select().from(schema.socKelpieIntegration).where(eq(schema.socKelpieIntegration.id, `kelpie-${input.tenantId}`)).limit(1);
  const tokenReference = input.tokenReference.trim() || existing?.tokenReference || "";
  await db.insert(schema.socKelpieIntegration).values({
    id: `kelpie-${input.tenantId}`,
    tenantId: input.tenantId,
    baseUrl: input.baseUrl,
    tokenReference,
    enabled: input.enabled,
    dedupeBy: "externalRef",
    syncFields: input.syncFields,
    updatedAt: new Date(),
  }).onConflictDoUpdate({
    target: schema.socKelpieIntegration.id,
    set: {
      baseUrl: input.baseUrl,
      tokenReference,
      enabled: input.enabled,
      syncFields: input.syncFields,
      updatedAt: new Date(),
    },
  });
}

export async function getKelpieToken(tenantId: string) {
  const [row] = await db.select().from(schema.socKelpieIntegration).where(eq(schema.socKelpieIntegration.tenantId, tenantId)).limit(1);
  return row?.tokenReference ?? "";
}

export async function listIntegrationChannels(tenantId: string): Promise<IntegrationChannelSetting[]> {
  const channels: IntegrationDelivery["channel"][] = ["email", "slack", "webhook", "sentinel", "wazuh"];
  const rows = await listSettingsByPrefix(tenantId, "integration.");
  return channels.map((channel) => {
    const value = rows[`integration.${channel}`] ?? {};
    const credential = typeof value.credential === "string" ? value.credential : "";
    return {
      channel,
      enabled: value.enabled === true,
      endpoint: typeof value.endpoint === "string" ? value.endpoint : "",
      credential: "",
      credentialConfigured: credential.length > 0,
    };
  });
}

export async function saveIntegrationChannel(input: IntegrationChannelSetting & { tenantId: string }) {
  const existing = (await listSettingsByPrefix(input.tenantId, "integration."))[`integration.${input.channel}`] ?? {};
  const currentCredential = typeof existing.credential === "string" ? existing.credential : "";
  await saveSetting(input.tenantId, `integration.${input.channel}`, {
    enabled: input.enabled,
    endpoint: input.endpoint,
    credential: input.credential.trim() || currentCredential,
  });
}

export async function testIntegrationChannel(input: IntegrationChannelSetting & { tenantId: string }) {
  if (!input.endpoint.trim()) throw new Error("Endpoint is required before testing.");
  const existing = (await listSettingsByPrefix(input.tenantId, "integration."))[`integration.${input.channel}`] ?? {};
  const currentCredential = typeof existing.credential === "string" ? existing.credential : "";
  const credential = input.credential.trim() || currentCredential;
  const delivery: IntegrationDelivery = {
    id: `delivery-${randomUUID()}`,
    channel: input.channel,
    target: input.endpoint,
    state: "queued",
    attempts: 1,
    lastAttemptAt: new Date().toISOString(),
    externalRef: `test-${input.channel}`,
  };
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    const res = await fetch(input.endpoint, {
      method: input.channel === "email" ? "GET" : "POST",
      headers: {
        "content-type": "application/json",
        ...(credential ? { authorization: `Bearer ${credential}` } : {}),
      },
      body: input.channel === "email" ? undefined : JSON.stringify({ source: "Tawny-SOC", type: "integration_test", channel: input.channel }),
      signal: controller.signal,
    });
    clearTimeout(timer);
    await recordDelivery({ ...delivery, state: res.ok ? "delivered" : "failed", error: res.ok ? undefined : `HTTP ${res.status}` }, input.tenantId);
    if (!res.ok) throw new Error(`Endpoint returned HTTP ${res.status}.`);
  } catch (error) {
    const detail = error instanceof Error ? error.message : "Integration test failed.";
    await recordDelivery({ ...delivery, state: "failed", error: detail }, input.tenantId);
    throw new Error(detail);
  }
}

export async function listSocSettings(tenantId: string): Promise<SocSettings> {
  const rows = await listSettingsByPrefix(tenantId, "soc.");
  const setting = <K extends keyof SocSettings>(key: K): SocSettings[K] => ({
    ...socSettingsDefaults[key],
    ...(rows[`soc.${key}`] ?? {}),
  }) as SocSettings[K];
  return {
    severity: setting("severity"),
    routing: setting("routing"),
    suppression: setting("suppression"),
    caseNumbering: setting("caseNumbering"),
    sla: setting("sla"),
    permissions: setting("permissions"),
    threatIntel: setting("threatIntel"),
  };
}

export async function saveSocSetting(tenantId: string, key: string, value: Record<string, unknown>) {
  await saveSetting(tenantId, `soc.${key}`, value);
}

type ParsedThreatIndicator = {
  confidence: number;
  expiresAt?: Date | null;
  firstSeen: Date;
  lastSeen: Date;
  tags: string[];
  type: ThreatIntelMatch["type"];
  value: string;
};

async function getThreatIntelTtlDays(tenantId: string) {
  const settings = await listSettingsByPrefix(tenantId, "soc.");
  const value = settings["soc.threatIntel"]?.defaultTtlDays;
  return normalizeTtlDays(value);
}

function normalizeTtlDays(value: unknown) {
  const days = Number(value);
  if (!Number.isFinite(days)) return socSettingsDefaults.threatIntel.defaultTtlDays;
  return Math.min(365, Math.max(1, Math.round(days)));
}

function addDays(date: Date, days: number) {
  return new Date(date.getTime() + days * 24 * 60 * 60_000);
}

function parseThreatIntelIndicators(feed: typeof schema.socThreatIntelFeed.$inferSelect, body: string, now: Date, defaultExpiresAt: Date) {
  const trimmed = body.trim();
  if (!trimmed) return [];

  const parsed = parseJson(trimmed);
  const indicators = parsed === undefined
    ? parseTextThreatIndicators(body, feed.name, now)
    : parseJsonThreatIndicators(parsed, feed.name, now);

  const seen = new Set<string>();
  return indicators.filter((indicator) => {
    const key = `${indicator.type}:${indicator.value.toLowerCase()}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).map((indicator) => ({
    ...indicator,
    expiresAt: indicator.expiresAt ?? defaultExpiresAt,
  }));
}

async function replaceThreatIntelIndicators(feed: typeof schema.socThreatIntelFeed.$inferSelect, indicators: ParsedThreatIndicator[]) {
  await db.delete(schema.socThreatIntelIndicator).where(eq(schema.socThreatIntelIndicator.feedId, feed.id));
  const values = indicators.map((indicator) => ({
    id: threatIndicatorId(feed.tenantId, feed.id, indicator.type, indicator.value),
    tenantId: feed.tenantId,
    feedId: feed.id,
    type: indicator.type,
    value: indicator.value,
    sourceFeed: feed.name,
    confidence: indicator.confidence,
    tags: indicator.tags,
    firstSeen: indicator.firstSeen,
    lastSeen: indicator.lastSeen,
    expiresAt: indicator.expiresAt ?? null,
  }));

  for (let index = 0; index < values.length; index += 500) {
    await db.insert(schema.socThreatIntelIndicator).values(values.slice(index, index + 500));
  }
}

function parseJsonThreatIndicators(parsed: unknown, sourceName: string, now: Date): ParsedThreatIndicator[] {
  if (isRecord(parsed) && Array.isArray(parsed.vulnerabilities)) {
    return parsed.vulnerabilities.flatMap((entry) => parseCisaKevIndicator(entry, sourceName, now));
  }

  if (Array.isArray(parsed)) {
    return parsed.flatMap((entry) => parseGenericJsonIndicator(entry, sourceName, now));
  }

  return parseGenericJsonIndicator(parsed, sourceName, now);
}

function parseCisaKevIndicator(entry: unknown, sourceName: string, now: Date): ParsedThreatIndicator[] {
  if (!isRecord(entry)) return [];
  const cve = String(entry.cveID ?? entry.cveId ?? entry.cve ?? "").trim().toUpperCase();
  if (!classifyIndicator(cve, sourceName)) return [];
  const vendor = String(entry.vendorProject ?? entry.vendor ?? "").trim();
  const ransomwareUse = String(entry.knownRansomwareCampaignUse ?? "").toLowerCase() === "known";
  return [{
    confidence: ransomwareUse ? 95 : 90,
    firstSeen: parseDate(entry.dateAdded) ?? now,
    lastSeen: now,
    tags: compactStrings(["cisa-kev", "known-exploited", ransomwareUse ? "ransomware-observed" : "", vendor]),
    type: "cve",
    value: cve,
  }];
}

function parseGenericJsonIndicator(entry: unknown, sourceName: string, now: Date): ParsedThreatIndicator[] {
  const values = collectScalarStrings(entry);
  return values.flatMap((value) => {
    const classified = classifyIndicator(value, sourceName);
    if (!classified) return [];
    return [{
      confidence: defaultIndicatorConfidence(classified.type, sourceName),
      firstSeen: now,
      lastSeen: now,
      tags: defaultIndicatorTags(sourceName, classified.type),
      type: classified.type,
      value: classified.value,
    }];
  });
}

function parseTextThreatIndicators(body: string, sourceName: string, now: Date): ParsedThreatIndicator[] {
  return body.split(/\r?\n/).flatMap((rawLine) => {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith(";") || line.startsWith("//")) return [];
    const withoutComment = line.split(/\s[;#]/)[0]?.trim() ?? line;
    const pieces = withoutComment.includes(",")
      ? withoutComment.split(",")
      : withoutComment.split(/\s+/);
    const classified = pieces
      .map((piece) => classifyIndicator(piece, sourceName))
      .find((item) => item !== undefined);
    if (!classified) return [];
    return [{
      confidence: defaultIndicatorConfidence(classified.type, sourceName),
      firstSeen: now,
      lastSeen: now,
      tags: defaultIndicatorTags(sourceName, classified.type),
      type: classified.type,
      value: classified.value,
    }];
  });
}

function classifyIndicator(rawValue: unknown, sourceName: string): Pick<ParsedThreatIndicator, "type" | "value"> | undefined {
  const value = normalizeIndicatorValue(rawValue);
  if (!value) return undefined;
  if (/^CVE-\d{4}-\d{4,}$/i.test(value)) return { type: "cve", value: value.toUpperCase() };
  if (/^https?:\/\//i.test(value)) return { type: "url", value };
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return { type: "email", value: value.toLowerCase() };

  const cidrMatch = value.match(/^(.+)\/(\d{1,3})$/);
  if (cidrMatch && isIP(cidrMatch[1])) return { type: "cidr", value };
  if (isIP(value)) return { type: "ip", value };
  if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(value)) return { type: "hash", value: value.toLowerCase() };
  if (looksLikeDomain(value) && !sourceName.toLowerCase().includes("cisa")) return { type: "domain", value: value.toLowerCase() };
  return undefined;
}

function normalizeIndicatorValue(rawValue: unknown) {
  return String(rawValue ?? "")
    .trim()
    .replace(/^["'`]+|["'`,]+$/g, "")
    .replace(/^hxxps?:\/\//i, (match) => match.toLowerCase().startsWith("hxxps") ? "https://" : "http://")
    .replace(/\[\.\]/g, ".")
    .replace(/\(\.\)/g, ".")
    .replace(/\s+/g, "");
}

function looksLikeDomain(value: string) {
  if (value.length > 253 || value.includes("/") || value.includes(":")) return false;
  return /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+\.?$/i.test(value);
}

function parseJson(value: string) {
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return undefined;
  }
}

function parseDate(value: unknown) {
  const date = typeof value === "string" ? new Date(value) : undefined;
  return date && Number.isFinite(date.getTime()) ? date : undefined;
}

function collectScalarStrings(value: unknown, output: string[] = [], depth = 0) {
  if (depth > 5 || value === null || value === undefined) return output;
  if (typeof value === "string" || typeof value === "number") {
    output.push(String(value));
    return output;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectScalarStrings(item, output, depth + 1);
    return output;
  }
  if (isRecord(value)) {
    for (const child of Object.values(value)) collectScalarStrings(child, output, depth + 1);
  }
  return output;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function defaultIndicatorConfidence(type: ThreatIntelMatch["type"], sourceName: string) {
  const source = sourceName.toLowerCase();
  if (source.includes("feodo")) return 95;
  if (source.includes("spamhaus")) return 92;
  if (source.includes("emerging threats")) return 88;
  if (type === "cve") return 90;
  return 80;
}

function defaultIndicatorTags(sourceName: string, type: ThreatIntelMatch["type"]) {
  const source = sourceName.toLowerCase();
  return compactStrings([
    source.includes("feodo") ? "botnet-c2" : "",
    source.includes("spamhaus") ? "rogue-network" : "",
    source.includes("blocklist.de") ? "recent-attacker" : "",
    source.includes("emerging threats") ? "compromised-host" : "",
    type,
    "osint",
  ]);
}

function compactStrings(values: string[]) {
  return values.map((value) => value.trim()).filter(Boolean);
}

function threatIndicatorId(tenantId: string, feedId: string, type: string, value: string) {
  const digest = createHash("sha256").update(`${tenantId}:${feedId}:${type}:${value.toLowerCase()}`).digest("hex").slice(0, 32);
  return `ioc-${digest}`;
}

async function listSettingsByPrefix(tenantId: string, prefix: string): Promise<Record<string, Record<string, unknown>>> {
  const rows = await db.select().from(schema.socSetting).where(eq(schema.socSetting.tenantId, tenantId));
  return Object.fromEntries(rows.filter((row) => row.key.startsWith(prefix)).map((row) => [row.key, row.value]));
}

async function saveSetting(tenantId: string, key: string, value: Record<string, unknown>) {
  await db.insert(schema.socSetting).values({
    id: `${tenantId}-${key}`,
    tenantId,
    key,
    value,
    updatedAt: new Date(),
  }).onConflictDoUpdate({
    target: schema.socSetting.id,
    set: { value, updatedAt: new Date() },
  });
}

export async function listSavedSearches() {
  return readJson<Array<{ name: string; query: string }>>(savedSearchesPath, []);
}

export async function saveSearch(query: string) {
  const savedSearches = await listSavedSearches();
  const name = query.length > 48 ? `${query.slice(0, 45)}...` : query;
  const next = [{ name, query }, ...savedSearches.filter((item) => item.query !== query)].slice(0, 20);
  await writeJson(savedSearchesPath, next);
  return next[0];
}

export async function clearRuntimeStore() {
  await writeJson(eventsPath, []);
  await writeJson(alertsPath, []);
}

export async function ingestTawny(payload: IngestPayload) {
  const existingEvents = await readJson<SocEvent[]>(eventsPath, []);
  const existingAlerts = await readJson<SocAlert[]>(alertsPath, []);
  const now = payload.sent_at ?? new Date().toISOString();
  const agent = payload.agent ?? {};
  const telemetryById = payload.telemetry_events ?? {};
  const rules = await listSigmaRules();

  const nextEvents: SocEvent[] = [];
  const nextAlerts: SocAlert[] = [];

  for (const rawAlert of payload.alerts ?? []) {
    const telemetryId = Number(rawAlert.telemetry_event_id ?? rawAlert.telemetryEventId ?? 0);
    const telemetry = telemetryById[String(telemetryId)] ?? {};
    const mergedPayload = { alert: rawAlert, telemetry };
    const explicitSeverity = normalizeSeverity(rawAlert.alert_severity ?? rawAlert.severity);
    const matches = matchRules(
      mergedPayload,
      String(telemetry.event_type ?? telemetry.eventType ?? ""),
      String(rawAlert.rule_id ?? rawAlert.alert_rule_id ?? ""),
      rules,
    );
    const severity = matches.length ? topSeverity([explicitSeverity, ...matches.map((rule) => rule.severity)]) : explicitSeverity;
    const title = cleanText(rawAlert.alert_title ?? rawAlert.title, "Tawny alert");
    const triage = triageSummary({
      title,
      hostname: agent.hostname,
      severity,
      rules: matches,
      eventType: String(telemetry.event_type ?? telemetry.eventType ?? ""),
    });

    nextAlerts.push({
      id: id("alert", rawAlert.alert_id ?? rawAlert.id),
      source: "tawny",
      kind: "alert",
      title,
      severity,
      status: "open",
      timestamp: extractTimestamp(rawAlert, now),
      tenantId: cleanText(agent.tenant_id ?? payload.tenant_id, ""),
      agentId: cleanText(agent.id, ""),
      hostname: cleanText(agent.hostname, "unknown-host"),
      os: cleanText(agent.operating_system, ""),
      eventType: cleanText(telemetry.event_type ?? telemetry.eventType, "unknown"),
      telemetryId: Number.isFinite(telemetryId) ? telemetryId : undefined,
      alertId: Number(rawAlert.alert_id ?? rawAlert.id ?? 0) || undefined,
      ruleId: cleanText(rawAlert.rule_id ?? rawAlert.alert_rule_id, ""),
      payload: mergedPayload,
      matchedRules: matches.map((rule) => rule.id),
      mitreTechniques: triage.techniques,
      confidence: triage.confidence,
      aiSummary: triage.aiSummary,
      recommendedPlaybook: triage.recommendedPlaybook,
    });
  }

  for (const rawEvent of payload.events ?? []) {
    const eventType = cleanText(rawEvent.event_type ?? rawEvent.eventType, "telemetry");
    const matches = matchRules(rawEvent, eventType, undefined, rules);
    const severity = matches.length ? topSeverity(matches.map((rule) => rule.severity)) : "low";
    nextEvents.push({
      id: id("event", rawEvent.telemetry_id ?? rawEvent.id),
      source: "tawny",
      kind: "telemetry",
      title: matches[0]?.title ?? `Tawny ${eventType}`,
      severity,
      status: "open",
      timestamp: extractTimestamp(rawEvent, now),
      tenantId: cleanText(agent.tenant_id ?? payload.tenant_id, ""),
      agentId: cleanText(agent.id, ""),
      hostname: cleanText(agent.hostname, "unknown-host"),
      os: cleanText(agent.operating_system, ""),
      eventType,
      telemetryId: Number(rawEvent.telemetry_id ?? rawEvent.id ?? 0) || undefined,
      payload: rawEvent,
      matchedRules: matches.map((rule) => rule.id),
      mitreTechniques: [...new Set(matches.flatMap((rule) => rule.mitreTechniques))],
    });
  }

  const mergedEvents = [...nextEvents, ...existingEvents].slice(0, 1000);
  const mergedAlerts = [...nextAlerts, ...existingAlerts].slice(0, 500);
  try {
    if (nextEvents.length > 0) {
      await db.insert(schema.socEvent).values(nextEvents.map((event) => ({
        ...event,
        timestamp: new Date(event.timestamp),
        telemetryId: event.telemetryId?.toString(),
        alertId: event.alertId?.toString(),
      }))).onConflictDoNothing();
    }
    if (nextAlerts.length > 0) {
      await db.insert(schema.socAlert).values(nextAlerts.map((alert) => ({
        ...alert,
        timestamp: new Date(alert.timestamp),
        telemetryId: alert.telemetryId?.toString(),
        alertId: alert.alertId?.toString(),
        confidence: alert.confidence.toString(),
      }))).onConflictDoNothing();
    }
  } catch {
    await writeJson(eventsPath, mergedEvents);
    await writeJson(alertsPath, mergedAlerts);
  }

  return {
    accepted: nextEvents.length + nextAlerts.length,
    alerts: nextAlerts.length,
    events: nextEvents.length,
  };
}

export type SocActor = {
  id: string;
  name: string;
  tenantId: string;
};

export async function assignAlert(alertId: string, actor: SocActor) {
  await db.update(schema.socAlert)
    .set({ assignee: actor.name, status: "triaging" })
    .where(eq(schema.socAlert.id, alertId));
  await recordTimeline({
    tenantId: actor.tenantId,
    alertId,
    actor: actor.name,
    action: "assigned_alert",
    detail: `Assigned alert to ${actor.name}.`,
  });
}

export async function updateAlertStatus(alertId: string, status: SocAlert["status"], actor: SocActor, detail?: string) {
  await db.update(schema.socAlert)
    .set({ status })
    .where(eq(schema.socAlert.id, alertId));
  await recordTimeline({
    tenantId: actor.tenantId,
    alertId,
    actor: actor.name,
    action: `alert_${status}`,
    detail: detail ?? `Changed alert status to ${status}.`,
  });
}

export async function createCaseForAlert(alertId: string, actor: SocActor) {
  const alert = (await listAlerts()).find((item) => item.id === alertId);
  if (!alert) throw new Error("Alert not found.");

  const existing = await db.select().from(schema.socIncident).limit(1000);
  const incident = createIncidentFromAlert({ ...alert, tenantId: alert.tenantId ?? actor.tenantId }, actor, existing.length);

  await db.insert(schema.socIncident).values({
    id: incident.id,
    tenantId: incident.tenantId,
    number: incident.number,
    title: incident.title,
    severity: incident.severity,
    priority: incident.priority,
    status: incident.status,
    assignee: incident.assignee,
    tags: incident.tags,
    tlp: incident.tlp,
    pap: incident.pap,
    classification: incident.classification,
    mitreTechniques: incident.mitreTechniques,
    observables: incident.observables,
    linkedHosts: incident.linkedHosts,
    kelpieSyncStatus: incident.kelpieSyncStatus,
    createdAt: new Date(incident.createdAt),
    updatedAt: new Date(incident.updatedAt),
  }).onConflictDoNothing();

  await db.insert(schema.socIncidentAlert).values({
    id: `incident-alert-${randomUUID()}`,
    tenantId: incident.tenantId,
    incidentId: incident.id,
    alertId,
    addedBy: actor.name,
    addedAt: new Date(),
  }).onConflictDoNothing();

  for (const item of incident.timeline) {
    await recordTimeline({
      tenantId: incident.tenantId,
      incidentId: incident.id,
      actor: item.actor,
      action: item.action,
      detail: item.detail,
      createdAt: item.at,
    });
  }

  await assignAlert(alertId, actor);
  return incident;
}

export async function assignIncident(incidentId: string, actor: SocActor) {
  await db.update(schema.socIncident)
    .set({ assignee: actor.name, updatedAt: new Date() })
    .where(eq(schema.socIncident.id, incidentId));
  await recordTimeline({
    tenantId: actor.tenantId,
    incidentId,
    actor: actor.name,
    action: "assigned_case",
    detail: `Assigned case to ${actor.name}.`,
  });
}

export async function updateIncidentStatus(incidentId: string, status: SocIncident["status"], actor: SocActor) {
  await db.update(schema.socIncident)
    .set({ status, updatedAt: new Date() })
    .where(eq(schema.socIncident.id, incidentId));
  await recordTimeline({
    tenantId: actor.tenantId,
    incidentId,
    actor: actor.name,
    action: `case_${status}`,
    detail: `Changed case status to ${status}.`,
  });
}

export async function addIncidentTask(incidentId: string, actor: SocActor, title = "Review new evidence") {
  await db.insert(schema.socTask).values({
    id: `task-${randomUUID()}`,
    tenantId: actor.tenantId,
    incidentId,
    title,
    owner: actor.name,
    status: "todo",
    dueAt: new Date(Date.now() + 60 * 60_000),
    requiredEvidence: ["Document analyst finding", "Attach supporting telemetry"],
  });
  await recordTimeline({
    tenantId: actor.tenantId,
    incidentId,
    actor: actor.name,
    action: "added_task",
    detail: `Added task: ${title}.`,
  });
}

export async function runPlaybookForIncident(incidentId: string, playbookId: string | undefined, actor: SocActor) {
  const playbook = playbooks.find((item) => item.id === playbookId) ?? playbooks[0];
  if (!playbook) throw new Error("No playbook is configured.");
  const dueBase = Date.now() + 45 * 60_000;
  await db.insert(schema.socTask).values(playbook.phases.map((phase, index) => ({
    id: `task-${randomUUID()}`,
    tenantId: actor.tenantId,
    incidentId,
    title: phase.name,
    owner: phase.owner,
    status: index === 0 ? "doing" : "todo",
    dueAt: new Date(dueBase + index * 45 * 60_000),
    requiredEvidence: phase.actions.slice(0, 2),
    responseAction: phase.actions.find((action) => action.toLowerCase().includes("isolation")),
  })));
  await recordTimeline({
    tenantId: actor.tenantId,
    incidentId,
    actor: actor.name,
    action: "ran_playbook",
    detail: `Created ${playbook.phases.length} tasks from ${playbook.name}.`,
  });
}

export async function markIncidentKelpieStatus(incidentId: string, actor: SocActor, status: SocIncident["kelpieSyncStatus"], detail: string, kelpieCaseId?: string, kelpieUrl?: string) {
  await db.update(schema.socIncident)
    .set({ kelpieSyncStatus: status, kelpieCaseId, kelpieUrl, updatedAt: new Date() })
    .where(eq(schema.socIncident.id, incidentId));
  await recordTimeline({
    tenantId: actor.tenantId,
    incidentId,
    actor: "Kelpie sync",
    action: `kelpie_${status}`,
    detail,
  });
}

export async function recordDelivery(delivery: IntegrationDelivery, tenantId: string) {
  await db.insert(schema.socDeliveryLog).values({
    id: delivery.id,
    tenantId,
    channel: delivery.channel,
    target: delivery.target,
    state: delivery.state,
    attempts: delivery.attempts,
    lastAttemptAt: new Date(delivery.lastAttemptAt),
    error: delivery.error,
    externalRef: delivery.externalRef,
  });
}

export async function recordTimeline(input: {
  tenantId: string;
  actor: string;
  action: string;
  detail: string;
  alertId?: string;
  incidentId?: string;
  createdAt?: string;
}) {
  await db.insert(schema.socTimeline).values({
    id: `timeline-${randomUUID()}`,
    tenantId: input.tenantId,
    incidentId: input.incidentId,
    alertId: input.alertId,
    actor: input.actor,
    action: input.action,
    detail: input.detail,
    createdAt: input.createdAt ? new Date(input.createdAt) : new Date(),
  });
}

export async function listAlertTimeline(alertId: string, tenantId: string) {
  try {
    const rows = await db.select().from(schema.socTimeline)
      .where(and(eq(schema.socTimeline.alertId, alertId), eq(schema.socTimeline.tenantId, tenantId)))
      .orderBy(desc(schema.socTimeline.createdAt));
    return rows.map(fromDbTimeline).reverse();
  } catch {
    return [];
  }
}
