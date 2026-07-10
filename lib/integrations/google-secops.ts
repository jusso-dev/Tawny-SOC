import { createSign } from "node:crypto";
import type { GoogleSecOpsIngestionMode, SocEvent } from "@/lib/types";

export const GOOGLE_SECOPS_DEFAULT_ENDPOINT = "https://malachiteingestion-pa.googleapis.com";
export const GOOGLE_SECOPS_INGESTION_SCOPE = "https://www.googleapis.com/auth/malachite-ingestion";
const MAX_BATCH_BYTES = 1_000_000;

export type GoogleSecOpsConfig = {
  endpoint: string;
  customerId: string;
  namespace: string;
  logType: string;
  ingestionMode: GoogleSecOpsIngestionMode;
  credential: string;
};

export type GoogleSecOpsSendResult = {
  batches: number;
  entries: number;
  endpoint: string;
};

type Fetch = typeof fetch;
type GoogleServiceAccount = {
  client_email: string;
  private_key: string;
  token_uri?: string;
};

export async function sendGoogleSecOpsLogs(
  config: GoogleSecOpsConfig,
  records: Array<SocEvent | Record<string, unknown>>,
  fetchImpl: Fetch = fetch,
): Promise<GoogleSecOpsSendResult> {
  validateConfig(config);
  if (records.length === 0) return { batches: 0, entries: 0, endpoint: ingestionEndpoint(config) };

  const accessToken = await resolveAccessToken(config.credential, fetchImpl);
  const endpoint = ingestionEndpoint(config);
  const entries = config.ingestionMode === "udm"
    ? records.map(toGoogleSecOpsUdmEvent)
    : records.map(toGoogleSecOpsLogEntry);
  const batches = splitIntoBatches(config, entries);

  for (const batch of batches) {
    const response = await fetchImpl(endpoint, {
      method: "POST",
      headers: {
        authorization: `Bearer ${accessToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(requestBody(config, batch)),
      signal: AbortSignal.timeout(90_000),
    });
    if (!response.ok) {
      const detail = (await response.text()).trim();
      throw new Error(`Google SecOps returned HTTP ${response.status}${detail ? `: ${detail.slice(0, 500)}` : "."}`);
    }
  }

  return { batches: batches.length, entries: records.length, endpoint };
}

export function ingestionEndpoint(config: Pick<GoogleSecOpsConfig, "endpoint" | "ingestionMode">): string {
  const base = (config.endpoint.trim() || GOOGLE_SECOPS_DEFAULT_ENDPOINT)
    .replace(/\/+$/, "")
    .replace(/\/v2\/(?:unstructuredlogentries|udmevents):batchCreate$/, "");
  const resource = config.ingestionMode === "udm" ? "udmevents" : "unstructuredlogentries";
  return `${base}/v2/${resource}:batchCreate`;
}

export function buildGoogleSecOpsRequest(
  config: Omit<GoogleSecOpsConfig, "credential">,
  records: Array<SocEvent | Record<string, unknown>>,
): Record<string, unknown> {
  validateConfig({ ...config, credential: "validation-placeholder" });
  const entries = config.ingestionMode === "udm"
    ? records.map(toGoogleSecOpsUdmEvent)
    : records.map(toGoogleSecOpsLogEntry);
  return requestBody(config, entries);
}

export function toGoogleSecOpsLogEntry(record: SocEvent | Record<string, unknown>) {
  return {
    log_text: JSON.stringify(record),
    ts_rfc3339: recordTimestamp(record),
  };
}

export function toGoogleSecOpsUdmEvent(record: SocEvent | Record<string, unknown>): Record<string, unknown> {
  const raw = record as Record<string, unknown>;
  const eventType = stringValue(raw.eventType) || stringValue(raw.event_type) || stringValue(raw.kind);
  const hostname = stringValue(raw.hostname);
  const user = stringValue(raw.user) || nestedString(raw, "payload", "user");
  const sourceIp = stringValue(raw.source_ip) || nestedString(raw, "payload", "source_ip");
  const destinationIp = stringValue(raw.destination_ip) || nestedString(raw, "payload", "destination_ip");

  return compactObject({
    metadata: {
      event_timestamp: recordTimestamp(record),
      event_type: udmEventType(eventType),
      product_name: "Tawny-SOC",
      vendor_name: "Tawny",
      product_event_type: eventType || "telemetry",
      product_log_id: stringValue(raw.id),
    },
    principal: compactObject({
      hostname,
      ip: sourceIp ? [sourceIp] : undefined,
      user: user ? { userid: user } : undefined,
    }),
    target: compactObject({
      ip: destinationIp ? [destinationIp] : undefined,
    }),
    security_result: [{
      severity: stringValue(raw.severity).toUpperCase() || "LOW",
      description: stringValue(raw.title),
    }],
  });
}

async function resolveAccessToken(credential: string, fetchImpl: Fetch): Promise<string> {
  const value = credential.trim();
  if (!value) throw new Error("A Google SecOps OAuth token or service-account JSON credential is required.");
  if (!value.startsWith("{")) return value.replace(/^Bearer\s+/i, "");

  let serviceAccount: GoogleServiceAccount;
  try {
    serviceAccount = JSON.parse(value) as GoogleServiceAccount;
  } catch {
    throw new Error("The Google SecOps service-account credential is not valid JSON.");
  }
  if (!serviceAccount.client_email || !serviceAccount.private_key) {
    throw new Error("Service-account JSON must include client_email and private_key.");
  }

  const tokenUri = serviceAccount.token_uri || "https://oauth2.googleapis.com/token";
  const now = Math.floor(Date.now() / 1000);
  const header = base64Url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claims = base64Url(JSON.stringify({
    iss: serviceAccount.client_email,
    scope: GOOGLE_SECOPS_INGESTION_SCOPE,
    aud: tokenUri,
    iat: now,
    exp: now + 3600,
  }));
  const unsigned = `${header}.${claims}`;
  const signer = createSign("RSA-SHA256");
  signer.update(unsigned);
  signer.end();
  const assertion = `${unsigned}.${signer.sign(serviceAccount.private_key).toString("base64url")}`;
  const response = await fetchImpl(tokenUri, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion,
    }).toString(),
    signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) throw new Error(`Google OAuth returned HTTP ${response.status}.`);
  const payload = await response.json() as { access_token?: string };
  if (!payload.access_token) throw new Error("Google OAuth did not return an access token.");
  return payload.access_token;
}

function validateConfig(config: GoogleSecOpsConfig) {
  if (!config.customerId.trim()) throw new Error("Google SecOps customer ID is required.");
  if (config.ingestionMode !== "unstructured" && config.ingestionMode !== "udm") {
    throw new Error("Google SecOps ingestion mode must be unstructured or UDM.");
  }
  if (config.ingestionMode === "unstructured" && !config.logType.trim()) {
    throw new Error("Google SecOps log type is required for unstructured logs.");
  }
  if (config.ingestionMode === "unstructured" && !config.namespace.trim()) {
    throw new Error("Google SecOps namespace is required for unstructured logs.");
  }
  if (!config.credential.trim()) throw new Error("Google SecOps credentials are required.");
}

function requestBody(
  config: Pick<GoogleSecOpsConfig, "customerId" | "namespace" | "logType" | "ingestionMode">,
  entries: Array<Record<string, unknown>>,
): Record<string, unknown> {
  if (config.ingestionMode === "udm") return { customer_id: config.customerId, events: entries };
  return {
    customer_id: config.customerId,
    log_type: config.logType,
    namespace: config.namespace,
    entries,
  };
}

function splitIntoBatches(config: GoogleSecOpsConfig, entries: Array<Record<string, unknown>>) {
  const batches: Array<Array<Record<string, unknown>>> = [];
  let current: Array<Record<string, unknown>> = [];
  for (const entry of entries) {
    const candidate = [...current, entry];
    if (Buffer.byteLength(JSON.stringify(requestBody(config, candidate)), "utf8") > MAX_BATCH_BYTES) {
      if (current.length === 0) throw new Error("A Google SecOps log entry exceeds the 1 MB ingestion limit.");
      batches.push(current);
      current = [entry];
      if (Buffer.byteLength(JSON.stringify(requestBody(config, current)), "utf8") > MAX_BATCH_BYTES) {
        throw new Error("A Google SecOps log entry exceeds the 1 MB ingestion limit.");
      }
    } else {
      current = candidate;
    }
  }
  if (current.length > 0) batches.push(current);
  return batches;
}

function udmEventType(eventType: string) {
  const value = eventType.toLowerCase();
  if (/process|exec|powershell|command/.test(value)) return "PROCESS_LAUNCH";
  if (/dns|query/.test(value)) return "NETWORK_DNS";
  if (/login|logon|signin|auth/.test(value)) return "USER_LOGIN";
  if (/network|firewall|connection|traffic/.test(value)) return "NETWORK_CONNECTION";
  return "GENERIC_EVENT";
}

function recordTimestamp(record: SocEvent | Record<string, unknown>) {
  const fields = record as Record<string, unknown>;
  const raw = stringValue(fields.timestamp) || stringValue(fields.ts_rfc3339);
  const date = raw ? new Date(raw) : new Date();
  return Number.isNaN(date.getTime()) ? new Date().toISOString() : date.toISOString();
}

function nestedString(record: Record<string, unknown>, parent: string, child: string) {
  const value = record[parent];
  return value && typeof value === "object" && !Array.isArray(value)
    ? stringValue((value as Record<string, unknown>)[child])
    : "";
}

function stringValue(value: unknown) {
  return typeof value === "string" ? value.trim() : "";
}

function compactObject(value: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).filter(([, item]) => {
    if (item === undefined || item === null || item === "") return false;
    if (Array.isArray(item)) return item.length > 0;
    if (typeof item === "object") return Object.keys(item).length > 0;
    return true;
  }));
}

function base64Url(value: string) {
  return Buffer.from(value).toString("base64url");
}
