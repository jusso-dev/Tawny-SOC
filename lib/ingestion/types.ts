import type { IngestPayload, Severity } from "@/lib/types";

export type IngestionSourceType =
  | "generic_json"
  | "syslog"
  | "cef"
  | "windows_event"
  | "sysmon"
  | "aws_cloudtrail"
  | "azure_signin"
  | "azure_activity"
  | "microsoft365_audit"
  | "firewall";

export type NormalizationContext = {
  tenantId?: string;
  connectorId?: string;
  observedAt?: string;
  defaultHostname?: string;
  defaultSeverity?: Severity;
};

export type NormalizationReject = {
  index: number;
  reason: string;
  raw: unknown;
};

export type NormalizationResult = {
  events: CanonicalIngestEvent[];
  rejected: NormalizationReject[];
};

export type CanonicalIngestEvent = Record<string, unknown> & {
  id: string;
  telemetry_id: string;
  source_type: IngestionSourceType;
  provider: string;
  product?: string;
  category?: string;
  event_type: string;
  eventType: string;
  title: string;
  severity: Severity;
  timestamp: string;
  tenant_id?: string;
  connector_id?: string;
  hostname?: string;
  user?: string;
  process?: string;
  image?: string;
  command_line?: string;
  source_ip?: string;
  destination_ip?: string;
  destination_port?: number;
  protocol?: string;
  action?: string;
  outcome?: string;
  message?: string;
  raw: unknown;
};

export type TelemetryIngestPayloadOptions = {
  source?: string;
  sentAt?: string;
  tenantId?: string;
  agentId?: string;
  agentHostname?: string;
  operatingSystem?: string;
};

export type TelemetryIngestPayload = IngestPayload & {
  kind: "telemetry_batch";
  events: CanonicalIngestEvent[];
};
