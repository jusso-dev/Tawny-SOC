import type { IngestionSourceType } from "../ingestion/types";

export type ConnectorProvider =
  | "generic"
  | "syslog"
  | "windows"
  | "aws"
  | "azure"
  | "microsoft"
  | "network";

export type ConnectorCategory =
  | "cloud_audit"
  | "endpoint"
  | "identity"
  | "network"
  | "saas_audit"
  | "generic";

export type ConnectorAuthType =
  | "none"
  | "shared_secret"
  | "bearer_token"
  | "oauth2_client_credentials"
  | "aws_iam_role"
  | "certificate";

export type ConnectorFieldType = "string" | "secret" | "url" | "number" | "select" | "boolean";

export type ConnectorField = {
  key: string;
  label: string;
  type: ConnectorFieldType;
  required: boolean;
  secret?: boolean;
  placeholder?: string;
  allowedValues?: string[];
  helpText?: string;
};

export type ConnectorSafeTest = {
  mode: "metadata_only" | "synthetic_event";
  networkAccess: "none" | "configured_endpoint";
  validates: Array<"required_fields" | "auth_shape" | "parser_mapping" | "tenant_scope" | "timestamp_parse">;
  sampleEventFormat?: IngestionSourceType;
  sampleEventDescription: string;
  redactedFields: string[];
  timeoutMs: number;
};

export type ConnectorCatalogItem = {
  id: string;
  name: string;
  provider: ConnectorProvider;
  categories: ConnectorCategory[];
  authType: ConnectorAuthType;
  ingestionFormats: IngestionSourceType[];
  requiredFields: ConnectorField[];
  optionalFields: ConnectorField[];
  safeTest: ConnectorSafeTest;
  enabledByDefault: boolean;
};

export type ConnectorCatalogFilter = {
  provider?: ConnectorProvider;
  category?: ConnectorCategory;
  format?: IngestionSourceType;
  authType?: ConnectorAuthType;
};

export type ConnectorValidationResult = {
  ok: boolean;
  connectorId?: string;
  missingFields: string[];
  unknownConnector: boolean;
};

export const CONNECTOR_CATALOG_VERSION = "2026-05-issue-2-slice";

export const connectorCatalog: ConnectorCatalogItem[] = [
  {
    id: "generic-json",
    name: "Generic JSON",
    provider: "generic",
    categories: ["generic"],
    authType: "shared_secret",
    ingestionFormats: ["generic_json"],
    requiredFields: [
      {
        key: "sourceName",
        label: "Source name",
        type: "string",
        required: true,
        placeholder: "custom-edr",
      },
      {
        key: "sharedSecretRef",
        label: "Shared secret reference",
        type: "secret",
        required: true,
        secret: true,
        helpText: "Reference or vault key, not the plaintext secret.",
      },
    ],
    optionalFields: [
      { key: "tenantId", label: "Tenant ID", type: "string", required: false },
      { key: "schemaHint", label: "Schema hint", type: "string", required: false },
    ],
    safeTest: {
      mode: "synthetic_event",
      networkAccess: "none",
      validates: ["required_fields", "parser_mapping", "timestamp_parse"],
      sampleEventFormat: "generic_json",
      sampleEventDescription: "Builds one local JSON telemetry record with a fixed timestamp.",
      redactedFields: ["sharedSecretRef"],
      timeoutMs: 1000,
    },
    enabledByDefault: true,
  },
  {
    id: "syslog-cef",
    name: "Syslog / CEF",
    provider: "syslog",
    categories: ["network", "endpoint", "generic"],
    authType: "none",
    ingestionFormats: ["syslog", "cef"],
    requiredFields: [
      {
        key: "listenerPort",
        label: "Listener port",
        type: "number",
        required: true,
        placeholder: "6514",
      },
      {
        key: "transport",
        label: "Transport",
        type: "select",
        required: true,
        allowedValues: ["tcp", "udp", "tls"],
      },
    ],
    optionalFields: [
      { key: "bindAddress", label: "Bind address", type: "string", required: false, placeholder: "0.0.0.0" },
      { key: "allowedCidrs", label: "Allowed CIDRs", type: "string", required: false, placeholder: "10.0.0.0/8, 192.168.0.0/16" },
    ],
    safeTest: {
      mode: "synthetic_event",
      networkAccess: "none",
      validates: ["required_fields", "parser_mapping", "timestamp_parse"],
      sampleEventFormat: "cef",
      sampleEventDescription: "Parses a local CEF line and never opens a listening socket.",
      redactedFields: [],
      timeoutMs: 1000,
    },
    enabledByDefault: true,
  },
  {
    id: "windows-sysmon",
    name: "Windows Event / Sysmon",
    provider: "windows",
    categories: ["endpoint"],
    authType: "certificate",
    ingestionFormats: ["windows_event", "sysmon"],
    requiredFields: [
      { key: "collectorId", label: "Collector ID", type: "string", required: true, placeholder: "win-collector-prod" },
      { key: "certificateRef", label: "Certificate reference", type: "secret", required: true, secret: true },
    ],
    optionalFields: [
      { key: "channels", label: "Channels", type: "string", required: false, placeholder: "Security, Microsoft-Windows-Sysmon/Operational" },
      { key: "tenantId", label: "Tenant ID", type: "string", required: false },
    ],
    safeTest: {
      mode: "synthetic_event",
      networkAccess: "none",
      validates: ["required_fields", "auth_shape", "parser_mapping", "timestamp_parse"],
      sampleEventFormat: "sysmon",
      sampleEventDescription: "Normalizes a local Sysmon process creation fixture.",
      redactedFields: ["certificateRef"],
      timeoutMs: 1000,
    },
    enabledByDefault: true,
  },
  {
    id: "aws-cloudtrail",
    name: "AWS CloudTrail",
    provider: "aws",
    categories: ["cloud_audit"],
    authType: "aws_iam_role",
    ingestionFormats: ["aws_cloudtrail"],
    requiredFields: [
      { key: "roleArn", label: "IAM role ARN", type: "string", required: true, placeholder: "arn:aws:iam::123456789012:role/tawny-soc-reader" },
      { key: "externalIdRef", label: "External ID reference", type: "secret", required: true, secret: true },
      { key: "region", label: "Region", type: "string", required: true, placeholder: "ap-southeast-2" },
    ],
    optionalFields: [
      { key: "s3Bucket", label: "S3 bucket", type: "string", required: false },
      { key: "cloudWatchLogGroup", label: "CloudWatch log group", type: "string", required: false },
    ],
    safeTest: {
      mode: "metadata_only",
      networkAccess: "none",
      validates: ["required_fields", "auth_shape", "tenant_scope"],
      sampleEventFormat: "aws_cloudtrail",
      sampleEventDescription: "Validates ARN shape and configured scope without calling AWS.",
      redactedFields: ["externalIdRef"],
      timeoutMs: 1000,
    },
    enabledByDefault: true,
  },
  {
    id: "azure-signin",
    name: "Azure Sign-In Logs",
    provider: "azure",
    categories: ["identity"],
    authType: "oauth2_client_credentials",
    ingestionFormats: ["azure_signin"],
    requiredFields: [
      { key: "tenantId", label: "Tenant ID", type: "string", required: true },
      { key: "clientId", label: "Client ID", type: "string", required: true },
      { key: "clientSecretRef", label: "Client secret reference", type: "secret", required: true, secret: true },
    ],
    optionalFields: [
      { key: "workspaceId", label: "Log Analytics workspace ID", type: "string", required: false },
      { key: "lookbackMinutes", label: "Lookback minutes", type: "number", required: false, placeholder: "15" },
    ],
    safeTest: {
      mode: "metadata_only",
      networkAccess: "none",
      validates: ["required_fields", "auth_shape", "tenant_scope"],
      sampleEventFormat: "azure_signin",
      sampleEventDescription: "Checks OAuth configuration shape and tenant scope locally.",
      redactedFields: ["clientSecretRef"],
      timeoutMs: 1000,
    },
    enabledByDefault: true,
  },
  {
    id: "azure-activity",
    name: "Azure Activity",
    provider: "azure",
    categories: ["cloud_audit"],
    authType: "oauth2_client_credentials",
    ingestionFormats: ["azure_activity"],
    requiredFields: [
      { key: "tenantId", label: "Tenant ID", type: "string", required: true },
      { key: "subscriptionId", label: "Subscription ID", type: "string", required: true },
      { key: "clientId", label: "Client ID", type: "string", required: true },
      { key: "clientSecretRef", label: "Client secret reference", type: "secret", required: true, secret: true },
    ],
    optionalFields: [
      { key: "workspaceId", label: "Log Analytics workspace ID", type: "string", required: false },
      { key: "resourceGroups", label: "Resource groups", type: "string", required: false },
    ],
    safeTest: {
      mode: "metadata_only",
      networkAccess: "none",
      validates: ["required_fields", "auth_shape", "tenant_scope"],
      sampleEventFormat: "azure_activity",
      sampleEventDescription: "Checks subscription and OAuth configuration shape locally.",
      redactedFields: ["clientSecretRef"],
      timeoutMs: 1000,
    },
    enabledByDefault: true,
  },
  {
    id: "microsoft365-audit",
    name: "Microsoft 365 Audit",
    provider: "microsoft",
    categories: ["saas_audit", "identity"],
    authType: "oauth2_client_credentials",
    ingestionFormats: ["microsoft365_audit"],
    requiredFields: [
      { key: "tenantId", label: "Tenant ID", type: "string", required: true },
      { key: "clientId", label: "Client ID", type: "string", required: true },
      { key: "clientSecretRef", label: "Client secret reference", type: "secret", required: true, secret: true },
    ],
    optionalFields: [
      { key: "contentTypes", label: "Content types", type: "string", required: false, placeholder: "Audit.AzureActiveDirectory, Audit.Exchange" },
      { key: "lookbackMinutes", label: "Lookback minutes", type: "number", required: false, placeholder: "15" },
    ],
    safeTest: {
      mode: "metadata_only",
      networkAccess: "none",
      validates: ["required_fields", "auth_shape", "tenant_scope"],
      sampleEventFormat: "microsoft365_audit",
      sampleEventDescription: "Checks OAuth configuration shape and content type settings locally.",
      redactedFields: ["clientSecretRef"],
      timeoutMs: 1000,
    },
    enabledByDefault: true,
  },
  {
    id: "firewall-network",
    name: "Firewall / Network Logs",
    provider: "network",
    categories: ["network"],
    authType: "shared_secret",
    ingestionFormats: ["firewall", "syslog", "cef"],
    requiredFields: [
      { key: "vendor", label: "Vendor", type: "select", required: true, allowedValues: ["fortinet", "palo_alto", "cisco", "checkpoint", "generic"] },
      { key: "transport", label: "Transport", type: "select", required: true, allowedValues: ["syslog", "http", "s3"] },
      { key: "sharedSecretRef", label: "Shared secret reference", type: "secret", required: true, secret: true },
    ],
    optionalFields: [
      { key: "listenerPort", label: "Listener port", type: "number", required: false, placeholder: "6514" },
      { key: "allowedCidrs", label: "Allowed CIDRs", type: "string", required: false },
    ],
    safeTest: {
      mode: "synthetic_event",
      networkAccess: "none",
      validates: ["required_fields", "parser_mapping", "timestamp_parse"],
      sampleEventFormat: "firewall",
      sampleEventDescription: "Normalizes a local allow and deny fixture without contacting the firewall.",
      redactedFields: ["sharedSecretRef"],
      timeoutMs: 1000,
    },
    enabledByDefault: true,
  },
];

export function listConnectorCatalog(filter: ConnectorCatalogFilter = {}): ConnectorCatalogItem[] {
  return connectorCatalog.filter((connector) => {
    if (filter.provider && connector.provider !== filter.provider) return false;
    if (filter.category && !connector.categories.includes(filter.category)) return false;
    if (filter.format && !connector.ingestionFormats.includes(filter.format)) return false;
    if (filter.authType && connector.authType !== filter.authType) return false;
    return true;
  }).map(cloneConnector);
}

export function getConnectorDefinition(id: string): ConnectorCatalogItem | undefined {
  const connector = connectorCatalog.find((item) => item.id === id);
  return connector ? cloneConnector(connector) : undefined;
}

export function validateConnectorConfig(id: string, config: Record<string, unknown>): ConnectorValidationResult {
  const connector = connectorCatalog.find((item) => item.id === id);
  if (!connector) {
    return { ok: false, missingFields: [], unknownConnector: true };
  }

  const missingFields = connector.requiredFields
    .filter((field) => field.required)
    .filter((field) => isBlank(config[field.key]))
    .map((field) => field.key);

  return {
    ok: missingFields.length === 0,
    connectorId: connector.id,
    missingFields,
    unknownConnector: false,
  };
}

export function requiredFieldKeys(id: string): string[] {
  return getConnectorDefinition(id)?.requiredFields.filter((field) => field.required).map((field) => field.key) ?? [];
}

export function redactConnectorConfig(id: string, config: Record<string, unknown>): Record<string, unknown> {
  const connector = connectorCatalog.find((item) => item.id === id);
  if (!connector) return { ...config };
  const redacted = { ...config };
  const secretKeys = new Set([
    ...connector.requiredFields.filter((field) => field.secret).map((field) => field.key),
    ...connector.optionalFields.filter((field) => field.secret).map((field) => field.key),
    ...connector.safeTest.redactedFields,
  ]);

  for (const key of secretKeys) {
    if (!isBlank(redacted[key])) redacted[key] = "[redacted]";
  }

  return redacted;
}

function cloneConnector(connector: ConnectorCatalogItem): ConnectorCatalogItem {
  return {
    ...connector,
    categories: [...connector.categories],
    ingestionFormats: [...connector.ingestionFormats],
    requiredFields: connector.requiredFields.map((field) => ({ ...field, allowedValues: field.allowedValues ? [...field.allowedValues] : undefined })),
    optionalFields: connector.optionalFields.map((field) => ({ ...field, allowedValues: field.allowedValues ? [...field.allowedValues] : undefined })),
    safeTest: {
      ...connector.safeTest,
      validates: [...connector.safeTest.validates],
      redactedFields: [...connector.safeTest.redactedFields],
    },
  };
}

function isBlank(value: unknown) {
  return value === undefined || value === null || (typeof value === "string" && value.trim() === "");
}
