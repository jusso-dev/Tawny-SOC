import type { IngestPayload, Severity } from "../types";
import type {
  CanonicalIngestEvent,
  IngestionSourceType,
  NormalizationContext,
  NormalizationReject,
  NormalizationResult,
  TelemetryIngestPayload,
  TelemetryIngestPayloadOptions,
} from "./types";

type RecordLike = Record<string, unknown>;

type CanonicalEventInput = {
  raw: unknown;
  sourceType: IngestionSourceType;
  provider: string;
  product?: string;
  category?: string;
  eventType: string;
  title?: string;
  severity?: unknown;
  timestamp?: unknown;
  tenantId?: string;
  connectorId?: string;
  hostname?: string;
  user?: string;
  process?: string;
  image?: string;
  commandLine?: string;
  sourceIp?: string;
  destinationIp?: string;
  destinationPort?: number;
  protocol?: string;
  action?: string;
  outcome?: string;
  message?: string;
  fields?: RecordLike;
};

const sysmonEventTypes: Record<string, string> = {
  "1": "ProcessLaunch",
  "3": "NetworkConnection",
  "7": "ImageLoad",
  "10": "ProcessAccess",
  "11": "FileCreate",
  "22": "DnsQuery",
};

const windowsSecurityEventTypes: Record<string, string> = {
  "4624": "WindowsLogonSuccess",
  "4625": "WindowsLogonFailure",
  "4688": "ProcessLaunch",
};

export function normalizeGenericJson(input: unknown, context: NormalizationContext = {}): NormalizationResult {
  const parsed = recordsFromInput(input, ["events", "Records", "records", "value"]);

  return normalizeRecords(parsed.records, parsed.rejected, (record) => {
    const eventType = getString(record, ["event_type", "eventType", "type", "eventName", "Operation", "operationName"], "GenericJson");
    const hostname = getString(record, ["hostname", "host", "host.name", "Computer", "ComputerName", "deviceName"]) ?? context.defaultHostname;
    const commandLine = getString(record, ["command_line", "commandLine", "CommandLine", "ProcessCommandLine"]);
    const image = getString(record, ["image", "Image", "process", "process.name", "NewProcessName"]);
    const queryName = getString(record, ["query_name", "queryName", "QueryName", "dns.question.name"]);
    const network = networkFields(record);

    return buildCanonicalEvent({
      raw: record,
      sourceType: "generic_json",
      provider: getString(record, ["provider", "vendor", "source"], "Generic JSON"),
      product: getString(record, ["product", "service", "eventSource"]),
      category: getString(record, ["category", "event_category", "eventCategory"]),
      eventType,
      title: getString(record, ["title", "name", "eventName", "Operation"]) ?? eventType,
      severity: getUnknown(record, ["severity", "level", "risk", "Severity"]) ?? context.defaultSeverity,
      timestamp: getUnknown(record, ["timestamp", "@timestamp", "time", "eventTime", "TimeGenerated", "CreationTime", "createdAt"]),
      hostname,
      user: getString(record, ["user", "username", "User", "UserName", "user.name", "UserId"]),
      process: getString(record, ["process", "process.name", "Image", "NewProcessName"]),
      image,
      commandLine,
      sourceIp: network.sourceIp,
      destinationIp: network.destinationIp,
      destinationPort: network.destinationPort,
      protocol: network.protocol,
      action: getString(record, ["action", "act", "Operation", "operationName"]),
      outcome: normalizeOutcome(getUnknown(record, ["outcome", "result", "ResultStatus", "status"])),
      message: getString(record, ["message", "msg", "Message", "description"]),
      fields: prune({
        QueryName: queryName,
        query_name: queryName,
        Image: image,
        CommandLine: commandLine,
      }),
    }, context);
  });
}

export function normalizeSyslogText(input: string | string[], context: NormalizationContext = {}): NormalizationResult {
  const lines = Array.isArray(input) ? input : input.split(/\r?\n/);
  const events: CanonicalIngestEvent[] = [];
  const rejected: NormalizationReject[] = [];

  lines.map((line) => line.trim()).filter(Boolean).forEach((line, index) => {
    const cef = parseCefLine(line);
    if (cef) {
      events.push(buildCanonicalEvent({
        raw: line,
        sourceType: "cef",
        provider: cef.vendor || "CEF",
        product: cef.product,
        category: "network_or_security",
        eventType: cef.signatureId ? `CEF:${cef.signatureId}` : "CEF",
        title: cef.name || "CEF event",
        severity: cef.severity,
        timestamp: cef.timestamp,
        hostname: cef.hostname ?? context.defaultHostname,
        user: firstDefined(cef.extension.suser, cef.extension.duser, cef.extension.suid, cef.extension.duid),
        sourceIp: firstDefined(cef.extension.src, cef.extension.sourceAddress, cef.extension.sourceTranslatedAddress),
        destinationIp: firstDefined(cef.extension.dst, cef.extension.destinationAddress, cef.extension.destinationTranslatedAddress),
        destinationPort: numberValue(firstDefined(cef.extension.dpt, cef.extension.destinationPort)),
        protocol: firstDefined(cef.extension.proto, cef.extension.app),
        action: firstDefined(cef.extension.act, cef.extension.deviceAction),
        outcome: normalizeOutcome(firstDefined(cef.extension.outcome, cef.extension.result, cef.extension.act)),
        message: firstDefined(cef.extension.msg, cef.extension.message, cef.name, line),
        fields: cef.extension,
      }, context));
      return;
    }

    const syslog = parseSyslogLine(line);
    if (!syslog.message) {
      rejected.push({ index, reason: "empty_syslog_message", raw: line });
      return;
    }

    const kv = parseKeyValueFields(syslog.message);
    const network = networkFields(kv);
    const action = getString(kv, ["action", "act"]);

    events.push(buildCanonicalEvent({
      raw: line,
      sourceType: "syslog",
      provider: "Syslog",
      product: syslog.app,
      category: "syslog",
      eventType: syslog.app ? `Syslog:${syslog.app}` : "Syslog",
      title: syslog.app ? `${syslog.app} syslog` : "Syslog event",
      severity: syslog.severity ?? getUnknown(kv, ["severity", "level"]),
      timestamp: syslog.timestamp,
      hostname: syslog.hostname ?? context.defaultHostname,
      user: getString(kv, ["user", "username", "suser", "duser"]),
      sourceIp: network.sourceIp,
      destinationIp: network.destinationIp,
      destinationPort: network.destinationPort,
      protocol: network.protocol,
      action,
      outcome: normalizeOutcome(getUnknown(kv, ["outcome", "result", "status"]) ?? action),
      message: syslog.message,
      fields: prune({ ...kv, pri: syslog.pri, app: syslog.app, pid: syslog.pid }),
    }, context));
  });

  return { events, rejected };
}

export function normalizeWindowsRecord(input: unknown, context: NormalizationContext = {}): NormalizationResult {
  const parsed = recordsFromInput(input, ["events", "Records", "records", "value"]);

  return normalizeRecords(parsed.records, parsed.rejected, (record) => {
    const flat = flattenWindowsRecord(record);
    const provider = getString(flat, ["ProviderName", "Provider", "Channel"], "Windows");
    const providerLower = provider.toLowerCase();
    const channel = getString(flat, ["Channel", "LogName"], "");
    const eventId = getString(flat, ["EventID", "EventId", "event_id", "event.code"]);
    const isSysmon = providerLower.includes("sysmon") || channel.toLowerCase().includes("sysmon");
    const eventType = (isSysmon && eventId ? sysmonEventTypes[eventId] : undefined)
      ?? (eventId ? windowsSecurityEventTypes[eventId] : undefined)
      ?? (eventId ? `WindowsEvent:${eventId}` : "WindowsEvent");
    const image = getString(flat, ["Image", "NewProcessName", "ProcessName", "winlog.event_data.Image"]);
    const commandLine = getString(flat, ["CommandLine", "ProcessCommandLine", "winlog.event_data.CommandLine"]);
    const queryName = getString(flat, ["QueryName", "query_name", "winlog.event_data.QueryName"]);
    const targetFilename = getString(flat, ["TargetFilename", "target_filename", "winlog.event_data.TargetFilename"]);
    const network = networkFields(flat);

    return buildCanonicalEvent({
      raw: record,
      sourceType: isSysmon ? "sysmon" : "windows_event",
      provider: isSysmon ? "Microsoft Sysmon" : "Microsoft Windows",
      product: provider,
      category: channel || (isSysmon ? "sysmon" : "windows_event_log"),
      eventType,
      title: windowsTitle(eventType, eventId),
      severity: windowsSeverity(eventType, eventId),
      timestamp: getUnknown(flat, ["UtcTime", "TimeCreated", "SystemTime", "@timestamp", "timestamp"]),
      hostname: getString(flat, ["Computer", "ComputerName", "Hostname", "host.name"]) ?? context.defaultHostname,
      user: getString(flat, ["User", "UserName", "TargetUserName", "SubjectUserName", "winlog.event_data.User"]),
      process: image ? basename(image) : undefined,
      image,
      commandLine,
      sourceIp: network.sourceIp,
      destinationIp: network.destinationIp,
      destinationPort: network.destinationPort,
      protocol: network.protocol,
      action: eventType,
      outcome: eventType === "WindowsLogonFailure" ? "failure" : undefined,
      message: getString(flat, ["Message", "message"]),
      fields: prune({
        EventID: eventId,
        Image: image,
        CommandLine: commandLine,
        QueryName: queryName,
        query_name: queryName,
        TargetFilename: targetFilename,
        ParentImage: getString(flat, ["ParentImage"]),
        ParentCommandLine: getString(flat, ["ParentCommandLine"]),
        SourceIp: network.sourceIp,
        DestinationIp: network.destinationIp,
        DestinationPort: network.destinationPort,
      }),
    }, context);
  });
}

export function normalizeCloudTrailRecord(input: unknown, context: NormalizationContext = {}): NormalizationResult {
  const parsed = recordsFromInput(input, ["Records"]);

  return normalizeRecords(parsed.records, parsed.rejected, (record) => {
    const eventName = getString(record, ["eventName"], "AwsApiCall");
    const errorCode = getString(record, ["errorCode"]);
    const outcome = errorCode ? "failure" : "success";

    return buildCanonicalEvent({
      raw: record,
      sourceType: "aws_cloudtrail",
      provider: "AWS",
      product: getString(record, ["eventSource"], "CloudTrail"),
      category: "cloud_audit",
      eventType: `CloudTrail:${eventName}`,
      title: `AWS ${eventName}`,
      severity: cloudTrailSeverity(eventName, outcome),
      timestamp: getUnknown(record, ["eventTime"]),
      tenantId: getString(record, ["recipientAccountId", "userIdentity.accountId"]),
      user: getString(record, ["userIdentity.arn", "userIdentity.userName", "userIdentity.principalId"]),
      sourceIp: getString(record, ["sourceIPAddress"]),
      action: eventName,
      outcome,
      message: errorCode ? `${errorCode}: ${getString(record, ["errorMessage"], "")}`.trim() : getString(record, ["eventSource"]),
      fields: prune({
        aws_account_id: getString(record, ["recipientAccountId", "userIdentity.accountId"]),
        aws_region: getString(record, ["awsRegion"]),
        aws_event_source: getString(record, ["eventSource"]),
        aws_event_name: eventName,
        error_code: errorCode,
        error_message: getString(record, ["errorMessage"]),
        user_agent: getString(record, ["userAgent"]),
        request_parameters: getUnknown(record, ["requestParameters"]),
        response_elements: getUnknown(record, ["responseElements"]),
      }),
    }, context);
  });
}

export function normalizeAzureRecord(input: unknown, context: NormalizationContext = {}): NormalizationResult {
  const parsed = recordsFromInput(input, ["value", "records", "Records"]);

  return normalizeRecords(parsed.records, parsed.rejected, (record) => {
    const category = getString(record, ["Category", "category", "operationName.localizedValue"], "");
    const operation = getString(record, ["OperationName", "operationName", "activityDisplayName", "operationName.value"], "AzureActivity");
    const isSignIn = hasAny(record, ["UserPrincipalName", "userPrincipalName", "AppDisplayName", "appDisplayName"]) || /signin/i.test(category);
    const result = getUnknown(record, ["ResultType", "resultType", "ResultSignature", "status.value", "Status"]);
    const outcome = normalizeOutcome(result) ?? (String(result ?? "") === "0" ? "success" : undefined);

    return buildCanonicalEvent({
      raw: record,
      sourceType: isSignIn ? "azure_signin" : "azure_activity",
      provider: "Azure",
      product: isSignIn ? "Microsoft Entra ID" : getString(record, ["ResourceProviderValue", "resourceProviderName.value"], "Azure Activity"),
      category: isSignIn ? "identity" : "cloud_audit",
      eventType: isSignIn ? "AzureSignIn" : `AzureActivity:${operation}`,
      title: isSignIn ? "Azure sign-in" : `Azure ${operation}`,
      severity: azureSeverity(outcome, getString(record, ["ResultType", "resultType"])),
      timestamp: getUnknown(record, ["TimeGenerated", "time", "createdDateTime", "activityDateTime", "eventTimestamp"]),
      tenantId: getString(record, ["TenantId", "tenantId", "AADTenantId"]),
      user: getString(record, ["UserPrincipalName", "userPrincipalName", "Caller", "caller", "identity.claims.name"]),
      sourceIp: getString(record, ["IPAddress", "ipAddress", "CallerIpAddress", "callerIpAddress", "properties.clientIpAddress"]),
      action: operation,
      outcome,
      message: getString(record, ["ResultDescription", "resultDescription", "status.localizedValue", "Message"]),
      fields: prune({
        azure_category: category,
        azure_operation: operation,
        correlation_id: getString(record, ["CorrelationId", "correlationId"]),
        app_display_name: getString(record, ["AppDisplayName", "appDisplayName"]),
        resource_id: getString(record, ["ResourceId", "resourceId"]),
        conditional_access_status: getString(record, ["ConditionalAccessStatus", "conditionalAccessStatus"]),
      }),
    }, context);
  });
}

export function normalizeMicrosoft365AuditRecord(input: unknown, context: NormalizationContext = {}): NormalizationResult {
  const parsed = recordsFromInput(input, ["value", "Records", "records"]);

  return normalizeRecords(parsed.records, parsed.rejected, (record) => {
    const operation = getString(record, ["Operation", "operation"], "M365Audit");
    const workload = getString(record, ["Workload", "workload"], "Microsoft 365");
    const outcome = normalizeOutcome(getUnknown(record, ["ResultStatus", "resultStatus", "Status"]));

    return buildCanonicalEvent({
      raw: record,
      sourceType: "microsoft365_audit",
      provider: "Microsoft 365",
      product: workload,
      category: "saas_audit",
      eventType: `M365Audit:${operation}`,
      title: `${workload} ${operation}`,
      severity: outcome === "failure" ? "medium" : "low",
      timestamp: getUnknown(record, ["CreationTime", "creationTime", "TimeGenerated"]),
      tenantId: getString(record, ["OrganizationId", "organizationId", "TenantId"]),
      user: getString(record, ["UserId", "userId", "UserKey"]),
      sourceIp: getString(record, ["ClientIP", "clientIp", "ClientIp"]),
      action: operation,
      outcome,
      message: getString(record, ["ObjectId", "objectId", "ItemName"]),
      fields: prune({
        record_type: getString(record, ["RecordType", "recordType"]),
        workload,
        object_id: getString(record, ["ObjectId", "objectId"]),
        user_type: getString(record, ["UserType", "userType"]),
        audit_data: getUnknown(record, ["AuditData", "auditData"]),
      }),
    }, context);
  });
}

export function normalizeFirewallRecord(input: unknown, context: NormalizationContext = {}): NormalizationResult {
  const parsed = firewallRecordsFromInput(input);

  return normalizeRecords(parsed.records, parsed.rejected, (record) => {
    const network = networkFields(record);
    const action = getString(record, ["action", "act", "Action", "deviceAction", "event.action"]);
    const eventType = firewallEventType(action, getString(record, ["threat_name", "ThreatName", "signature"]));

    return buildCanonicalEvent({
      raw: record,
      sourceType: "firewall",
      provider: getString(record, ["vendor", "Vendor", "deviceVendor"], "Network"),
      product: getString(record, ["product", "Product", "deviceProduct", "device_name"], "Firewall"),
      category: "network",
      eventType,
      title: getString(record, ["name", "Name", "threat_name", "ThreatName", "rule"], eventType),
      severity: firewallSeverity(action, getUnknown(record, ["severity", "Severity", "level"])),
      timestamp: getUnknown(record, ["timestamp", "@timestamp", "receive_time", "time", "eventTime"]),
      hostname: getString(record, ["hostname", "host", "device_name", "dvc", "observer.name"]) ?? context.defaultHostname,
      user: getString(record, ["user", "src_user", "sourceUser", "suser"]),
      sourceIp: network.sourceIp,
      destinationIp: network.destinationIp,
      destinationPort: network.destinationPort,
      protocol: network.protocol,
      action,
      outcome: normalizeOutcome(getUnknown(record, ["outcome", "result", "status"]) ?? action),
      message: getString(record, ["message", "msg", "description"]),
      fields: prune({
        rule: getString(record, ["rule", "Rule", "rule_name"]),
        interface_in: getString(record, ["inbound_interface", "src_intf", "in"]),
        interface_out: getString(record, ["outbound_interface", "dst_intf", "out"]),
        application: getString(record, ["application", "app", "proto"]),
        bytes_in: getNumber(record, ["bytes_in", "sentbyte", "in_bytes"]),
        bytes_out: getNumber(record, ["bytes_out", "rcvdbyte", "out_bytes"]),
      }),
    }, context);
  });
}

export function normalizeIngestion(
  input: unknown,
  options: NormalizationContext & { format?: IngestionSourceType | "auto" } = {},
): NormalizationResult {
  if (options.format && options.format !== "auto") {
    return normalizeByFormat(input, options.format, options);
  }

  if (typeof input === "string") {
    if (input.includes("CEF:") || /^\s*<\d{1,3}>/.test(input)) return normalizeSyslogText(input, options);
    return normalizeGenericJson(input, options);
  }

  const sample = Array.isArray(input) ? input.find(isRecord) : input;
  if (isRecord(sample)) {
    if (hasAny(sample, ["Records"]) && isRecordArray(sample.Records) && sample.Records.some((record) => hasAny(record, ["eventSource", "eventName"]))) {
      return normalizeCloudTrailRecord(input, options);
    }
    if (hasAny(sample, ["eventSource", "eventName", "userIdentity"])) return normalizeCloudTrailRecord(input, options);
    if (hasAny(sample, ["Operation", "Workload", "CreationTime", "UserId"])) return normalizeMicrosoft365AuditRecord(input, options);
    if (hasAny(sample, ["UserPrincipalName", "CallerIpAddress", "ResourceProviderValue", "activityDisplayName"])) return normalizeAzureRecord(input, options);
    if (hasAny(sample, ["EventID", "EventId", "ProviderName", "Channel", "Event"])) return normalizeWindowsRecord(input, options);
    if (hasAny(sample, ["src", "dst", "src_ip", "dst_ip", "action", "dpt", "deviceVendor"])) return normalizeFirewallRecord(input, options);
  }

  return normalizeGenericJson(input, options);
}

export function toTelemetryIngestPayload(
  events: CanonicalIngestEvent[],
  options: TelemetryIngestPayloadOptions = {},
): TelemetryIngestPayload {
  const tenantId = options.tenantId ?? firstString(events.map((event) => event.tenant_id));
  const hostnames = uniqueStrings(events.map((event) => event.hostname));
  const connectorIds = uniqueStrings(events.map((event) => event.connector_id));

  return {
    source: options.source ?? "multi_source",
    kind: "telemetry_batch",
    sent_at: options.sentAt ?? new Date().toISOString(),
    tenant_id: tenantId,
    agent: {
      id: options.agentId ?? (connectorIds.length === 1 ? connectorIds[0] : "multi-source-ingest"),
      tenant_id: tenantId,
      hostname: options.agentHostname ?? (hostnames.length === 1 ? hostnames[0] : "multi-source-ingest"),
      operating_system: options.operatingSystem,
    },
    events,
  };
}

function normalizeByFormat(input: unknown, format: IngestionSourceType, context: NormalizationContext): NormalizationResult {
  if (format === "generic_json") return normalizeGenericJson(input, context);
  if (format === "syslog" || format === "cef") return normalizeSyslogText(asText(input), context);
  if (format === "windows_event" || format === "sysmon") return normalizeWindowsRecord(input, context);
  if (format === "aws_cloudtrail") return normalizeCloudTrailRecord(input, context);
  if (format === "azure_signin" || format === "azure_activity") return normalizeAzureRecord(input, context);
  if (format === "microsoft365_audit") return normalizeMicrosoft365AuditRecord(input, context);
  return normalizeFirewallRecord(input, context);
}

function normalizeRecords(
  records: unknown[],
  initialRejected: NormalizationReject[],
  normalizer: (record: RecordLike, index: number) => CanonicalIngestEvent,
): NormalizationResult {
  const events: CanonicalIngestEvent[] = [];
  const rejected = [...initialRejected];

  records.forEach((raw, index) => {
    if (!isRecord(raw)) {
      rejected.push({ index, reason: "record_not_object", raw });
      return;
    }

    try {
      events.push(normalizer(raw, index));
    } catch (error) {
      rejected.push({
        index,
        reason: error instanceof Error ? error.message : "normalization_failed",
        raw,
      });
    }
  });

  return { events, rejected };
}

function buildCanonicalEvent(input: CanonicalEventInput, context: NormalizationContext): CanonicalIngestEvent {
  const timestamp = normalizeTimestamp(input.timestamp, context.observedAt);
  const severity = normalizeSeverityValue(input.severity ?? context.defaultSeverity);
  const tenantId = input.tenantId ?? context.tenantId;
  const connectorId = input.connectorId ?? context.connectorId;
  const title = cleanTitle(input.title ?? `${input.provider} ${input.eventType}`);
  const seed = stableStringify({
    sourceType: input.sourceType,
    provider: input.provider,
    product: input.product,
    eventType: input.eventType,
    timestamp,
    hostname: input.hostname,
    user: input.user,
    sourceIp: input.sourceIp,
    destinationIp: input.destinationIp,
    raw: input.raw,
  });
  const id = `norm-${input.sourceType}-${hashString(seed)}`;

  return prune({
    ...input.fields,
    id,
    telemetry_id: id,
    source_type: input.sourceType,
    provider: input.provider,
    product: input.product,
    category: input.category,
    event_type: input.eventType,
    eventType: input.eventType,
    title,
    severity,
    timestamp,
    tenant_id: tenantId,
    connector_id: connectorId,
    hostname: input.hostname,
    user: input.user,
    process: input.process,
    image: input.image,
    Image: input.image,
    command_line: input.commandLine,
    commandLine: input.commandLine,
    CommandLine: input.commandLine,
    source_ip: input.sourceIp,
    SourceIp: input.sourceIp,
    destination_ip: input.destinationIp,
    DestinationIp: input.destinationIp,
    destination_port: input.destinationPort,
    DestinationPort: input.destinationPort,
    protocol: input.protocol,
    action: input.action,
    outcome: input.outcome,
    message: input.message,
    raw: input.raw,
  }) as CanonicalIngestEvent;
}

function recordsFromInput(input: unknown, arrayKeys: string[]): { records: unknown[]; rejected: NormalizationReject[] } {
  const rejected: NormalizationReject[] = [];

  if (typeof input === "string") {
    const text = input.trim();
    if (!text) return { records: [], rejected };

    try {
      return recordsFromParsed(JSON.parse(text), arrayKeys, rejected);
    } catch {
      const records: unknown[] = [];
      text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).forEach((line, index) => {
        try {
          records.push(JSON.parse(line));
        } catch {
          rejected.push({ index, reason: "invalid_json_line", raw: line });
        }
      });
      return { records, rejected };
    }
  }

  return recordsFromParsed(input, arrayKeys, rejected);
}

function recordsFromParsed(input: unknown, arrayKeys: string[], rejected: NormalizationReject[]) {
  if (Array.isArray(input)) return { records: input, rejected };
  if (isRecord(input)) {
    for (const key of arrayKeys) {
      const value = input[key];
      if (Array.isArray(value)) return { records: value, rejected };
    }
    return { records: [input], rejected };
  }
  return { records: [input], rejected };
}

function firewallRecordsFromInput(input: unknown): { records: unknown[]; rejected: NormalizationReject[] } {
  if (typeof input !== "string") return recordsFromInput(input, ["events", "records", "value"]);

  const parsed = recordsFromInput(input, ["events", "records", "value"]);
  if (parsed.records.length > 0) return parsed;

  const records: unknown[] = [];
  const rejected: NormalizationReject[] = [];
  input.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).forEach((line, index) => {
    const fields = parseKeyValueFields(line);
    if (Object.keys(fields).length === 0) {
      rejected.push({ index, reason: "firewall_line_without_fields", raw: line });
      return;
    }
    records.push({ ...fields, message: line });
  });
  return { records, rejected };
}

function parseCefLine(line: string) {
  const cefIndex = line.indexOf("CEF:");
  if (cefIndex < 0) return undefined;

  const prefix = line.slice(0, cefIndex).trim();
  const syslog = prefix ? parseSyslogLine(prefix) : {};
  const cef = line.slice(cefIndex);
  const parts = cef.split("|");
  if (parts.length < 7) return undefined;

  const extension = parseCefExtension(parts.slice(7).join("|"));
  return {
    timestamp: syslog.timestamp,
    hostname: syslog.hostname ?? singleToken(syslog.message),
    vendor: unescapeCef(parts[1] ?? ""),
    product: unescapeCef(parts[2] ?? ""),
    version: unescapeCef(parts[3] ?? ""),
    signatureId: unescapeCef(parts[4] ?? ""),
    name: unescapeCef(parts[5] ?? ""),
    severity: parts[6],
    extension,
  };
}

function parseCefExtension(extension: string): RecordLike {
  const fields: RecordLike = {};
  const pattern = /([A-Za-z0-9_.-]+)=((?:\\.|(?!\s+[A-Za-z0-9_.-]+=).)*)/g;
  let match: RegExpExecArray | null;

  while ((match = pattern.exec(extension)) !== null) {
    fields[match[1]] = unescapeCef(match[2].trim());
  }

  return fields;
}

function parseSyslogLine(line: string): {
  pri?: number;
  timestamp?: string;
  hostname?: string;
  app?: string;
  pid?: string;
  message?: string;
  severity?: Severity;
} {
  const match = line.match(/^(?:<(\d{1,3})>)?(?:(\d{4}-\d{2}-\d{2}T[^\s]+)|([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}))?\s*(?:([A-Za-z0-9_.:-]+)\s+)?(?:([A-Za-z0-9_.\/-]+)(?:\[(\d+)])?:\s*)?(.*)$/);
  const pri = match?.[1] ? Number(match[1]) : undefined;
  const timestamp = match?.[2] ?? (match?.[3] ? normalizeLegacySyslogTime(match[3]) : undefined);

  return {
    pri,
    timestamp,
    hostname: match?.[4],
    app: match?.[5],
    pid: match?.[6],
    message: match?.[7] ?? line,
    severity: pri === undefined ? undefined : syslogSeverity(pri),
  };
}

function parseKeyValueFields(text: string): RecordLike {
  const fields: RecordLike = {};
  const pattern = /([A-Za-z0-9_.-]+)=("[^"]*"|'[^']*'|\S+)/g;
  let match: RegExpExecArray | null;

  while ((match = pattern.exec(text)) !== null) {
    fields[match[1]] = stripQuotes(match[2]);
  }

  return fields;
}

function flattenWindowsRecord(record: RecordLike): RecordLike {
  const event = getRecord(record, ["Event"]) ?? record;
  const system = getRecord(event, ["System"]) ?? {};
  const provider = getRecord(system, ["Provider"]);
  const timeCreated = getRecord(system, ["TimeCreated"]);
  const eventData = getUnknown(event, ["EventData.Data", "UserData.EventData.Data"])
    ?? getUnknown(record, ["EventData.Data", "winlog.event_data"]);

  return prune({
    ...record,
    ...event,
    ...system,
    ...extractWindowsEventData(eventData),
    ProviderName: getString(system, ["ProviderName"]) ?? getString(provider, ["Name", "@Name"]) ?? getString(record, ["ProviderName", "Provider"]),
    EventID: scalarString(getUnknown(system, ["EventID"]) ?? getUnknown(record, ["EventID", "EventId"])),
    Channel: getString(system, ["Channel"]) ?? getString(record, ["Channel"]),
    Computer: getString(system, ["Computer"]) ?? getString(record, ["Computer", "ComputerName"]),
    SystemTime: getString(timeCreated, ["SystemTime", "@SystemTime"]) ?? getString(record, ["SystemTime"]),
  });
}

function extractWindowsEventData(value: unknown): RecordLike {
  if (Array.isArray(value)) {
    return value.reduce<RecordLike>((fields, item) => {
      if (!isRecord(item)) return fields;
      const name = getString(item, ["Name", "@Name", "name"]);
      if (!name) return fields;
      fields[name] = scalarValue(getUnknown(item, ["#text", "_", "Value", "value"]));
      return fields;
    }, {});
  }

  if (isRecord(value)) return value;
  return {};
}

function networkFields(record: RecordLike) {
  return {
    sourceIp: getString(record, ["source_ip", "src_ip", "src", "SourceIp", "SourceIP", "SourceAddress", "source.ip", "IPAddress"]),
    destinationIp: getString(record, ["destination_ip", "dest_ip", "dst_ip", "dst", "DestinationIp", "DestinationIP", "DestinationAddress", "destination.ip"]),
    destinationPort: getNumber(record, ["destination_port", "dest_port", "dst_port", "dpt", "DestinationPort", "destination.port"]),
    protocol: getString(record, ["protocol", "proto", "Protocol", "network.protocol"]),
  };
}

function normalizeTimestamp(value: unknown, fallback?: string) {
  const fallbackTimestamp = fallback ?? new Date().toISOString();
  if (value === undefined || value === null || value === "") return fallbackTimestamp;
  if (typeof value === "number") {
    const millis = value > 9999999999 ? value : value * 1000;
    const date = new Date(millis);
    return Number.isFinite(date.getTime()) ? date.toISOString() : fallbackTimestamp;
  }
  const text = scalarString(value);
  if (!text) return fallbackTimestamp;
  const date = new Date(text);
  return Number.isFinite(date.getTime()) ? date.toISOString() : fallbackTimestamp;
}

function normalizeLegacySyslogTime(value: string) {
  const year = new Date().getUTCFullYear();
  const date = new Date(`${value} ${year} UTC`);
  return Number.isFinite(date.getTime()) ? date.toISOString() : undefined;
}

function normalizeSeverityValue(value: unknown): Severity {
  if (typeof value === "number") return numericSeverity(value);
  const normalized = String(value ?? "low").trim().toLowerCase();
  if (/^\d+$/.test(normalized)) return numericSeverity(Number(normalized));
  if (["critical", "crit", "emergency", "alert", "fatal"].includes(normalized)) return "critical";
  if (["high", "error", "err", "severe"].includes(normalized)) return "high";
  if (["medium", "med", "warn", "warning", "notice"].includes(normalized)) return "medium";
  return "low";
}

function numericSeverity(value: number): Severity {
  if (value >= 9) return "critical";
  if (value >= 7) return "high";
  if (value >= 4) return "medium";
  return "low";
}

function syslogSeverity(pri: number): Severity {
  const severity = pri % 8;
  if (severity <= 2) return "critical";
  if (severity === 3) return "high";
  if (severity === 4) return "medium";
  return "low";
}

function normalizeOutcome(value: unknown): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  const normalized = String(value).trim().toLowerCase();
  if (["0", "success", "succeeded", "allow", "allowed", "accept", "accepted", "pass", "ok", "true"].includes(normalized)) return "success";
  if (["failure", "failed", "fail", "deny", "denied", "drop", "dropped", "blocked", "reject", "rejected", "false"].includes(normalized)) return "failure";
  return normalized;
}

function windowsTitle(eventType: string, eventId?: string) {
  if (eventType === "ProcessLaunch") return "Windows process launch";
  if (eventType === "NetworkConnection") return "Sysmon network connection";
  if (eventType === "DnsQuery") return "Sysmon DNS query";
  if (eventType === "WindowsLogonFailure") return "Windows failed logon";
  return eventId ? `Windows event ${eventId}` : "Windows event";
}

function windowsSeverity(eventType: string, eventId?: string): Severity {
  if (eventType === "WindowsLogonFailure") return "medium";
  if (eventId === "10") return "medium";
  return "low";
}

function cloudTrailSeverity(eventName: string, outcome: string): Severity {
  const normalized = eventName.toLowerCase();
  if (normalized === "consolelogin" && outcome === "failure") return "high";
  if (/delete|disable|putbucketpolicy|authorizesecuritygroup/.test(normalized)) return "medium";
  return outcome === "failure" ? "medium" : "low";
}

function azureSeverity(outcome?: string, resultType?: string): Severity {
  if (resultType && resultType !== "0") return "medium";
  return outcome === "failure" ? "medium" : "low";
}

function firewallEventType(action?: string, threatName?: string) {
  if (threatName) return "FirewallThreat";
  const normalized = String(action ?? "").toLowerCase();
  if (/deny|drop|block|reject/.test(normalized)) return "FirewallDeny";
  if (/allow|accept|pass/.test(normalized)) return "FirewallAllow";
  return "NetworkConnection";
}

function firewallSeverity(action?: string, value?: unknown): Severity {
  const explicit = value === undefined ? undefined : normalizeSeverityValue(value);
  if (explicit && explicit !== "low") return explicit;
  return /deny|drop|block|reject/i.test(String(action ?? "")) ? "medium" : "low";
}

function getUnknown(record: RecordLike | undefined, paths: string[]): unknown {
  if (!record) return undefined;
  for (const path of paths) {
    const value = lookup(record, path);
    if (value !== undefined && value !== null && value !== "") return value;
  }
  return undefined;
}

function getString(record: RecordLike | undefined, paths: string[]): string | undefined;
function getString(record: RecordLike | undefined, paths: string[], fallback: string): string;
function getString(record: RecordLike | undefined, paths: string[], fallback?: string): string | undefined {
  const value = getUnknown(record, paths);
  const text = scalarString(value);
  return text || fallback;
}

function getNumber(record: RecordLike | undefined, paths: string[]): number | undefined {
  const value = getUnknown(record, paths);
  return numberValue(value);
}

function getRecord(record: RecordLike | undefined, paths: string[]): RecordLike | undefined {
  const value = getUnknown(record, paths);
  return isRecord(value) ? value : undefined;
}

function lookup(record: RecordLike, path: string): unknown {
  if (Object.prototype.hasOwnProperty.call(record, path)) return record[path];
  return path.split(".").reduce<unknown>((current, part) => {
    if (!isRecord(current)) return undefined;
    return current[part];
  }, record);
}

function hasAny(record: RecordLike, paths: string[]) {
  return paths.some((path) => getUnknown(record, [path]) !== undefined);
}

function firstDefined(...values: unknown[]): string | undefined {
  for (const value of values) {
    const text = scalarString(value);
    if (text) return text;
  }
  return undefined;
}

function firstString(values: unknown[]) {
  return values.map(scalarString).find(Boolean);
}

function uniqueStrings(values: unknown[]) {
  return [...new Set(values.map(scalarString).filter(Boolean))];
}

function scalarValue(value: unknown): unknown {
  if (isRecord(value)) return getUnknown(value, ["#text", "_", "value", "Value"]) ?? value;
  return value;
}

function scalarString(value: unknown): string | undefined {
  const scalar = scalarValue(value);
  if (scalar === undefined || scalar === null) return undefined;
  if (typeof scalar === "string") return scalar.trim();
  if (typeof scalar === "number" || typeof scalar === "boolean") return String(scalar);
  return undefined;
}

function numberValue(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  const text = scalarString(value);
  if (!text) return undefined;
  const parsed = Number(text);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function isRecord(value: unknown): value is RecordLike {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function isRecordArray(value: unknown): value is RecordLike[] {
  return Array.isArray(value) && value.every(isRecord);
}

function asText(input: unknown) {
  if (typeof input === "string") return input;
  return JSON.stringify(input);
}

function cleanTitle(value: string) {
  const normalized = value.replace(/\s+/g, " ").trim();
  return normalized.length > 160 ? `${normalized.slice(0, 157)}...` : normalized;
}

function basename(value: string) {
  return value.split(/[\\/]/).filter(Boolean).at(-1);
}

function stripQuotes(value: string) {
  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
    return value.slice(1, -1);
  }
  return value;
}

function singleToken(value?: string) {
  return value && !/\s/.test(value) ? value : undefined;
}

function unescapeCef(value: string) {
  return value.replace(/\\=/g, "=").replace(/\\\|/g, "|").replace(/\\n/g, "\n").replace(/\\\\/g, "\\");
}

function prune<T extends RecordLike>(value: T): Partial<T> {
  return Object.fromEntries(Object.entries(value).filter(([, entry]) => entry !== undefined && entry !== "")) as Partial<T>;
}

function stableStringify(value: unknown): string {
  const seen = new WeakSet<object>();
  return JSON.stringify(value, (_key, item) => {
    if (!isRecord(item)) return item;
    if (seen.has(item)) return "[Circular]";
    seen.add(item);
    return Object.fromEntries(Object.keys(item).sort().map((key) => [key, item[key]]));
  }) ?? String(value);
}

function hashString(value: string) {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16).padStart(8, "0");
}

export type {
  CanonicalIngestEvent,
  IngestionSourceType,
  NormalizationContext,
  NormalizationResult,
  TelemetryIngestPayload,
};

export type { IngestPayload };
