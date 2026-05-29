import { describe, expect, it } from "vitest";
import {
  normalizeAzureRecord,
  normalizeCloudTrailRecord,
  normalizeFirewallRecord,
  normalizeGenericJson,
  normalizeMicrosoft365AuditRecord,
  normalizeSyslogText,
  normalizeWindowsRecord,
  toTelemetryIngestPayload,
} from "../lib/ingestion/normalizers";

describe("ingestion normalizers", () => {
  it("normalizes generic JSON into Tawny-compatible telemetry payloads", () => {
    const result = normalizeGenericJson(JSON.stringify([{
      event_type: "DnsQuery",
      timestamp: "2026-05-28T02:03:04.000Z",
      hostname: "dns-01",
      query_name: "a83kdl29dls02ka9sldk20v.example",
      user: "alice",
    }]), { tenantId: "tenant-a", connectorId: "generic-json" });

    expect(result.rejected).toHaveLength(0);
    expect(result.events[0]).toMatchObject({
      source_type: "generic_json",
      event_type: "DnsQuery",
      eventType: "DnsQuery",
      tenant_id: "tenant-a",
      connector_id: "generic-json",
      hostname: "dns-01",
      QueryName: "a83kdl29dls02ka9sldk20v.example",
    });
    expect(result.events[0].id).toMatch(/^norm-generic_json-/);

    const payload = toTelemetryIngestPayload(result.events, { sentAt: "2026-05-28T02:04:00.000Z" });
    expect(payload.kind).toBe("telemetry_batch");
    expect(payload.agent?.hostname).toBe("dns-01");
    expect(payload.events[0].telemetry_id).toBe(result.events[0].id);
  });

  it("parses CEF-ish syslog and maps network fields", () => {
    const line = "<134>2026-05-28T02:03:04.000Z fw01 CEF:0|Palo Alto|PAN-OS|11|100001|Traffic denied|8|src=10.0.0.5 dst=203.0.113.4 dpt=443 act=deny suser=alice msg=Blocked outbound";
    const result = normalizeSyslogText(line);

    expect(result.rejected).toHaveLength(0);
    expect(result.events[0]).toMatchObject({
      source_type: "cef",
      provider: "Palo Alto",
      product: "PAN-OS",
      event_type: "CEF:100001",
      severity: "high",
      hostname: "fw01",
      user: "alice",
      source_ip: "10.0.0.5",
      destination_ip: "203.0.113.4",
      destination_port: 443,
      action: "deny",
      outcome: "failure",
    });
  });

  it("normalizes Windows and Sysmon-like process records", () => {
    const result = normalizeWindowsRecord({
      Event: {
        System: {
          Provider: { Name: "Microsoft-Windows-Sysmon" },
          EventID: 1,
          Channel: "Microsoft-Windows-Sysmon/Operational",
          Computer: "win-01",
          TimeCreated: { SystemTime: "2026-05-28T02:03:04.000Z" },
        },
        EventData: {
          Data: [
            { Name: "Image", "#text": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" },
            { Name: "CommandLine", "#text": "powershell.exe -NoP -enc SQBFAFgA" },
            { Name: "User", "#text": "ACME\\alice" },
          ],
        },
      },
    });

    expect(result.rejected).toHaveLength(0);
    expect(result.events[0]).toMatchObject({
      source_type: "sysmon",
      provider: "Microsoft Sysmon",
      event_type: "ProcessLaunch",
      hostname: "win-01",
      user: "ACME\\alice",
      process: "powershell.exe",
      CommandLine: "powershell.exe -NoP -enc SQBFAFgA",
      EventID: "1",
    });
  });

  it("normalizes AWS CloudTrail, Azure, and Microsoft 365 audit records", () => {
    const cloudTrail = normalizeCloudTrailRecord({
      Records: [{
        eventTime: "2026-05-28T02:03:04Z",
        eventName: "ConsoleLogin",
        eventSource: "signin.amazonaws.com",
        awsRegion: "us-east-1",
        recipientAccountId: "123456789012",
        sourceIPAddress: "198.51.100.20",
        userIdentity: { arn: "arn:aws:iam::123456789012:user/alice" },
        errorCode: "FailedAuthentication",
      }],
    }).events[0];

    const azure = normalizeAzureRecord({
      TimeGenerated: "2026-05-28T02:03:04Z",
      Category: "SignInLogs",
      UserPrincipalName: "alice@example.com",
      IPAddress: "198.51.100.21",
      ResultType: "50074",
      AppDisplayName: "Azure Portal",
    }).events[0];

    const m365 = normalizeMicrosoft365AuditRecord({
      CreationTime: "2026-05-28T02:03:04Z",
      Workload: "SharePoint",
      Operation: "FileAccessed",
      UserId: "alice@example.com",
      ClientIP: "198.51.100.22",
      ResultStatus: "Succeeded",
      ObjectId: "https://contoso.sharepoint.com/sites/finance/report.xlsx",
    }).events[0];

    expect(cloudTrail).toMatchObject({
      source_type: "aws_cloudtrail",
      event_type: "CloudTrail:ConsoleLogin",
      severity: "high",
      outcome: "failure",
      source_ip: "198.51.100.20",
    });
    expect(azure).toMatchObject({
      source_type: "azure_signin",
      event_type: "AzureSignIn",
      severity: "medium",
      user: "alice@example.com",
      source_ip: "198.51.100.21",
    });
    expect(m365).toMatchObject({
      source_type: "microsoft365_audit",
      event_type: "M365Audit:FileAccessed",
      outcome: "success",
      user: "alice@example.com",
      source_ip: "198.51.100.22",
    });
  });

  it("normalizes firewall key-value logs", () => {
    const result = normalizeFirewallRecord("timestamp=2026-05-28T02:03:04Z vendor=fortinet product=fortigate src=10.0.0.10 dst=203.0.113.10 dpt=22 proto=tcp action=deny rule=blocked-ssh");

    expect(result.rejected).toHaveLength(0);
    expect(result.events[0]).toMatchObject({
      source_type: "firewall",
      provider: "fortinet",
      product: "fortigate",
      event_type: "FirewallDeny",
      severity: "medium",
      source_ip: "10.0.0.10",
      destination_ip: "203.0.113.10",
      destination_port: 22,
      protocol: "tcp",
      outcome: "failure",
    });
  });
});
