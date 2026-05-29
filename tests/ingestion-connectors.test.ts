import { describe, expect, it } from "vitest";
import {
  connectorCatalog,
  getConnectorDefinition,
  listConnectorCatalog,
  redactConnectorConfig,
  requiredFieldKeys,
  validateConnectorConfig,
} from "../lib/connectors";

describe("connector catalog", () => {
  it("filters connectors by category and format", () => {
    expect(listConnectorCatalog({ category: "cloud_audit" }).map((connector) => connector.id)).toEqual(
      expect.arrayContaining(["aws-cloudtrail", "azure-activity"]),
    );
    expect(listConnectorCatalog({ format: "sysmon" }).map((connector) => connector.id)).toEqual(["windows-sysmon"]);
  });

  it("validates required fields and reports unknown connectors", () => {
    expect(requiredFieldKeys("aws-cloudtrail")).toEqual(["roleArn", "externalIdRef", "region"]);

    const missing = validateConnectorConfig("aws-cloudtrail", {
      roleArn: "arn:aws:iam::123456789012:role/tawny-soc-reader",
      region: "ap-southeast-2",
    });
    expect(missing).toMatchObject({
      ok: false,
      unknownConnector: false,
      missingFields: ["externalIdRef"],
    });

    expect(validateConnectorConfig("missing", {})).toMatchObject({
      ok: false,
      unknownConnector: true,
    });
  });

  it("redacts secret fields and keeps safe tests local", () => {
    const redacted = redactConnectorConfig("microsoft365-audit", {
      tenantId: "tenant",
      clientId: "client",
      clientSecretRef: "vault://m365-secret",
      lookbackMinutes: 15,
    });

    expect(redacted).toEqual({
      tenantId: "tenant",
      clientId: "client",
      clientSecretRef: "[redacted]",
      lookbackMinutes: 15,
    });

    expect(connectorCatalog.every((connector) => connector.safeTest.networkAccess === "none")).toBe(true);
    expect(getConnectorDefinition("firewall-network")?.safeTest).toMatchObject({
      mode: "synthetic_event",
      sampleEventFormat: "firewall",
    });
  });

  it("returns cloned catalog entries", () => {
    const first = getConnectorDefinition("generic-json");
    first?.categories.push("network");

    expect(getConnectorDefinition("generic-json")?.categories).toEqual(["generic"]);
  });
});
