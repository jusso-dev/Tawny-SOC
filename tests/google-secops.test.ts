import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  buildGoogleSecOpsRequest,
  ingestionEndpoint,
  sendGoogleSecOpsLogs,
  toGoogleSecOpsUdmEvent,
} from "../lib/integrations/google-secops";

describe("Google Security Operations forwarding", () => {
  it("formats unstructured log batches with Google log type metadata", () => {
    const config = {
      endpoint: "https://australia-southeast1-malachiteingestion-pa.googleapis.com/",
      customerId: "customer-123",
      namespace: "tawny-prod",
      logType: "TAWNY_SOC",
      ingestionMode: "unstructured" as const,
    };
    const body = buildGoogleSecOpsRequest(config, [{
      id: "event-1",
      eventType: "DnsQuery",
      timestamp: "2026-07-10T01:02:03.000Z",
    }]);

    expect(ingestionEndpoint(config)).toBe(
      "https://australia-southeast1-malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate",
    );
    expect(body).toMatchObject({
      customer_id: "customer-123",
      log_type: "TAWNY_SOC",
      namespace: "tawny-prod",
      entries: [{
        ts_rfc3339: "2026-07-10T01:02:03.000Z",
      }],
    });
    expect(JSON.parse((body.entries as Array<{ log_text: string }>)[0].log_text)).toMatchObject({ id: "event-1" });
  });

  it("maps common Tawny records into UDM events", () => {
    expect(toGoogleSecOpsUdmEvent({
      id: "event-2",
      eventType: "ProcessLaunch",
      timestamp: "2026-07-10T01:02:03.000Z",
      hostname: "win-01",
      user: "alice@example.com",
      source_ip: "10.0.0.5",
      destination_ip: "203.0.113.5",
      severity: "high",
      title: "Suspicious PowerShell",
    })).toMatchObject({
      metadata: {
        event_type: "PROCESS_LAUNCH",
        product_name: "Tawny-SOC",
        vendor_name: "Tawny",
      },
      principal: {
        hostname: "win-01",
        ip: ["10.0.0.5"],
        user: { userid: "alice@example.com" },
      },
      target: { ip: ["203.0.113.5"] },
      security_result: [{ severity: "HIGH" }],
    });
  });

  it("exchanges service-account JSON for OAuth and sends the batch", async () => {
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const credential = JSON.stringify({
      client_email: "secops@example.iam.gserviceaccount.com",
      private_key: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
      token_uri: "https://oauth2.googleapis.com/token",
    });
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(JSON.stringify({ access_token: "oauth-token" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }))
      .mockResolvedValueOnce(new Response(null, { status: 200 }));

    const result = await sendGoogleSecOpsLogs({
      endpoint: "https://malachiteingestion-pa.googleapis.com",
      customerId: "customer-123",
      namespace: "tawny-soc",
      logType: "TAWNY_SOC",
      ingestionMode: "unstructured",
      credential,
    }, [{ id: "event-3", timestamp: "2026-07-10T01:02:03Z" }], fetchMock);

    expect(result).toMatchObject({ batches: 1, entries: 1 });
    expect(fetchMock).toHaveBeenNthCalledWith(1, "https://oauth2.googleapis.com/token", expect.objectContaining({
      method: "POST",
    }));
    expect(fetchMock).toHaveBeenNthCalledWith(2,
      "https://malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate",
      expect.objectContaining({
        headers: expect.objectContaining({ authorization: "Bearer oauth-token" }),
      }),
    );
  });
});
