import { describe, expect, it } from "vitest";
import type { ApiPrincipal } from "../lib/api-auth";
import { handleMcpMessage, listMcpTools, MCP_PROTOCOL_VERSION } from "../lib/mcp-server";

const principal: ApiPrincipal = {
  id: "token-1",
  name: "API token token-1",
  tenantId: "tenant-a",
  role: "member",
  scopes: ["events:read", "alerts:read", "playbooks:read"],
  authType: "bearer",
};

describe("MCP server", () => {
  it("negotiates the current protocol and advertises tool capability", async () => {
    const response = await handleMcpMessage({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: MCP_PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: "test", version: "1" } },
    }, principal);

    expect(response).toMatchObject({
      jsonrpc: "2.0",
      id: 1,
      result: { protocolVersion: MCP_PROTOCOL_VERSION, capabilities: { tools: { listChanged: false } } },
    });
  });

  it("filters the tool catalog by API-token scope", () => {
    const names = listMcpTools(principal).map((tool) => tool.name);
    expect(names).toContain("tawny_hunt");
    expect(names).toContain("tawny_get_alert");
    expect(names).toContain("tawny_run_playbook");
    expect(names).not.toContain("tawny_get_case");
    expect(names).not.toContain("tawny_approve_response");
  });

  it("returns a protocol authorization error when a hidden tool is called", async () => {
    const response = await handleMcpMessage({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "tawny_approve_response", arguments: { runId: "run-1", actionId: "action-1", reason: "Approved" } },
    }, principal);

    expect(response).toMatchObject({ error: { code: -32003, message: "Missing scope: playbooks:approve" } });
  });

  it("accepts initialized notifications without returning a response body", async () => {
    await expect(handleMcpMessage({ jsonrpc: "2.0", method: "notifications/initialized" }, principal)).resolves.toBeNull();
  });
});
