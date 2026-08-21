import assert from "node:assert/strict";
import { chromium } from "@playwright/test";

const baseUrl = process.env.SMOKE_URL ?? "http://localhost:3001";

async function main() {
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    await page.goto(`${baseUrl}/sign-in?next=%2Fwar-room`, { waitUntil: "networkidle" });
    await page.getByLabel("Email").fill(process.env.SMOKE_EMAIL ?? "analyst@tawny.local");
    await page.getByLabel("Password").fill(process.env.SMOKE_PASSWORD ?? "TawnySocLocal123!");
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await page.getByRole("heading", { name: "Agents investigate. Analysts command." }).waitFor();

    const tokenResponse = await page.request.post(`${baseUrl}/api/soc/actions`, { data: {
      action: "create-api-token",
      name: `Hermes smoke ${Date.now()}`,
      role: "member",
      scopes: ["events:read", "alerts:read", "cases:read", "threat-intel:read", "playbooks:read"],
    } });
    assert.equal(tokenResponse.ok(), true, "Hermes smoke token creation failed");
    const tokenBody = await tokenResponse.json() as { token?: string; tokenId?: string };
    assert.ok(tokenBody.token && tokenBody.tokenId, "Hermes smoke token missing");
    try {
      const headers = { authorization: `Bearer ${tokenBody.token}`, "content-type": "application/json" };
      const toolsResponse = await page.request.post(`${baseUrl}/api/mcp`, { headers, data: { jsonrpc: "2.0", id: 1, method: "tools/list" } });
      const toolsBody = await toolsResponse.json() as { result?: { tools?: Array<{ name?: string }> } };
      const toolNames = toolsBody.result?.tools?.map((tool) => tool.name) ?? [];
      assert.ok(toolNames.includes("tawny_run_agent_mesh"), "Hermes agent mesh tool missing");
      assert.ok(toolNames.includes("tawny_list_hunt_schedules"), "Hermes hunt schedule tool missing");
      const ledgerResponse = await page.request.post(`${baseUrl}/api/mcp`, { headers, data: { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "tawny_list_agent_runs", arguments: { limit: 5 } } } });
      const ledgerBody = await ledgerResponse.json() as { result?: { isError?: boolean; structuredContent?: { runs?: unknown[] } } };
      assert.equal(ledgerBody.result?.isError, false, "Hermes ledger tool returned error");
      assert.ok((ledgerBody.result?.structuredContent?.runs?.length ?? 0) > 0, "Hermes ledger tool returned no runs");
    } finally {
      await page.request.post(`${baseUrl}/api/soc/actions`, { data: { action: "delete-api-token", tokenId: tokenBody.tokenId } });
    }

    const runCount = await page.locator(".agent-run-list details").count();
    await page.getByRole("button", { name: "Run agent mesh" }).click();
    await page.getByText("Agent mesh completed.").waitFor();
    await page.waitForLoadState("networkidle");
    assert.equal(await page.locator(".agent-run-list details").count(), runCount + 1, "agent run ledger did not grow");

    const scheduleName = `Smoke hunt ${Date.now()}`;
    await page.getByLabel("Name").fill(scheduleName);
    await page.getByLabel("Hypothesis").fill("A high-severity signal repeats across the retained endpoint dataset.");
    await page.getByLabel("YAAQL query").fill("kind=alert and severity in (critical, high)");
    await page.getByRole("button", { name: "Create schedule" }).click();
    await page.getByText("Proactive hunt scheduled.").waitFor();
    await page.getByText(scheduleName).waitFor();

    await page.goto(`${baseUrl}/world`, { waitUntil: "networkidle" });
    await page.getByRole("heading", { name: "See attack pressure outside your perimeter." }).waitFor();
    assert.equal(await page.locator(".world-path.tenant").count(), 4, "tenant world paths missing");

    await page.goto(`${baseUrl}/integrations#hermes`, { waitUntil: "networkidle" });
    await page.getByRole("heading", { name: "Give every Hermes bot a native Tawny-SOC toolset." }).waitFor();
    await page.getByText("tawny_run_agent_mesh", { exact: false }).waitFor();
    process.stdout.write("War room, proactive hunt, world view, and Hermes MCP smoke checks passed.\n");
  } finally {
    await browser.close();
  }
}

void main();
