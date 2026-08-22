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
    await page.getByRole("heading", { name: "Every bot. Every message. Every tool call." }).waitFor();

    const tokenResponse = await page.request.post(`${baseUrl}/api/soc/actions`, { data: {
      action: "create-api-token",
      name: `Hermes smoke ${Date.now()}`,
      role: "member",
      scopes: ["ingest:write", "events:read", "alerts:read", "cases:read", "threat-intel:read", "playbooks:read", "agent-rooms:read", "agent-rooms:write"],
    } });
    assert.equal(tokenResponse.ok(), true, "Hermes smoke token creation failed");
    const tokenBody = await tokenResponse.json() as { token?: string; tokenId?: string };
    assert.ok(tokenBody.token && tokenBody.tokenId, "Hermes smoke token missing");
    try {
      const headers = { authorization: `Bearer ${tokenBody.token}`, "content-type": "application/json" };
      const restAgents = await page.request.get(`${baseUrl}/api/v1/agents`, { headers });
      const restAgentsBody = await restAgents.json() as { agents?: unknown[] };
      assert.equal(restAgentsBody.agents?.length, 13, "REST specialist catalog incomplete");
      const restWorkflows = await page.request.get(`${baseUrl}/api/v1/agent-workflows`, { headers });
      const restWorkflowsBody = await restWorkflows.json() as { workflows?: unknown[] };
      assert.equal(restWorkflowsBody.workflows?.length, 6, "REST workflow catalog incomplete");
      const toolsResponse = await page.request.post(`${baseUrl}/api/mcp`, { headers, data: { jsonrpc: "2.0", id: 1, method: "tools/list" } });
      const toolsBody = await toolsResponse.json() as { result?: { tools?: Array<{ name?: string }> } };
      const toolNames = toolsBody.result?.tools?.map((tool) => tool.name) ?? [];
      assert.ok(toolNames.includes("tawny_run_agent_mesh"), "Hermes agent mesh tool missing");
      assert.ok(toolNames.includes("tawny_list_soc_agents"), "Hermes specialist catalog tool missing");
      assert.ok(toolNames.includes("tawny_list_agent_workflows"), "Hermes workflow catalog tool missing");
      assert.ok(toolNames.includes("tawny_run_agent_workflow"), "Hermes workflow dispatch tool missing");
      assert.ok(toolNames.includes("tawny_open_agent_room"), "Hermes room-open tool missing");
      assert.ok(toolNames.includes("tawny_get_agent_room"), "Hermes room-read tool missing");
      assert.ok(toolNames.includes("tawny_post_agent_message"), "Hermes room-message tool missing");
      assert.ok(toolNames.includes("tawny_close_agent_room"), "Hermes room-close tool missing");
      assert.ok(toolNames.includes("tawny_list_hunt_schedules"), "Hermes hunt schedule tool missing");
      const agentsResponse = await page.request.post(`${baseUrl}/api/mcp`, { headers, data: { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "tawny_list_soc_agents", arguments: {} } } });
      const agentsBody = await agentsResponse.json() as { result?: { structuredContent?: { agents?: unknown[] } } };
      assert.equal(agentsBody.result?.structuredContent?.agents?.length, 13, "Hermes specialist catalog incomplete");
      const workflowsResponse = await page.request.post(`${baseUrl}/api/mcp`, { headers, data: { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "tawny_list_agent_workflows", arguments: {} } } });
      const workflowsBody = await workflowsResponse.json() as { result?: { structuredContent?: { workflows?: unknown[] } } };
      assert.equal(workflowsBody.result?.structuredContent?.workflows?.length, 6, "Hermes workflow catalog incomplete");
      const openRoomResponse = await page.request.post(`${baseUrl}/api/mcp`, { headers, data: { jsonrpc: "2.0", id: 21, method: "tools/call", params: { name: "tawny_open_agent_room", arguments: { alertId: "alert-war-room-001", workflowId: "incident-response", agentId: "triage" } } } });
      const openRoomBody = await openRoomResponse.json() as { result?: { isError?: boolean; structuredContent?: { room?: { id?: string } } } };
      const roomId = openRoomBody.result?.structuredContent?.room?.id;
      assert.equal(openRoomBody.result?.isError, false, "Hermes room open returned error");
      assert.ok(roomId, "Hermes room ID missing");
      const messageResponse = await page.request.post(`${baseUrl}/api/mcp`, { headers, data: { jsonrpc: "2.0", id: 22, method: "tools/call", params: { name: "tawny_post_agent_message", arguments: { roomId, agentId: "triage", targetAgentId: "investigator", messageType: "handoff", message: "Triage confirmed. Investigate retained evidence.", evidence: ["alert-war-room-001"] } } } });
      assert.equal((await messageResponse.json() as { result?: { isError?: boolean } }).result?.isError, false, "Hermes room message returned error");
      const tracedAlertResponse = await page.request.post(`${baseUrl}/api/mcp`, { headers, data: { jsonrpc: "2.0", id: 23, method: "tools/call", params: { name: "tawny_get_alert", arguments: { alertId: "alert-war-room-001", roomId, agentId: "investigator" } } } });
      assert.equal((await tracedAlertResponse.json() as { result?: { isError?: boolean } }).result?.isError, false, "Hermes traced tool returned error");
      const roomResponse = await page.request.post(`${baseUrl}/api/mcp`, { headers, data: { jsonrpc: "2.0", id: 24, method: "tools/call", params: { name: "tawny_get_agent_room", arguments: { roomId, agentId: "reporter" } } } });
      const roomBody = await roomResponse.json() as { result?: { structuredContent?: { room?: { events?: Array<{ eventType?: string; toolName?: string }> } } } };
      const roomEvents = roomBody.result?.structuredContent?.room?.events ?? [];
      assert.ok(roomEvents.some((event) => event.eventType === "agent.handoff"), "Hermes handoff missing from room trace");
      assert.ok(roomEvents.some((event) => event.eventType === "tool.completed" && event.toolName === "tawny_get_alert"), "Hermes MCP output missing from room trace");
      const closeRoomResponse = await page.request.post(`${baseUrl}/api/mcp`, { headers, data: { jsonrpc: "2.0", id: 25, method: "tools/call", params: { name: "tawny_close_agent_room", arguments: { roomId, agentId: "reporter", summary: "Smoke room complete with attributed handoff and tool trace." } } } });
      assert.equal((await closeRoomResponse.json() as { result?: { isError?: boolean } }).result?.isError, false, "Hermes room close returned error");
      const workflowResponse = await page.request.post(`${baseUrl}/api/mcp`, { headers, data: { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "tawny_run_agent_workflow", arguments: { alertId: "alert-war-room-001", workflowId: "incident-response" } } } });
      const workflowBody = await workflowResponse.json() as { result?: { isError?: boolean; structuredContent?: { run?: { workflowId?: string; steps?: unknown[] } } } };
      assert.equal(workflowBody.result?.isError, false, "Hermes workflow dispatch returned error");
      assert.equal(workflowBody.result?.structuredContent?.run?.workflowId, "incident-response", "Hermes dispatched wrong workflow");
      assert.equal(workflowBody.result?.structuredContent?.run?.steps?.length, 4, "Hermes incident response did not run four specialists");
      const autoAlertSourceId = `vigil-smoke-${Date.now()}`;
      const autoAlertId = `alert-${autoAlertSourceId}`;
      const ingestResponse = await page.request.post(`${baseUrl}/api/ingest/tawny`, { headers, data: {
        kind: "alert_batch",
        agent: { id: "smoke-agent", hostname: "win-smoke-01", operating_system: "Windows" },
        alerts: [{ alert_id: autoAlertSourceId, alert_title: "Critical specialist autorun smoke", alert_severity: "critical", rule_id: "smoke-critical" }],
      } });
      assert.equal(ingestResponse.ok(), true, "critical alert ingest failed");
      const ingestBody = await ingestResponse.json() as { priorityAlertIds?: string[] };
      assert.ok(ingestBody.priorityAlertIds?.includes(autoAlertId), "critical alert was not queued for automatic investigation");
      let automaticRun: { workflowId?: string; steps?: unknown[]; status?: string } | undefined;
      for (let attempt = 0; attempt < 50 && !automaticRun; attempt += 1) {
        const automaticLedgerResponse = await page.request.post(`${baseUrl}/api/mcp`, { headers, data: { jsonrpc: "2.0", id: 40 + attempt, method: "tools/call", params: { name: "tawny_list_agent_runs", arguments: { limit: 50 } } } });
        const automaticLedgerBody = await automaticLedgerResponse.json() as { result?: { structuredContent?: { runs?: Array<{ alertId?: string; trigger?: string; workflowId?: string; steps?: unknown[]; status?: string }> } } };
        automaticRun = automaticLedgerBody.result?.structuredContent?.runs?.find((run) => run.alertId === autoAlertId && run.trigger === "automatic-ingest" && run.status === "completed");
        if (!automaticRun) await page.waitForTimeout(200);
      }
      assert.equal(automaticRun?.workflowId, "incident-response", "critical alert did not enter default specialist workflow");
      assert.equal(automaticRun?.steps?.length, 4, "automatic incident response did not run four specialists");
      const ledgerResponse = await page.request.post(`${baseUrl}/api/mcp`, { headers, data: { jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "tawny_list_agent_runs", arguments: { limit: 5 } } } });
      const ledgerBody = await ledgerResponse.json() as { result?: { isError?: boolean; structuredContent?: { runs?: unknown[] } } };
      assert.equal(ledgerBody.result?.isError, false, "Hermes ledger tool returned error");
      assert.ok((ledgerBody.result?.structuredContent?.runs?.length ?? 0) > 0, "Hermes ledger tool returned no runs");
    } finally {
      await page.request.post(`${baseUrl}/api/soc/actions`, { data: { action: "delete-api-token", tokenId: tokenBody.tokenId } });
    }

    await page.reload({ waitUntil: "networkidle" });
    const runCount = await page.locator(".agent-run-list details").count();
    await page.getByLabel("Specialist workflow").selectOption("full-investigation");
    await page.getByRole("button", { name: "Run workflow" }).click();
    await page.getByText("Specialist workflow completed.").waitFor();
    await page.reload({ waitUntil: "networkidle" });
    assert.equal(await page.locator(".agent-run-list details").count(), runCount + 1, "agent run ledger did not grow");
    assert.equal(await page.locator(".agent-run-list details").first().locator(".run-steps article").count(), 5, "full investigation did not run five specialists");

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
    await page.getByRole("heading", { name: "Install 13 named SOC bots with durable shared rooms." }).waitFor();
    await page.getByText("pnpm hermes:profiles:install", { exact: false }).waitFor();
    process.stdout.write("Hermes Bot profiles, shared room trace, specialist workflows, proactive hunt, and world view smoke checks passed.\n");
  } finally {
    await browser.close();
  }
}

void main();
