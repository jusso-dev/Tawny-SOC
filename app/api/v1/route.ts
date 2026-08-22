export async function GET() {
  return Response.json({
    name: "Tawny-SOC Agent API",
    version: "v1",
    authentication: "Bearer tawny_* API token",
    documentation: "/api/v1/openapi.json",
    mcp: "/api/mcp",
    capabilities: ["13 Hermes Bot Mode profiles", "SOUL.md specialist contracts", "six reusable multi-agent workflows", "durable shared agent rooms", "complete MCP tool and handoff trace", "scheduled YAAQL threat hunting", "alert detail", "case context", "threat intelligence", "SOAR planning and runs", "approval-gated response"],
    discovery: { agents: "/api/v1/agents", workflows: "/api/v1/agent-workflows", rooms: "/api/v1/agent-rooms" },
  });
}
