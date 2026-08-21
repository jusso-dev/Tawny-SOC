export async function GET() {
  return Response.json({
    name: "Tawny-SOC Agent API",
    version: "v1",
    authentication: "Bearer tawny_* API token",
    documentation: "/api/v1/openapi.json",
    mcp: "/api/mcp",
    capabilities: ["Detect/Triage/Hunt/Respond agent mesh", "replayable investigation ledger", "scheduled YAAQL threat hunting", "alert detail", "case context", "threat intelligence", "SOAR planning and runs", "approval-gated response"],
  });
}
