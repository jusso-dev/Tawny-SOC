const document = {
  openapi: "3.1.0",
  info: {
    title: "Tawny-SOC Agent API",
    version: "1.0.0",
    description: "Tenant-scoped Hermes Bot Mode profiles, durable shared rooms, complete MCP trace events, reusable multi-agent workflows, scheduled threat hunting, investigation context, and approval-gated SOAR automation.",
  },
  servers: [{ url: "/api/v1" }],
  security: [{ bearerAuth: [] }],
  paths: {
    "/agents": { get: { summary: "List specialist SOC agent profiles", responses: { "200": { description: "Agent catalog" }, "401": { description: "Requires alerts:read" } } } },
    "/agent-workflows": { get: { summary: "List reusable multi-agent workflows", responses: { "200": { description: "Workflow catalog" }, "401": { description: "Requires playbooks:read" } } } },
    "/agent-rooms": {
      get: { summary: "List shared agent rooms with ordered trace events", parameters: [{ name: "limit", in: "query", schema: { type: "integer", minimum: 1, maximum: 50 } }], responses: { "200": { description: "Agent rooms" }, "401": { description: "Requires agent-rooms:read" } } },
      post: {
        summary: "Open a durable Hermes Bot Mode room",
        requestBody: { required: true, content: { "application/json": { schema: { type: "object", required: ["alertId", "workflowId", "agentId"], properties: { alertId: { type: "string" }, workflowId: { type: "string" }, agentId: { type: "string" }, title: { type: "string" } } } } } },
        responses: { "201": { description: "Room opened" }, "401": { description: "Requires agent-rooms:write" }, "404": { description: "Workflow or alert not found" } },
      },
    },
    "/agent-rooms/{id}": { get: { summary: "Read one room, including bot messages, tool calls, handoffs, approvals, and outcomes", parameters: [pathId()], responses: { "200": { description: "Complete ordered room trace" }, "401": { description: "Requires agent-rooms:read" }, "404": { description: "Room not found" } } } },
    "/agent-workflows/{id}/runs": {
      post: {
        summary: "Run a specialist workflow against an alert",
        description: "Executes ordered specialist phases and persists their handoffs. Response phases propose approval-gated actions but never execute containment.",
        parameters: [pathId()],
        requestBody: { required: true, content: { "application/json": { schema: { type: "object", required: ["alertId"], properties: { alertId: { type: "string" } } } } } },
        responses: { "200": { description: "Completed workflow ledger" }, "401": { description: "Requires alerts:read" }, "404": { description: "Workflow or alert not found" } },
      },
    },
    "/hunt": {
      get: {
        summary: "Run a YAAQL hunt across alerts and telemetry",
        parameters: [
          { name: "q", in: "query", schema: { type: "string" } },
          { name: "dataset", in: "query", schema: { enum: ["all", "alerts", "events", "telemetry"] } },
          { name: "range", in: "query", schema: { type: "string", examples: ["24h"] } },
          { name: "from", in: "query", schema: { type: "string", format: "date-time" } },
          { name: "to", in: "query", schema: { type: "string", format: "date-time" } },
          { name: "limit", in: "query", schema: { type: "integer", minimum: 1, maximum: 1000 } },
          { name: "cursor", in: "query", schema: { type: "string" } },
        ],
        responses: { "200": { description: "Hunt results" }, "401": { description: "Requires events:read" } },
      },
    },
    "/alerts/{id}": { get: { summary: "Get an alert", parameters: [pathId()], responses: { "200": { description: "Alert detail" }, "404": { description: "Not found" } } } },
    "/cases": { get: { summary: "List cases", parameters: [{ name: "status", in: "query", schema: { type: "string" } }, { name: "limit", in: "query", schema: { type: "integer", maximum: 100 } }], responses: { "200": { description: "Case list" } } } },
    "/cases/{id}": { get: { summary: "Get a case with tasks and timeline", parameters: [pathId()], responses: { "200": { description: "Case detail" } } } },
    "/threat-intel": { get: { summary: "Search active threat indicators", parameters: [{ name: "search", in: "query", schema: { type: "string" } }, { name: "type", in: "query", schema: { enum: ["ip", "cidr", "domain", "url", "hash", "email", "file", "cve"] } }], responses: { "200": { description: "Threat indicators" } } } },
    "/playbooks": { get: { summary: "List SOAR playbooks", responses: { "200": { description: "Playbook catalog" } } } },
    "/playbooks/{id}/runs": {
      post: {
        summary: "Preview or execute a playbook",
        description: "dryRun defaults to true. Execution requires playbooks:run. Response actions always pause for approval.",
        parameters: [pathId()],
        requestBody: { required: true, content: { "application/json": { schema: { type: "object", required: ["incidentId"], properties: { incidentId: { type: "string" }, dryRun: { type: "boolean", default: true } } } } } },
        responses: { "200": { description: "SOAR run or preview" }, "401": { description: "Missing playbook scope" } },
      },
    },
    "/playbook-runs/{id}": { get: { summary: "Get SOAR run status and actions", parameters: [pathId()], responses: { "200": { description: "SOAR run" } } } },
    "/playbook-runs/{id}/approve": {
      post: {
        summary: "Approve a gated response action",
        description: "Requires the owner-only playbooks:approve scope. Approval is audited; external dispatch still requires a configured response connector.",
        parameters: [pathId()],
        requestBody: { required: true, content: { "application/json": { schema: { type: "object", required: ["actionId", "reason"], properties: { actionId: { type: "string" }, reason: { type: "string" } } } } } },
        responses: { "200": { description: "Updated SOAR run" }, "401": { description: "Requires playbooks:approve" } },
      },
    },
  },
  components: {
    securitySchemes: { bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "tawny_* API token" } },
  },
};

export async function GET() {
  return Response.json(document, { headers: { "Cache-Control": "public, max-age=300" } });
}

function pathId() {
  return { name: "id", in: "path", required: true, schema: { type: "string" } };
}
