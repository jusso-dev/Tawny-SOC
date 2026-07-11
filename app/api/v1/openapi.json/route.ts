const document = {
  openapi: "3.1.0",
  info: {
    title: "Tawny-SOC Agent API",
    version: "1.0.0",
    description: "Tenant-scoped threat hunting, investigation context, threat intelligence, and approval-gated SOAR automation for coding agents.",
  },
  servers: [{ url: "/api/v1" }],
  security: [{ bearerAuth: [] }],
  paths: {
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
