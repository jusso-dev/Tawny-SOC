export const apiTokenScopes = [
  { id: "ingest:write", label: "Ingest telemetry", detail: "Submit Tawny alerts and telemetry batches." },
  { id: "events:read", label: "Read events", detail: "Read retained telemetry events." },
  { id: "alerts:read", label: "Read alerts", detail: "Read alert records and search results." },
  { id: "alerts:write", label: "Write alerts", detail: "Update alert workflow state." },
  { id: "cases:read", label: "Read cases", detail: "Read case records, tasks, and timelines." },
  { id: "cases:write", label: "Write cases", detail: "Create and update incident cases." },
  { id: "detections:read", label: "Read detections", detail: "Read detection and Sigma rule state." },
  { id: "detections:write", label: "Write detections", detail: "Import, duplicate, disable, and tune detections." },
  { id: "threat-intel:read", label: "Read threat intel", detail: "Read IOC feeds and indicators." },
  { id: "threat-intel:write", label: "Write threat intel", detail: "Create feeds and sync indicators." },
  { id: "playbooks:read", label: "Read playbooks", detail: "Inspect SOAR playbooks, plans, and run history." },
  { id: "playbooks:run", label: "Run playbooks", detail: "Start SOAR runs and execute non-destructive automation." },
  { id: "playbooks:approve", label: "Approve response actions", detail: "Approve gated containment and response actions." },
  { id: "agent-rooms:read", label: "Read agent rooms", detail: "Read specialist room messages, tool traces, handoffs, and outcomes." },
  { id: "agent-rooms:write", label: "Write agent rooms", detail: "Open rooms and append attributed Hermes bot messages and trace events." },
  { id: "settings:read", label: "Read settings", detail: "Read tenant configuration and audit state." },
] as const;

export type ApiTokenScope = typeof apiTokenScopes[number]["id"];
export type ApiTokenRole = "member" | "admin" | "owner";
export type ApiTokenStatus = "active" | "revoked";

export function allowedApiTokenScopesForRole(role: ApiTokenRole): ApiTokenScope[] {
  if (role === "owner") return apiTokenScopes.map((scope) => scope.id);
  if (role === "admin") return apiTokenScopes.map((scope) => scope.id).filter((scope) => scope !== "playbooks:approve");
  return ["ingest:write", "events:read", "alerts:read", "cases:read", "threat-intel:read", "playbooks:read", "agent-rooms:read", "agent-rooms:write"];
}
