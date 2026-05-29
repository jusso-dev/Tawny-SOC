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
  { id: "settings:read", label: "Read settings", detail: "Read tenant configuration and audit state." },
] as const;

export type ApiTokenScope = typeof apiTokenScopes[number]["id"];
export type ApiTokenRole = "member" | "admin" | "owner";
export type ApiTokenStatus = "active" | "revoked";

export function allowedApiTokenScopesForRole(role: ApiTokenRole): ApiTokenScope[] {
  if (role === "owner" || role === "admin") return apiTokenScopes.map((scope) => scope.id);
  return ["ingest:write", "events:read", "alerts:read", "cases:read", "threat-intel:read"];
}
