import { listAgentPlaybooks } from "@/lib/agent-api";
import { withApiPrincipal } from "@/lib/api-response";

export async function GET(request: Request) {
  return withApiPrincipal(request, "playbooks:read", async () => ({ playbooks: listAgentPlaybooks() }));
}
