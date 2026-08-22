import { withApiPrincipal } from "@/lib/api-response";
import { listAgentWorkflows } from "@/lib/war-room";

export async function GET(request: Request) {
  return withApiPrincipal(request, "playbooks:read", async () => ({ workflows: listAgentWorkflows() }));
}
