import { withApiPrincipal } from "@/lib/api-response";
import { listSocAgents } from "@/lib/war-room";

export async function GET(request: Request) {
  return withApiPrincipal(request, "alerts:read", async () => ({ agents: listSocAgents() }));
}
