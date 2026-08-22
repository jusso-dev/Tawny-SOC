import { authenticateApiRequest, unauthorized } from "@/lib/api-auth";
import { getAgentRoom } from "@/lib/war-room";

export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const principal = await authenticateApiRequest(request, "agent-rooms:read");
  if (!principal) return unauthorized("agent-rooms:read");
  const { id } = await params;
  try {
    return Response.json({ room: await getAgentRoom(principal.tenantId, id) });
  } catch {
    return Response.json({ error: "not_found", detail: "Agent room not found." }, { status: 404 });
  }
}
