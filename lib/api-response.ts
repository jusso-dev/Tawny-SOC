import type { ApiTokenScope } from "@/lib/api-token-policy";
import { authenticateApiRequest, unauthorized } from "@/lib/api-auth";

export async function withApiPrincipal<T>(
  request: Request,
  scope: ApiTokenScope,
  handler: (principal: NonNullable<Awaited<ReturnType<typeof authenticateApiRequest>>>) => Promise<T>,
) {
  const principal = await authenticateApiRequest(request, scope);
  if (!principal) return unauthorized(scope);
  try {
    return Response.json(await handler(principal));
  } catch (error) {
    const message = error instanceof Error ? error.message : "Request failed.";
    const status = /not found/i.test(message) ? 404 : /required|invalid/i.test(message) ? 400 : 500;
    return Response.json({ error: status === 500 ? "request_failed" : "invalid_request", detail: message }, { status });
  }
}
