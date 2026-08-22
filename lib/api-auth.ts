import type { ApiTokenRole, ApiTokenScope } from "@/lib/api-token-policy";
import { getSession } from "@/lib/session";
import { validateApiToken } from "@/lib/store";

export type ApiPrincipal = {
  id: string;
  name: string;
  tenantId: string;
  role: ApiTokenRole | "session";
  scopes: ApiTokenScope[];
  authType: "bearer" | "session";
};

export async function authenticateApiRequest(
  request: Request,
  requiredScope?: ApiTokenScope,
  options: { allowSession?: boolean } = {},
): Promise<ApiPrincipal | null> {
  const secret = bearerToken(request);
  if (secret) {
    const token = await validateApiToken(secret, requiredScope);
    if (!token) return null;
    return {
      id: token.id,
      name: token.name,
      tenantId: token.tenantId,
      role: token.role,
      scopes: token.scopes,
      authType: "bearer",
    };
  }

  if (!options.allowSession) return null;
  const session = await getSession();
  if (!session) return null;
  return {
    id: session.user.id,
    name: session.user.name || session.user.email,
    tenantId: sessionTenantId(session),
    role: "session",
    scopes: [],
    authType: "session",
  };
}

export function bearerToken(request: Request) {
  const authorization = request.headers.get("authorization") ?? "";
  return authorization.startsWith("Bearer ") ? authorization.slice("Bearer ".length).trim() : "";
}

export function hasScope(principal: ApiPrincipal, scope: ApiTokenScope) {
  return principal.authType === "session" || principal.scopes.includes(scope);
}

export function sessionTenantId(session: Awaited<ReturnType<typeof getSession>>) {
  if (!session) return "local-tenant";
  return (session.session as { activeOrganizationId?: string | null }).activeOrganizationId ?? "local-tenant";
}

export function unauthorized(scope?: ApiTokenScope) {
  return Response.json(
    { error: "unauthorized", requiredScope: scope },
    {
      status: 401,
      headers: { "WWW-Authenticate": `Bearer${scope ? ` scope="${scope}"` : ""}` },
    },
  );
}
