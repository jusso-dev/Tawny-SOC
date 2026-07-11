import { authenticateApiRequest } from "@/lib/api-auth";
import { handleMcpMessage, MCP_SUPPORTED_VERSIONS } from "@/lib/mcp-server";

export async function POST(request: Request) {
  if (!validOrigin(request)) {
    return Response.json({ jsonrpc: "2.0", id: null, error: { code: -32000, message: "Origin not allowed" } }, { status: 403 });
  }
  const protocolVersion = request.headers.get("mcp-protocol-version");
  if (protocolVersion && !MCP_SUPPORTED_VERSIONS.includes(protocolVersion)) {
    return Response.json({ jsonrpc: "2.0", id: null, error: { code: -32602, message: "Unsupported MCP protocol version" } }, { status: 400 });
  }
  const principal = await authenticateApiRequest(request);
  if (!principal) {
    return Response.json(
      { jsonrpc: "2.0", id: null, error: { code: -32001, message: "Bearer API token required" } },
      { status: 401, headers: { "WWW-Authenticate": "Bearer" } },
    );
  }
  const body = await request.json().catch(() => null);
  const response = await handleMcpMessage(body, principal);
  if (!response) return new Response(null, { status: 202 });
  return Response.json(response, { headers: { "Cache-Control": "no-store" } });
}

export async function GET() {
  return Response.json({ error: "SSE listen streams are not enabled; use Streamable HTTP POST requests." }, { status: 405, headers: { Allow: "POST" } });
}

export async function DELETE() {
  return new Response(null, { status: 405, headers: { Allow: "POST" } });
}

function validOrigin(request: Request) {
  const origin = request.headers.get("origin");
  if (!origin) return true;
  const configured = [
    new URL(request.url).origin,
    process.env.NEXT_PUBLIC_APP_URL,
    process.env.BETTER_AUTH_URL,
    ...(process.env.MCP_ALLOWED_ORIGINS ?? "").split(","),
  ].filter((value): value is string => Boolean(value)).map((value) => value.replace(/\/$/, ""));
  return configured.includes(origin.replace(/\/$/, ""));
}
