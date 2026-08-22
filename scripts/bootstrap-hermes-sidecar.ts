import { randomUUID } from "node:crypto";
import { access, chmod, chown, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import YAML from "yaml";
import type { ApiTokenScope } from "../lib/api-token-policy";
import { hermesBotProfiles } from "../lib/hermes-bot-profiles";
import { createApiToken, validateApiToken } from "../lib/store";

const dataDirectory = resolve(process.env.TAWNY_HERMES_DATA_DIR ?? "/opt/hermes-data");
const tenantId = process.env.TAWNY_HERMES_TENANT_ID?.trim() || "local-tenant";
const mcpUrl = process.env.TAWNY_SOC_MCP_URL?.trim() || "http://app:3001/api/mcp";
const ownerUid = optionalNumericEnv("TAWNY_HERMES_UID");
const ownerGid = optionalNumericEnv("TAWNY_HERMES_GID") ?? ownerUid;
const tokenScopes: ApiTokenScope[] = [
  "events:read",
  "alerts:read",
  "cases:read",
  "threat-intel:read",
  "playbooks:read",
  "agent-rooms:read",
  "agent-rooms:write",
];

async function main() {
  await ensureDirectory(dataDirectory);
  await ensureDirectory(resolve(dataDirectory, "profiles"));
  await atomicWrite(resolve(dataDirectory, "config.yaml"), YAML.stringify({
    model: {
      default: "gpt-5.6-luna",
      provider: "openai-codex",
      base_url: "https://chatgpt.com/backend-api/codex",
    },
  }));

  const results: Array<{ profileId: string; token: "created" | "reused" }> = [];
  for (const profile of hermesBotProfiles) {
    const directory = resolve(dataDirectory, "profiles", profile.profileId);
    const envPath = resolve(directory, ".env");
    const tokenName = `Hermes bot ${profile.profileId}`;
    await ensureDirectory(directory);

    const existingSecret = await readEnvValue(envPath, "TAWNY_SOC_TOKEN");
    const existing = existingSecret ? await validateApiToken(existingSecret, "agent-rooms:write") : null;
    const reusable = existing?.tenantId === tenantId && existing.name === tokenName;
    const secret = reusable
      ? existingSecret
      : (await createApiToken({ tenantId, name: tokenName, role: "member", scopes: tokenScopes })).token;

    await Promise.all([
      atomicWrite(resolve(directory, "SOUL.md"), profile.soul),
      atomicWrite(resolve(directory, "profile.yaml"), YAML.stringify(profile.profile)),
      atomicWrite(resolve(directory, "config.yaml"), YAML.stringify(profile.config)),
      atomicWrite(resolve(directory, "mcp.json"), `${JSON.stringify(profile.mcp, null, 2)}\n`),
      atomicWrite(resolve(directory, "distribution.yaml"), YAML.stringify(profile.distribution)),
      atomicWrite(resolve(directory, ".env"), `TAWNY_SOC_MCP_URL=${mcpUrl}\nTAWNY_SOC_TOKEN=${secret}\n`, 0o600),
    ]);
    const gatewayStatePath = resolve(directory, "gateway_state.json");
    if (!(await exists(gatewayStatePath))) {
      await atomicWrite(gatewayStatePath, `${JSON.stringify({
        desired_state: "running",
        updated_at: new Date().toISOString(),
        platforms: {},
        kind: "hermes-gateway",
      })}\n`);
    }
    results.push({ profileId: profile.profileId, token: reusable ? "reused" : "created" });
  }

  process.stdout.write(`${JSON.stringify({ dataDirectory, tenantId, profiles: results }, null, 2)}\n`);
}

async function readEnvValue(path: string, key: string) {
  try {
    const content = await readFile(path, "utf8");
    const line = content.split(/\r?\n/).find((candidate) => candidate.startsWith(`${key}=`));
    return line?.slice(key.length + 1).trim() || "";
  } catch {
    return "";
  }
}

async function atomicWrite(path: string, content: string, mode = 0o644) {
  const temporaryPath = `${path}.${randomUUID()}.tmp`;
  await writeFile(temporaryPath, content, { encoding: "utf8", mode });
  await chmod(temporaryPath, mode);
  if (ownerUid !== undefined && ownerGid !== undefined) await chown(temporaryPath, ownerUid, ownerGid);
  await rename(temporaryPath, path);
}

async function ensureDirectory(path: string) {
  await mkdir(path, { recursive: true });
  if (ownerUid !== undefined && ownerGid !== undefined) await chown(path, ownerUid, ownerGid);
}

function optionalNumericEnv(name: string) {
  const value = process.env[name]?.trim();
  if (!value) return undefined;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) throw new Error(`${name} must be a non-negative integer.`);
  return parsed;
}

async function exists(path: string) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

void main();
