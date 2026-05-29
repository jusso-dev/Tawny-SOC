import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import YAML from "yaml";
import { sigmaRules as builtinSigmaRules } from "./rules";
import type { Severity, SigmaRule } from "./types";

const runtimeDir = path.join(process.cwd(), "data", "runtime");
const customRulesPath = path.join(runtimeDir, "custom-rules.json");
const disabledRulesPath = path.join(runtimeDir, "disabled-rules.json");

type RawSigma = {
  id?: string;
  title?: string;
  status?: string;
  description?: string;
  logsource?: {
    product?: string;
    category?: string;
    service?: string;
  };
  detection?: Record<string, unknown>;
  level?: string;
  tags?: string[];
  falsepositives?: string[];
  false_positives?: string[];
};

async function readJson<T>(filePath: string, fallback: T): Promise<T> {
  try {
    const raw = await readFile(filePath, "utf8");
    return JSON.parse(raw) as T;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return fallback;
    throw err;
  }
}

async function writeJson<T>(filePath: string, value: T) {
  await mkdir(runtimeDir, { recursive: true });
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

export async function listSigmaRules() {
  const [customRules, disabledRuleIds] = await Promise.all([
    readJson<SigmaRule[]>(customRulesPath, []),
    readJson<string[]>(disabledRulesPath, []),
  ]);
  const disabled = new Set(disabledRuleIds);
  const byId = new Map<string, SigmaRule>();
  for (const rule of [...builtinSigmaRules, ...customRules]) {
    if (!disabled.has(rule.id)) byId.set(rule.id, rule);
  }
  return [...byId.values()];
}

export async function getSigmaRule(ruleId: string) {
  return (await listSigmaRules()).find((rule) => rule.id === ruleId);
}

export async function importSigmaRule(sigma: string) {
  const rule = parseSigmaRule(sigma);
  const customRules = await readJson<SigmaRule[]>(customRulesPath, []);
  const nextRules = [rule, ...customRules.filter((item) => item.id !== rule.id)];
  await writeJson(customRulesPath, nextRules);
  return rule;
}

export async function duplicateSigmaRule(ruleId: string) {
  const source = await getSigmaRule(ruleId);
  if (!source) throw new Error("Rule not found.");
  const copyId = `${source.id}-copy-${Date.now()}`;
  const copy: SigmaRule = {
    ...source,
    id: copyId,
    title: `${source.title} copy`,
    status: "test",
    source: "Duplicated in Tawny-SOC",
    sigma: source.sigma.replace(/^id: .+$/m, `id: ${copyId}`),
  };
  const customRules = await readJson<SigmaRule[]>(customRulesPath, []);
  await writeJson(customRulesPath, [copy, ...customRules]);
  return copy;
}

export async function disableSigmaRule(ruleId: string) {
  const disabledRuleIds = await readJson<string[]>(disabledRulesPath, []);
  if (!disabledRuleIds.includes(ruleId)) await writeJson(disabledRulesPath, [...disabledRuleIds, ruleId]);
}

export function parseSigmaRule(sigma: string): SigmaRule {
  const raw = YAML.parse(sigma) as RawSigma | null;
  if (!raw || typeof raw !== "object") throw new Error("Sigma YAML must be an object.");
  const id = cleanId(raw.id ?? raw.title);
  const title = cleanText(raw.title, "Imported Sigma rule");
  const detection = raw.detection && typeof raw.detection === "object" ? raw.detection : undefined;
  if (!detection || !Object.keys(detection).length) throw new Error("Sigma rule must include a detection block.");

  return {
    id,
    title,
    status: normalizeStatus(raw.status),
    severity: normalizeSigmaSeverity(raw.level),
    source: "Imported Sigma rule",
    logsource: {
      product: cleanText(raw.logsource?.product, "unknown"),
      category: raw.logsource?.category,
      service: raw.logsource?.service,
    },
    mitreTechniques: extractMitre(raw.tags ?? []),
    tags: raw.tags ?? [],
    description: cleanText(raw.description, "Imported Sigma detection."),
    falsePositives: raw.falsepositives ?? raw.false_positives ?? [],
    detection,
    sigma,
  };
}

export function ruleMatchesPayload(rule: SigmaRule, payload: unknown, eventType?: string, explicitRuleId?: string) {
  if (explicitRuleId && rule.id === explicitRuleId) return true;
  const haystack = `${payloadText(payload)} ${String(eventType ?? "").toLowerCase()}`;

  if (rule.id.includes("ps-encoded-command")) {
    return /powershell|pwsh/.test(haystack) && /-enc|-encodedcommand|\/encodedcommand/.test(haystack);
  }
  if (rule.id.includes("lolbin-mshta")) {
    return haystack.includes("mshta") && /http:\/\/|https:\/\/|javascript:|vbscript:/.test(haystack);
  }
  if (rule.id.includes("curl-pipe")) {
    return /(curl|wget).*(\|\s*(sh|bash|python))/.test(haystack);
  }
  if (rule.id.includes("launch-agent")) {
    return /launchagents|launchdaemons|\/library\/launch/.test(haystack);
  }
  if (rule.id.includes("dns-dga")) {
    return /\b[a-z0-9]{22,}\.[a-z]{2,}\b/.test(haystack);
  }
  if (rule.id.includes("credential-dump")) {
    return /lsass|procdump|sekurlsa::|minidump|comsvcs\.dll/.test(haystack);
  }

  return matchGenericSigma(rule, haystack);
}

function matchGenericSigma(rule: SigmaRule, haystack: string) {
  const condition = String(rule.detection.condition ?? "");
  const selections = Object.entries(rule.detection).filter(([key]) => key !== "condition");
  if (!selections.length) return false;

  const results = new Map(selections.map(([key, value]) => [key, selectionMatches(value, haystack)]));
  const referenced = [...results.keys()].filter((key) => condition.includes(key));
  if (!condition || !referenced.length) return [...results.values()].some(Boolean);
  if (condition.includes(" and ")) return referenced.every((key) => results.get(key));
  if (condition.includes(" or ")) return referenced.some((key) => results.get(key));
  return referenced.every((key) => results.get(key));
}

function selectionMatches(value: unknown, haystack: string): boolean {
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return valueMatches(String(value), haystack);
  }
  if (Array.isArray(value)) return value.some((item) => selectionMatches(item, haystack));
  if (value && typeof value === "object") {
    return Object.entries(value).some(([key, child]) => {
      if (key.toLowerCase().includes("|re")) return regexValues(child).some((pattern) => safeRegex(pattern).test(haystack));
      return selectionMatches(child, haystack);
    });
  }
  return false;
}

function valueMatches(value: string, haystack: string) {
  const normalized = value.toLowerCase();
  if (!normalized) return false;
  if (normalized.startsWith("regex:")) return safeRegex(normalized.slice(6)).test(haystack);
  if (normalized.includes("*") || normalized.includes("?")) {
    const expression = normalized
      .replace(/[.+^${}()|[\]\\]/g, "\\$&")
      .replace(/\*/g, ".*")
      .replace(/\?/g, ".");
    return new RegExp(expression, "i").test(haystack);
  }
  return haystack.includes(normalized);
}

function regexValues(value: unknown): string[] {
  if (Array.isArray(value)) return value.flatMap(regexValues);
  if (typeof value === "string") return [value];
  return [];
}

function safeRegex(pattern: string) {
  try {
    return new RegExp(pattern, "i");
  } catch {
    return /$a/;
  }
}

function payloadText(payload: unknown) {
  if (typeof payload === "string") return payload.toLowerCase();
  try {
    return JSON.stringify(payload).toLowerCase();
  } catch {
    return "";
  }
}

function normalizeSigmaSeverity(value: unknown): Severity {
  const normalized = String(value ?? "low").toLowerCase();
  if (normalized === "critical" || normalized === "high" || normalized === "medium" || normalized === "low") return normalized;
  if (normalized === "informational") return "low";
  return "low";
}

function normalizeStatus(value: unknown): SigmaRule["status"] {
  const normalized = String(value ?? "test").toLowerCase();
  if (normalized === "stable" || normalized === "test" || normalized === "experimental") return normalized;
  return "test";
}

function cleanText(value: unknown, fallback: string) {
  const text = typeof value === "string" ? value.trim() : "";
  return text || fallback;
}

function cleanId(value: unknown) {
  const text = cleanText(value, `imported-sigma-${Date.now()}`);
  return text.toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^-|-$/g, "");
}

function extractMitre(tags: string[]) {
  return tags
    .map((tag) => tag.match(/attack\.t(\d{4}(?:\.\d{3})?)/i)?.[1])
    .filter((value): value is string => Boolean(value))
    .map((value) => `T${value}`);
}
