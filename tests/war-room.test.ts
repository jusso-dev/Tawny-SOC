import { afterEach, describe, expect, it, vi } from "vitest";
import { getWorldViewData } from "../lib/cloudflare-radar";
import { agentWorkflows } from "../lib/agent-workflows";
import { socAgentIds, socAgentProfiles } from "../lib/ai/agents/catalog";
import { buildSpecialistPrompt, deterministicSpecialist } from "../lib/ai/agents/specialist";
import { UNTRUSTED_DATA_GUARDRAIL } from "../lib/ai/agents/shared";
import { cronMatches } from "../lib/war-room";
import type { SocAlert } from "../lib/types";

const alert = {
  id: "alert-1", source: "tawny", kind: "alert", title: "Remote sign-in", severity: "high", status: "open",
  timestamp: "2026-08-21T00:00:00.000Z", tenantId: "tenant-a", hostname: "entra-id",
  payload: { alert: { source_country: "US", source_country_name: "United States" } }, matchedRules: [], mitreTechniques: [],
  confidence: 0.9, aiSummary: "Remote sign-in", recommendedPlaybook: "incident-response",
} satisfies SocAlert;

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe("proactive hunt schedules", () => {
  it("matches five-field cron expressions in the schedule timezone", () => {
    const instant = new Date("2026-08-20T23:00:00.000Z");
    expect(cronMatches("0 9 * * 5", "Australia/Sydney", instant)).toBe(true);
    expect(cronMatches("15 9 * * 5", "Australia/Sydney", instant)).toBe(false);
  });

  it("supports step and range fields used by the hunt presets", () => {
    const instant = new Date("2026-08-21T00:30:00.000Z");
    expect(cronMatches("*/15 * * * *", "UTC", instant)).toBe(true);
    expect(cronMatches("0 9 * * 1-5", "UTC", instant)).toBe(false);
  });
});

describe("specialist agent workflows", () => {
  it("publishes 13 unique SOC specialists with scoped tools and methodology", () => {
    expect(socAgentProfiles).toHaveLength(13);
    expect(new Set(socAgentProfiles.map((agent) => agent.id)).size).toBe(13);
    expect(socAgentProfiles.map((agent) => agent.id)).toEqual(socAgentIds);
    expect(socAgentProfiles.every((agent) => agent.tools.length > 0 && agent.methodology.length > 0)).toBe(true);
  });

  it("defines reusable workflows using only registered agents and explicit phases", () => {
    expect(agentWorkflows.map((workflow) => workflow.id)).toEqual(expect.arrayContaining(["incident-response", "full-investigation", "threat-hunt", "forensic-analysis"]));
    expect(agentWorkflows.every((workflow) => workflow.phases.length >= 3)).toBe(true);
    expect(agentWorkflows.flatMap((workflow) => workflow.phases).every((phase) => socAgentIds.includes(phase.agent) && phase.tools.length > 0)).toBe(true);
    expect(agentWorkflows.find((workflow) => workflow.id === "full-investigation")?.phases.map((phase) => phase.agent)).toEqual(["investigator", "mitre_analyst", "correlator", "responder", "reporter"]);
  });

  it("keeps deterministic containment outputs approval-gated", () => {
    const workflow = agentWorkflows.find((item) => item.id === "autonomous-containment")!;
    const phase = workflow.phases.find((item) => item.agent === "auto_responder")!;
    const result = deterministicSpecialist("auto_responder", phase, { alert, relatedSignals: [], matchedRules: [], indicators: [], priorSteps: [] });
    expect(result.actions.every((action) => action.startsWith("Approval required:"))).toBe(true);
    expect(result.evidence).toContain(alert.id);
  });

  it("gives every specialist phase scoped tools, prior handoffs, and the telemetry guardrail", () => {
    const phase = agentWorkflows.find((item) => item.id === "full-investigation")!.phases[1];
    const prompt = buildSpecialistPrompt(phase.agent, phase, { alert, relatedSignals: [], matchedRules: [], indicators: [], priorSteps: [{ agent: "Investigation Agent", summary: "timeline built", evidence: [alert.id], actions: ["handoff"] }] });
    expect(prompt[0].content).toContain(UNTRUSTED_DATA_GUARDRAIL);
    expect(prompt[0].content).toContain(phase.tools[0]);
    expect(prompt[1].content).toContain("timeline built");
  });
});

describe("Cloudflare Radar world view", () => {
  it("keeps tenant geo signals visible when Radar is not configured", async () => {
    vi.stubEnv("CLOUDFLARE_RADAR_API_TOKEN", "");
    const result = await getWorldViewData([alert]);
    expect(result.status).toBe("not_configured");
    expect(result.signals[0]).toMatchObject({ originCode: "US", targetCode: "AU", source: "tawny" });
  });

  it("merges live Radar attack pairs without relabeling tenant evidence", async () => {
    vi.stubEnv("CLOUDFLARE_RADAR_API_TOKEN", "radar-token");
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({
      success: true,
      result: { meta: { lastUpdated: "2026-08-21T00:00:00.000Z" }, top_0: [{ originCountryAlpha2: "DE", originCountryName: "Germany", targetCountryAlpha2: "AU", targetCountryName: "Australia", value: "4.25" }] },
    }), { status: 200 })));
    const result = await getWorldViewData([alert]);
    expect(result.status).toBe("live");
    expect(result.signals).toHaveLength(2);
    expect(result.signals.map((signal) => signal.source)).toEqual(["tawny", "cloudflare-radar"]);
  });
});
