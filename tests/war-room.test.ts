import { afterEach, describe, expect, it, vi } from "vitest";
import { getWorldViewData } from "../lib/cloudflare-radar";
import { cronMatches } from "../lib/war-room";
import type { SocAlert } from "../lib/types";

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

describe("Cloudflare Radar world view", () => {
  const alert = {
    id: "alert-1", source: "tawny", kind: "alert", title: "Remote sign-in", severity: "high", status: "open",
    timestamp: "2026-08-21T00:00:00.000Z", tenantId: "tenant-a", hostname: "entra-id",
    payload: { alert: { source_country: "US", source_country_name: "United States" } }, matchedRules: [], mitreTechniques: [],
    confidence: 0.9, aiSummary: "Remote sign-in", recommendedPlaybook: "incident-response",
  } satisfies SocAlert;

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
