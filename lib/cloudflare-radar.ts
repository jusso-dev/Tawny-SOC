import type { SocAlert } from "@/lib/types";

export type WorldSignal = {
  id: string;
  originCode: string;
  originName: string;
  targetCode: string;
  targetName: string;
  value: number;
  source: "cloudflare-radar" | "tawny";
  label: string;
};

export type WorldViewData = {
  configured: boolean;
  status: "live" | "degraded" | "not_configured";
  lastUpdated?: string;
  error?: string;
  signals: WorldSignal[];
};

type RadarResponse = {
  success?: boolean;
  result?: {
    meta?: { lastUpdated?: string };
    top_0?: Array<{
      originCountryAlpha2?: string;
      originCountryName?: string;
      targetCountryAlpha2?: string;
      targetCountryName?: string;
      value?: string;
    }>;
  };
  errors?: Array<{ message?: string }>;
};

export async function getWorldViewData(alerts: SocAlert[]): Promise<WorldViewData> {
  const localSignals = buildLocalSignals(alerts);
  const token = process.env.CLOUDFLARE_RADAR_API_TOKEN?.trim();
  if (!token) return { configured: false, status: "not_configured", signals: localSignals };

  try {
    const url = new URL("https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/attacks");
    url.searchParams.set("dateRange", "1d");
    url.searchParams.set("limit", "12");
    url.searchParams.set("normalization", "PERCENTAGE");
    const response = await fetch(url, {
      headers: { authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(8_000),
      next: { revalidate: 900 },
    });
    const body = await response.json().catch(() => ({})) as RadarResponse;
    if (!response.ok || !body.success) throw new Error(body.errors?.[0]?.message ?? `Cloudflare Radar returned HTTP ${response.status}.`);
    const radarSignals = (body.result?.top_0 ?? []).flatMap((item, index): WorldSignal[] => {
      if (!item.originCountryAlpha2 || !item.targetCountryAlpha2) return [];
      return [{
        id: `radar-${index}-${item.originCountryAlpha2}-${item.targetCountryAlpha2}`,
        originCode: item.originCountryAlpha2,
        originName: item.originCountryName ?? item.originCountryAlpha2,
        targetCode: item.targetCountryAlpha2,
        targetName: item.targetCountryName ?? item.targetCountryAlpha2,
        value: Number(item.value ?? 0),
        source: "cloudflare-radar",
        label: "Layer 7 mitigated request share",
      }];
    });
    return { configured: true, status: "live", lastUpdated: body.result?.meta?.lastUpdated, signals: [...localSignals, ...radarSignals] };
  } catch (error) {
    return { configured: true, status: "degraded", error: error instanceof Error ? error.message : "Cloudflare Radar request failed.", signals: localSignals };
  }
}

function buildLocalSignals(alerts: SocAlert[]): WorldSignal[] {
  return alerts.flatMap((alert): WorldSignal[] => {
    const payload = alert.payload && typeof alert.payload === "object" ? alert.payload as Record<string, unknown> : {};
    const nested = payload.alert && typeof payload.alert === "object" ? payload.alert as Record<string, unknown> : payload;
    const originCode = readString(nested, ["source_country", "sourceCountry", "country", "country_code"]);
    const originName = readString(nested, ["source_country_name", "sourceCountryName", "country_name"]) || originCode;
    if (!originCode || originCode.length !== 2) return [];
    return [{
      id: `tawny-${alert.id}`,
      originCode: originCode.toUpperCase(),
      originName,
      targetCode: "AU",
      targetName: "Australia",
      value: Math.round(alert.confidence * 100),
      source: "tawny",
      label: alert.title,
    }];
  }).slice(0, 20);
}

function readString(record: Record<string, unknown>, keys: string[]) {
  for (const key of keys) if (typeof record[key] === "string") return String(record[key]).trim();
  return "";
}

export const countryPoints: Record<string, { x: number; y: number }> = {
  AU: { x: 83, y: 75 }, BR: { x: 34, y: 68 }, CA: { x: 18, y: 24 }, CN: { x: 75, y: 40 },
  DE: { x: 52, y: 31 }, FR: { x: 49, y: 35 }, GB: { x: 47, y: 28 }, ID: { x: 78, y: 62 },
  IN: { x: 68, y: 50 }, JP: { x: 87, y: 41 }, NL: { x: 50, y: 29 }, RU: { x: 70, y: 23 },
  SG: { x: 75, y: 58 }, UA: { x: 58, y: 32 }, US: { x: 20, y: 38 }, ZA: { x: 55, y: 75 },
};
