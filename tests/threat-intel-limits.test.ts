import { describe, expect, it } from "vitest";
import {
  MAX_THREAT_INTEL_VALUE_BYTES,
  isIndexableThreatIntelValue,
} from "../lib/threat-intel-limits";

describe("threat-intelligence indicator limits", () => {
  it("accepts index-safe values", () => {
    expect(isIndexableThreatIntelValue("example.com")).toBe(true);
    expect(
      isIndexableThreatIntelValue("a".repeat(MAX_THREAT_INTEL_VALUE_BYTES)),
    ).toBe(true);
  });

  it("rejects blank and oversized values", () => {
    expect(isIndexableThreatIntelValue("  ")).toBe(false);
    expect(
      isIndexableThreatIntelValue(
        "a".repeat(MAX_THREAT_INTEL_VALUE_BYTES + 1),
      ),
    ).toBe(false);
    expect(
      isIndexableThreatIntelValue(
        "🛡".repeat(MAX_THREAT_INTEL_VALUE_BYTES / 4 + 1),
      ),
    ).toBe(false);
    expect(
      isIndexableThreatIntelValue(
        `example.com${" ".repeat(MAX_THREAT_INTEL_VALUE_BYTES)}`,
      ),
    ).toBe(false);
  });
});
