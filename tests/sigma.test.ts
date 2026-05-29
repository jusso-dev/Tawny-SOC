import { describe, expect, it } from "vitest";
import { parseSigmaRule, ruleMatchesPayload } from "../lib/sigma";

describe("Sigma import", () => {
  it("parses Sigma YAML and matches generic selections", () => {
    const rule = parseSigmaRule(`title: Suspicious PowerShell Download
id: tawny-custom-powershell-download
status: test
description: Detects PowerShell downloading remote content.
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - powershell
      - downloadstring
  condition: selection
level: high
tags:
  - attack.t1059.001`);

    expect(rule.id).toBe("tawny-custom-powershell-download");
    expect(rule.severity).toBe("high");
    expect(rule.mitreTechniques).toEqual(["T1059.001"]);
    expect(ruleMatchesPayload(rule, { CommandLine: "powershell.exe -c downloadstring('http://example')" })).toBe(true);
  });

  it("rejects YAML without a detection block", () => {
    expect(() => parseSigmaRule("title: Missing Detection")).toThrow("detection block");
  });
});
