import { describe, expect, it } from "vitest";
import { isPublic } from "../proxy";

describe("session proxy API boundaries", () => {
  it("lets bearer-authenticated agent routes reach their own scope checks", () => {
    expect(isPublic("/api/mcp")).toBe(true);
    expect(isPublic("/api/v1")).toBe(true);
    expect(isPublic("/api/v1/agent-rooms")).toBe(true);
  });

  it("still protects browser application routes", () => {
    expect(isPublic("/war-room")).toBe(false);
    expect(isPublic("/settings/api-tokens")).toBe(false);
  });
});
