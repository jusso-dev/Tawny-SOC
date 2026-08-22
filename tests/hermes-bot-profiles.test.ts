import { describe, expect, it } from "vitest";
import { hermesBotProfiles } from "../lib/hermes-bot-profiles";
import { socAgentIds } from "../lib/ai/agents/catalog";

describe("Hermes Bot Mode profiles", () => {
  it("builds one Bot Mode-managed profile and unique SOUL.md for every SOC specialist", () => {
    expect(hermesBotProfiles).toHaveLength(13);
    expect(hermesBotProfiles.map((profile) => profile.agentId)).toEqual(socAgentIds);
    expect(new Set(hermesBotProfiles.map((profile) => profile.profileId)).size).toBe(13);
    expect(new Set(hermesBotProfiles.map((profile) => profile.soul)).size).toBe(13);
    for (const profile of hermesBotProfiles) {
      expect(profile.profile).toMatchObject({ ui_meta: { "hermes-bots": { title: profile.displayName } } });
      expect(profile.config).toMatchObject({
        agent: { bot_mode_protocol: true },
        model: { provider: "openai-codex", default: "gpt-5.6-luna" },
      });
      expect(profile.soul).toContain(`agentId: "${profile.agentId}"`);
      expect(profile.soul).toContain("message_agent");
      expect(profile.soul).toContain("tawny_post_agent_message");
    }
  });

  it("gives every profile room tools, scoped MCP transport, and no response approval tool", () => {
    for (const profile of hermesBotProfiles) {
      const server = (profile.config.mcp_servers as { tawny_soc: { url: string; tools: { include: string[] } } }).tawny_soc;
      expect(server.url).toBe("${TAWNY_SOC_MCP_URL}");
      expect(server.tools.include).toEqual(expect.arrayContaining([
        "tawny_open_agent_room",
        "tawny_get_agent_room",
        "tawny_post_agent_message",
        "tawny_close_agent_room",
      ]));
      expect(server.tools.include).not.toContain("tawny_approve_response");
      expect(profile.distribution).toMatchObject({ env_requires: expect.arrayContaining([expect.objectContaining({ name: "TAWNY_SOC_TOKEN", required: true })]) });
    }
  });
});
