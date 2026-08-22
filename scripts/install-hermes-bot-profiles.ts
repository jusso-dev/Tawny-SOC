import { access, mkdir, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { resolve } from "node:path";
import YAML from "yaml";
import { hermesBotProfiles } from "../lib/hermes-bot-profiles";

const args = process.argv.slice(2);
const outputFlag = args.indexOf("--output");
const output = resolve(outputFlag >= 0 && args[outputFlag + 1] ? args[outputFlag + 1] : `${homedir()}/.hermes/profiles`);
const force = args.includes("--force");
const targets = hermesBotProfiles.map((profile) => ({ profile, directory: resolve(output, profile.profileId) }));

async function main() {
  if (!force) {
    const conflicts: string[] = [];
    for (const target of targets) {
      if (await exists(target.directory)) conflicts.push(target.directory);
    }
    if (conflicts.length) {
      throw new Error(`Profiles already exist. Nothing written. Re-run with --force to replace distribution-owned files only:\n${conflicts.join("\n")}`);
    }
  }

  for (const { profile, directory } of targets) {
    await mkdir(directory, { recursive: true });
    await Promise.all([
      writeFile(resolve(directory, "SOUL.md"), profile.soul, "utf8"),
      writeFile(resolve(directory, "profile.yaml"), YAML.stringify(profile.profile), "utf8"),
      writeFile(resolve(directory, "config.yaml"), YAML.stringify(profile.config), "utf8"),
      writeFile(resolve(directory, "mcp.json"), `${JSON.stringify(profile.mcp, null, 2)}\n`, "utf8"),
      writeFile(resolve(directory, "distribution.yaml"), YAML.stringify(profile.distribution), "utf8"),
      writeFile(resolve(directory, ".env.EXAMPLE"), profile.envExample, "utf8"),
    ]);
  }

  process.stdout.write(`${JSON.stringify({ output, profiles: targets.map((target) => target.profile.profileId) }, null, 2)}\n`);
}

void main();

async function exists(path: string) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}
