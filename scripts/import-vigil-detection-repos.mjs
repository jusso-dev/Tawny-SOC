#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import path from "node:path";

const target = process.argv[2] ?? path.join(process.cwd(), "data", "detections", "external");
const repos = [
  ["sigma", "https://github.com/SigmaHQ/sigma.git"],
  ["security_content", "https://github.com/splunk/security_content.git"],
  ["elastic_detection_rules", "https://github.com/elastic/detection-rules.git"],
  ["kql_hunting_queries", "https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules.git"],
];

mkdirSync(target, { recursive: true });

for (const [name, url] of repos) {
  const destination = path.join(target, name);
  const args = ["clone", "--depth", "1", url, destination];
  console.log(`Cloning ${name} into ${destination}`);
  const result = spawnSync("git", args, { stdio: "inherit" });
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

console.log("Detection repositories imported. Point a future indexer at data/detections/external.");
