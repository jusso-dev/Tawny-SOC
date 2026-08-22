import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { chromium } from "@playwright/test";

const baseUrl = process.env.SCREENSHOT_URL ?? "http://localhost:3001";
const captures = [
  { path: "/war-room", heading: "Specialists investigate. Analysts command.", output: "docs/screenshots/ai-war-room.png" },
  { path: "/world", heading: "See attack pressure outside your perimeter.", output: "docs/screenshots/world-view.png" },
  { path: "/", heading: "Endpoint signals, ready for triage.", output: "docs/screenshots/soc-overview.png" },
];

async function main() {
  mkdirSync(dirname(resolve(captures[0].output)), { recursive: true });
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1600, height: 1000 }, deviceScaleFactor: 1 });
    await page.goto(`${baseUrl}/sign-in?next=${encodeURIComponent(captures[0].path)}`, { waitUntil: "networkidle" });
    await page.getByLabel("Email").fill(process.env.SCREENSHOT_EMAIL ?? "analyst@tawny.local");
    await page.getByLabel("Password").fill(process.env.SCREENSHOT_PASSWORD ?? "TawnySocLocal123!");
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await page.getByRole("heading", { name: captures[0].heading }).waitFor();

    for (const capture of captures) {
      await page.goto(`${baseUrl}${capture.path}`, { waitUntil: "networkidle" });
      await page.getByRole("heading", { name: capture.heading }).waitFor();
      await page.screenshot({ path: resolve(capture.output), fullPage: false });
    }
  } finally {
    await browser.close();
  }
}

void main();
