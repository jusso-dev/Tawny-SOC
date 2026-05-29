"use client";

import { RadioTower, RefreshCw, Save } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";
import { notify } from "@/components/toast-provider";
import type { ThreatIntelFeed } from "@/lib/types";

const feedTypes: ThreatIntelFeed["type"][] = ["STIX", "OpenIOC", "CSV", "TXT", "MISP", "OTX", "URLhaus", "Custom URL"];

export function ThreatFeedForm({ feeds }: { feeds: ThreatIntelFeed[] }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [busyAction, setBusyAction] = useState("");

  function submit(payload: Record<string, unknown>, key: string) {
    setBusyAction(key);
    startTransition(async () => {
      const res = await fetch("/api/soc/actions", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      const body = await res.json().catch(() => ({})) as { message?: string; error?: string };
      setBusyAction("");
      if (!res.ok) {
        notify(body.error ?? "Threat feed action failed.", "error");
        return;
      }
      notify(body.message ?? "Threat feed updated.", "success");
      router.refresh();
    });
  }

  return (
    <div className="integration-stack">
      <form className="config-form" action={(formData) => submit({
        action: "add-threat-feed",
        name: formData.get("name"),
        type: formData.get("type"),
        url: formData.get("url"),
        enabled: formData.get("enabled") === "on",
      }, "add-feed")}>
        <div className="config-form-heading">
          <div>
            <h3>Add feed</h3>
            <p>Store a feed endpoint for this tenant.</p>
          </div>
          <RadioTower size={18} aria-hidden />
        </div>
        <div className="config-grid">
          <label>
            <span>Name</span>
            <input name="name" required placeholder="Internal blocklist" />
          </label>
          <label>
            <span>Type</span>
            <select name="type" defaultValue="Custom URL">
              {feedTypes.map((type) => <option key={type} value={type}>{type}</option>)}
            </select>
          </label>
          <label>
            <span>URL</span>
            <input name="url" type="url" required placeholder="https://feeds.example.com/iocs.txt" />
          </label>
          <label className="checkbox-field">
            <input name="enabled" type="checkbox" defaultChecked />
            <span>Enable feed</span>
          </label>
        </div>
        <div className="config-actions">
          <button type="submit" disabled={pending && busyAction === "add-feed"}><Save size={15} aria-hidden /> Save feed</button>
        </div>
      </form>

      <div className="feed-list">
        {feeds.map((feed) => (
          <article key={feed.id}>
            <div className="row-split">
              <div>
                <strong>{feed.name}</strong>
                <span>{feed.type} · {feed.indicatorCount.toLocaleString()} indicators · {feed.status}</span>
                <small>{feed.url}</small>
                {feed.lastError ? <small>Error: {feed.lastError}</small> : null}
              </div>
              <button
                className="inline-action"
                type="button"
                disabled={pending && busyAction === feed.id}
                onClick={() => submit({ action: "test-threat-feed", feedId: feed.id }, feed.id)}
              >
                <RefreshCw size={14} aria-hidden /> Test and load
              </button>
            </div>
          </article>
        ))}
        {!feeds.length ? <p className="muted-copy">No threat intel feeds configured.</p> : null}
      </div>
    </div>
  );
}
