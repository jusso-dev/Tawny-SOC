"use client";

import { RefreshCw, Save, Send } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";
import { notify } from "@/components/toast-provider";
import type { IntegrationChannelSetting } from "@/lib/store";
import type { KelpieIntegrationConfig } from "@/lib/types";

export function IntegrationConfigForm({
  kelpieConfig,
  channels,
}: {
  kelpieConfig: KelpieIntegrationConfig;
  channels: IntegrationChannelSetting[];
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [busyAction, setBusyAction] = useState("");

  function submit(payload: Record<string, unknown>, label: string) {
    setBusyAction(label);
    startTransition(async () => {
      const res = await fetch("/api/soc/actions", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      const body = await res.json().catch(() => ({})) as { message?: string; error?: string };
      setBusyAction("");
      if (!res.ok) {
        notify(body.error ?? "Integration action failed.", "error");
        return;
      }
      notify(body.message ?? "Integration updated.", "success");
      router.refresh();
    });
  }

  return (
    <div className="integration-stack">
      <form className="config-form" action={(formData) => submit({
        action: "save-kelpie-config",
        baseUrl: formData.get("baseUrl"),
        tokenReference: formData.get("tokenReference"),
        enabled: formData.get("enabled") === "on",
        syncFields: formData.get("syncFields"),
      }, "kelpie-save")}>
        <div className="config-form-heading">
          <div>
            <h3>Kelpie</h3>
            <p>Alert and case promotion endpoint.</p>
          </div>
          <span className={kelpieConfig.enabled ? "status status-healthy" : "status status-watch"}>
            {kelpieConfig.enabled ? "Enabled" : "Disabled"}
          </span>
        </div>
        <div className="config-grid">
          <label>
            <span>Base URL</span>
            <input name="baseUrl" type="url" defaultValue={kelpieConfig.baseUrl} placeholder="https://kelpie.example.com" />
          </label>
          <label>
            <span>API token</span>
            <input name="tokenReference" type="password" placeholder={kelpieConfig.tokenConfigured ? "Saved, leave blank to keep" : "Paste token"} autoComplete="off" />
          </label>
          <label>
            <span>Sync fields</span>
            <input name="syncFields" defaultValue={kelpieConfig.syncFields.join(", ")} placeholder="comments, tasks, status" />
          </label>
          <label className="checkbox-field">
            <input name="enabled" type="checkbox" defaultChecked={kelpieConfig.enabled} />
            <span>Enable Kelpie sync</span>
          </label>
        </div>
        <div className="config-actions">
          <button type="submit" disabled={pending && busyAction === "kelpie-save"}><Save size={15} aria-hidden /> Save Kelpie</button>
          <button
            type="button"
            className="secondary"
            disabled={pending && busyAction === "kelpie-test"}
            onClick={() => submit({ action: "send-test-alert" }, "kelpie-test")}
          >
            <Send size={15} aria-hidden /> Test alert
          </button>
          <button
            type="button"
            className="secondary"
            disabled={pending && busyAction === "kelpie-sync"}
            onClick={() => submit({ action: "sync-stale-cases" }, "kelpie-sync")}
          >
            <RefreshCw size={15} aria-hidden /> Sync stale cases
          </button>
        </div>
      </form>

      <div className="channel-grid">
        {channels.map((channel) => (
          <form
            key={channel.channel}
            className="config-form"
            action={(formData) => submit({
              action: "save-integration-channel",
              channel: channel.channel,
              endpoint: formData.get("endpoint"),
              credential: formData.get("credential"),
              enabled: formData.get("enabled") === "on",
            }, `${channel.channel}-save`)}
          >
            <div className="config-form-heading">
              <div>
                <h3>{channelLabel(channel.channel)}</h3>
                <p>{channelCopy(channel.channel)}</p>
              </div>
              <span className={channel.enabled ? "status status-healthy" : "status status-watch"}>
                {channel.enabled ? "Enabled" : "Disabled"}
              </span>
            </div>
            <label>
              <span>Endpoint</span>
              <input name="endpoint" defaultValue={channel.endpoint} placeholder={channelPlaceholder(channel.channel)} />
            </label>
            <label>
              <span>Token or credential</span>
              <input name="credential" type="password" placeholder={channel.credentialConfigured ? "Saved, leave blank to keep" : "Paste credential"} autoComplete="off" />
            </label>
            <label className="checkbox-field">
              <input name="enabled" type="checkbox" defaultChecked={channel.enabled} />
              <span>Enable channel</span>
            </label>
            <div className="config-actions">
              <button type="submit" disabled={pending && busyAction === `${channel.channel}-save`}><Save size={15} aria-hidden /> Save</button>
              <button
                type="button"
                className="secondary"
                disabled={pending && busyAction === `${channel.channel}-test`}
                onClick={(event) => {
                  const form = event.currentTarget.form;
                  if (!form) return;
                  const formData = new FormData(form);
                  submit({
                    action: "test-integration-channel",
                    channel: channel.channel,
                    endpoint: formData.get("endpoint"),
                    credential: formData.get("credential"),
                    enabled: formData.get("enabled") === "on",
                  }, `${channel.channel}-test`);
                }}
              >
                <Send size={15} aria-hidden /> Test
              </button>
            </div>
          </form>
        ))}
      </div>
    </div>
  );
}

function channelLabel(channel: string) {
  if (channel === "sentinel") return "Microsoft Sentinel";
  return channel.slice(0, 1).toUpperCase() + channel.slice(1);
}

function channelCopy(channel: string) {
  if (channel === "email") return "SOC summary and assignment notification delivery.";
  if (channel === "slack") return "Critical and high alert forwarding.";
  if (channel === "webhook") return "Generic outbound automation calls.";
  if (channel === "sentinel") return "Forward notable events into Log Analytics.";
  return "Forward decoded Tawny events to Wazuh.";
}

function channelPlaceholder(channel: string) {
  if (channel === "email") return "https://mail-relay.example.com/send";
  if (channel === "slack") return "https://hooks.slack.com/services/...";
  if (channel === "sentinel") return "https://ingest.monitor.azure.com/...";
  if (channel === "wazuh") return "https://wazuh.example.com/api";
  return "https://automation.example.com/tawny";
}
