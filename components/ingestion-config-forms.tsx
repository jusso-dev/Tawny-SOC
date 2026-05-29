"use client";

import { Save, Send } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";
import { notify } from "@/components/toast-provider";
import type { ConnectorCatalogItem } from "@/lib/connectors";
import type { ConnectorInstance, IngestSourceSetting } from "@/lib/store";

export function IngestionConfigForms({
  catalog,
  connectors,
  sources,
}: {
  catalog: ConnectorCatalogItem[];
  connectors: ConnectorInstance[];
  sources: IngestSourceSetting[];
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [busy, setBusy] = useState("");

  function submit(payload: Record<string, unknown>, busyKey: string) {
    setBusy(busyKey);
    startTransition(async () => {
      const res = await fetch("/api/soc/actions", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      const body = await res.json().catch(() => ({})) as { message?: string; error?: string };
      setBusy("");
      if (!res.ok) {
        notify(body.error ?? "Configuration failed.", "error");
        return;
      }
      notify(body.message ?? "Configuration saved.", "success");
      router.refresh();
    });
  }

  return (
    <div className="integration-stack">
      <form className="config-form" action={(formData) => submit({
        action: "save-ingest-source",
        name: formData.get("name"),
        sourceType: formData.get("sourceType"),
        authMode: formData.get("authMode"),
        parser: formData.get("parser"),
      }, "source-save")}>
        <div className="config-form-heading">
          <div>
            <h3>Ingestion source</h3>
            <p>Register an incoming telemetry source and parser contract.</p>
          </div>
          <span className="status status-watch">{sources.length} configured</span>
        </div>
        <div className="config-grid">
          <label>
            <span>Name</span>
            <input name="name" placeholder="Production CloudTrail" required />
          </label>
          <label>
            <span>Source type</span>
            <select name="sourceType" defaultValue="generic_json">
              {["generic_json", "syslog", "cef", "windows_event", "sysmon", "aws_cloudtrail", "azure_signin", "azure_activity", "microsoft365_audit", "firewall"].map((sourceType) => (
                <option key={sourceType} value={sourceType}>{sourceType}</option>
              ))}
            </select>
          </label>
          <label>
            <span>Auth mode</span>
            <select name="authMode" defaultValue="shared-secret">
              <option value="shared-secret">Shared secret</option>
              <option value="bearer-token">Bearer token</option>
              <option value="oauth-client">OAuth client</option>
              <option value="aws-role">AWS role</option>
              <option value="none">None</option>
            </select>
          </label>
          <label>
            <span>Parser</span>
            <input name="parser" defaultValue="generic_json" />
          </label>
        </div>
        <button type="submit" disabled={pending && busy === "source-save"}><Save size={15} aria-hidden /> Save source</button>
      </form>

      <div className="channel-grid">
        {catalog.map((item) => {
          const configured = connectors.find((connector) => connector.catalogId === item.id);
          return (
            <form key={item.id} className="config-form" action={(formData) => {
              const payload: Record<string, unknown> = {
                action: "save-connector",
                catalogId: item.id,
                name: formData.get("name"),
                schedule: formData.get("schedule"),
                credential: formData.get("credential"),
                enabled: formData.get("enabled") === "on",
              };
              for (const field of [...item.requiredFields, ...item.optionalFields]) payload[field.key] = formData.get(field.key);
              submit(payload, `${item.id}-save`);
            }}>
              <div className="config-form-heading">
                <div>
                  <h3>{item.name}</h3>
                  <p>{item.provider} · {item.categories.join(", ")} · {item.authType}</p>
                </div>
                <span className={configured?.status === "healthy" ? "status status-healthy" : "status status-watch"}>
                  {configured?.status ?? "not configured"}
                </span>
              </div>
              <label>
                <span>Display name</span>
                <input name="name" defaultValue={configured?.name ?? item.name} />
              </label>
              <label>
                <span>Schedule</span>
                <select name="schedule" defaultValue={configured?.schedule ?? "manual"}>
                  <option value="manual">Manual</option>
                  <option value="15m">Every 15 minutes</option>
                  <option value="hourly">Hourly</option>
                  <option value="daily">Daily</option>
                </select>
              </label>
              {[...item.requiredFields, ...item.optionalFields].map((field) => (
                <label key={field.key}>
                  <span>{field.label}</span>
                  <input
                    name={field.key}
                    type={field.secret || field.type === "secret" ? "password" : field.type === "number" ? "number" : field.type === "url" ? "url" : "text"}
                    placeholder={configured?.config[field.key] ? "Saved" : field.placeholder ?? field.key}
                    defaultValue={typeof configured?.config[field.key] === "string" || typeof configured?.config[field.key] === "number" ? String(configured.config[field.key]) : ""}
                    required={field.required && !(field.secret && configured?.credentialConfigured)}
                    autoComplete="off"
                  />
                </label>
              ))}
              <label>
                <span>Credential override</span>
                <input name="credential" type="password" placeholder={configured?.credentialConfigured ? "Saved, leave blank to keep" : "Token, secret, or key"} autoComplete="off" />
              </label>
              <label className="checkbox-field">
                <input name="enabled" type="checkbox" defaultChecked={configured?.enabled ?? false} />
                <span>Enable connector</span>
              </label>
              <div className="config-actions">
                <button type="submit" disabled={pending && busy === `${item.id}-save`}><Save size={15} aria-hidden /> Save</button>
                <button
                  type="button"
                  className="secondary"
                  disabled={!configured || (pending && busy === `${item.id}-test`)}
                  onClick={() => submit({ action: "test-connector", catalogId: item.id }, `${item.id}-test`)}
                >
                  <Send size={15} aria-hidden /> Test
                </button>
              </div>
            </form>
          );
        })}
      </div>
    </div>
  );
}
