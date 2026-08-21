"use client";

import { PlugZap, Save } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";
import { notify } from "@/components/toast-provider";
import type { AiProviderId, AiSettingsView } from "@/lib/ai/types";

export function AiSettingsForm({ settings }: { settings: AiSettingsView }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [busyAction, setBusyAction] = useState("");
  const [provider, setProvider] = useState<AiProviderId>(settings.provider);

  function submit(action: "save-ai-settings" | "test-ai-connection", form: HTMLFormElement) {
    const formData = new FormData(form);
    setBusyAction(action);
    startTransition(async () => {
      const res = await fetch("/api/soc/actions", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          action,
          enabled: formData.get("enabled") === "on",
          provider: formData.get("provider"),
          azureEndpoint: formData.get("azureEndpoint"),
          azureDeployment: formData.get("azureDeployment"),
          azureApiVersion: formData.get("azureApiVersion"),
          azureApiKey: formData.get("azureApiKey"),
          bedrockRegion: formData.get("bedrockRegion"),
          bedrockModelId: formData.get("bedrockModelId"),
          bedrockAccessKeyId: formData.get("bedrockAccessKeyId"),
          bedrockSecretAccessKey: formData.get("bedrockSecretAccessKey"),
          bedrockSessionToken: formData.get("bedrockSessionToken"),
          agentDetect: formData.get("agentDetect") === "on",
          agentTriage: formData.get("agentTriage") === "on",
          agentHunt: formData.get("agentHunt") === "on",
          agentRespond: formData.get("agentRespond") === "on",
        }),
      });
      const body = await res.json().catch(() => ({})) as { message?: string; error?: string };
      setBusyAction("");
      if (!res.ok) {
        notify(body.error ?? "AI engine action failed.", "error");
        return;
      }
      notify(body.message ?? "AI engine updated.", "success");
      router.refresh();
    });
  }

  return (
    <form className="config-form" onSubmit={(event) => { event.preventDefault(); submit("save-ai-settings", event.currentTarget); }}>
      <div className="config-form-heading">
        <div>
          <h3>Model provider</h3>
          <p>Hot-swap the engine behind every SOC agent. Saved credentials stay server-side.</p>
        </div>
        <span className={settings.enabled ? "status status-healthy" : "status status-watch"}>
          {settings.enabled ? "Enabled" : "Disabled"}
        </span>
      </div>

      <div className="config-grid">
        <label>
          <span>Provider</span>
          <select name="provider" value={provider} onChange={(event) => setProvider(event.target.value as AiProviderId)}>
            <option value="azure-openai">Azure OpenAI</option>
            <option value="aws-bedrock">AWS Bedrock</option>
          </select>
        </label>
        <label className="checkbox-field">
          <input name="enabled" type="checkbox" defaultChecked={settings.enabled} />
          <span>Enable AI engine</span>
        </label>
      </div>

      <div className="config-grid" style={provider === "azure-openai" ? undefined : { display: "none" }}>
        <label>
          <span>Azure endpoint</span>
          <input name="azureEndpoint" type="url" defaultValue={settings.azure.endpoint} placeholder="https://your-resource.openai.azure.com" />
        </label>
        <label>
          <span>Deployment name</span>
          <input name="azureDeployment" defaultValue={settings.azure.deployment} placeholder="gpt-4o-soc" />
        </label>
        <label>
          <span>API version</span>
          <input name="azureApiVersion" defaultValue={settings.azure.apiVersion} placeholder="2024-10-21" />
        </label>
        <label>
          <span>API key</span>
          <input name="azureApiKey" type="password" placeholder={settings.azure.apiKeyConfigured ? "Saved, leave blank to keep" : "Paste API key"} autoComplete="off" />
        </label>
      </div>

      <div className="config-grid" style={provider === "aws-bedrock" ? undefined : { display: "none" }}>
        <label>
          <span>AWS region</span>
          <input name="bedrockRegion" defaultValue={settings.bedrock.region} placeholder="ap-southeast-2" />
        </label>
        <label>
          <span>Model ID</span>
          <input name="bedrockModelId" defaultValue={settings.bedrock.modelId} placeholder="us.anthropic.claude-sonnet-4-5-20250929-v1:0" />
        </label>
        <label>
          <span>Access key ID</span>
          <input name="bedrockAccessKeyId" defaultValue={settings.bedrock.accessKeyId} placeholder="AKIA..." autoComplete="off" />
        </label>
        <label>
          <span>Secret access key</span>
          <input name="bedrockSecretAccessKey" type="password" placeholder={settings.bedrock.secretConfigured ? "Saved, leave blank to keep" : "Paste secret key"} autoComplete="off" />
        </label>
        <label>
          <span>Session token (optional)</span>
          <input name="bedrockSessionToken" type="password" placeholder="For temporary STS credentials" autoComplete="off" />
        </label>
      </div>

      <div className="config-form-heading">
        <div>
          <h3>Agents</h3>
          <p>Toggle which SOC agents run through the AI engine. Disabled agents fall back to deterministic logic.</p>
        </div>
      </div>
      <div className="config-grid">
        <label className="checkbox-field">
          <input name="agentDetect" type="checkbox" defaultChecked={settings.agents.detect} />
          <span>Detect agent — fuse related signals and map attack chains</span>
        </label>
        <label className="checkbox-field">
          <input name="agentTriage" type="checkbox" defaultChecked={settings.agents.triage} />
          <span>Triage agent — verdict, confidence, and next actions per alert</span>
        </label>
        <label className="checkbox-field">
          <input name="agentHunt" type="checkbox" defaultChecked={settings.agents.hunt} />
          <span>TI enrichment agent — indicator assessment and hunt pivots</span>
        </label>
        <label className="checkbox-field">
          <input name="agentRespond" type="checkbox" defaultChecked={settings.agents.respond} />
          <span>Respond agent — plan containment and draft case reporting</span>
        </label>
      </div>

      <div className="config-actions">
        <button type="submit" disabled={pending && busyAction === "save-ai-settings"}>
          <Save size={15} aria-hidden /> Save AI engine
        </button>
        <button
          type="button"
          className="secondary"
          disabled={pending && busyAction === "test-ai-connection"}
          onClick={(event) => {
            const form = event.currentTarget.form;
            if (form) submit("test-ai-connection", form);
          }}
        >
          <PlugZap size={15} aria-hidden /> Test connection
        </button>
      </div>
    </form>
  );
}
