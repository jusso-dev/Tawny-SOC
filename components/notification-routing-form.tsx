"use client";

import { Save } from "lucide-react";
import { useRouter } from "next/navigation";
import { useTransition } from "react";
import { notify } from "@/components/toast-provider";
import type { IntegrationChannelSetting, SocSettings } from "@/lib/store";

type SeverityKey = "critical" | "high" | "medium" | "low";

const severityRows: Array<{ key: SeverityKey; label: string; detail: string }> = [
  { key: "critical", label: "Critical", detail: "Page immediately and create a case if configured." },
  { key: "high", label: "High", detail: "Notify the active response channel." },
  { key: "medium", label: "Medium", detail: "Send analyst visibility without paging." },
  { key: "low", label: "Low", detail: "Usually quiet unless a tenant has a low-noise channel." },
];

export function NotificationRoutingForm({
  channels,
  routing,
}: {
  channels: IntegrationChannelSetting[];
  routing: SocSettings["routing"];
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const channelOptions = channels.map((channel) => channel.channel);

  function submit(formData: FormData) {
    const values = {
      criticalChannels: formData.getAll("criticalChannels"),
      highChannels: formData.getAll("highChannels"),
      mediumChannels: formData.getAll("mediumChannels"),
      lowChannels: formData.getAll("lowChannels"),
      criticalChannel: firstChannel(formData.getAll("criticalChannels")),
      highChannel: firstChannel(formData.getAll("highChannels")),
      defaultAssignee: String(formData.get("defaultAssignee") ?? ""),
      caseCreationSeverity: String(formData.get("caseCreationSeverity") ?? "critical"),
      quietHoursEnabled: formData.get("quietHoursEnabled") === "on",
      quietHoursStart: String(formData.get("quietHoursStart") ?? ""),
      quietHoursEnd: String(formData.get("quietHoursEnd") ?? ""),
    };

    startTransition(async () => {
      const res = await fetch("/api/soc/actions", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ action: "save-soc-setting", settingKey: "routing", values }),
      });
      const body = await res.json().catch(() => ({})) as { message?: string; error?: string };
      if (!res.ok) {
        notify(body.error ?? "Routing update failed.", "error");
        return;
      }
      notify(body.message ?? "Notification routing saved.", "success");
      router.refresh();
    });
  }

  return (
    <form className="config-form routing-form" action={submit}>
      <div className="config-form-heading">
        <div>
          <h3>Severity routes</h3>
          <p>Select which configured outbound channels receive each alert severity.</p>
        </div>
      </div>

      <div className="routing-matrix">
        {severityRows.map((row) => (
          <fieldset key={row.key}>
            <legend>
              <strong>{row.label}</strong>
              <span>{row.detail}</span>
            </legend>
            <div className="scope-grid">
              {channelOptions.map((channel) => (
                <label className="checkbox-field" key={channel}>
                  <input
                    name={`${row.key}Channels`}
                    type="checkbox"
                    value={channel}
                    defaultChecked={routing[`${row.key}Channels`].includes(channel)}
                  />
                  <span>{channelLabel(channel)}{channels.find((item) => item.channel === channel)?.enabled ? "" : " (disabled)"}</span>
                </label>
              ))}
            </div>
          </fieldset>
        ))}
      </div>

      <div className="config-grid">
        <label>
          <span>Default assignee</span>
          <input name="defaultAssignee" defaultValue={routing.defaultAssignee} placeholder="analyst@company.com" />
        </label>
        <label>
          <span>Auto-case threshold</span>
          <select name="caseCreationSeverity" defaultValue={routing.caseCreationSeverity}>
            <option value="critical">Critical only</option>
            <option value="high">High and above</option>
            <option value="medium">Medium and above</option>
            <option value="disabled">Do not auto-create cases</option>
          </select>
        </label>
        <label>
          <span>Quiet hours start</span>
          <input name="quietHoursStart" type="time" defaultValue={routing.quietHoursStart} />
        </label>
        <label>
          <span>Quiet hours end</span>
          <input name="quietHoursEnd" type="time" defaultValue={routing.quietHoursEnd} />
        </label>
        <label className="checkbox-field">
          <input name="quietHoursEnabled" type="checkbox" defaultChecked={routing.quietHoursEnabled} />
          <span>Enable quiet hours</span>
        </label>
      </div>

      <div className="config-actions">
        <button type="submit" disabled={pending}><Save size={15} aria-hidden /> {pending ? "Saving..." : "Save routing"}</button>
      </div>
    </form>
  );
}

function firstChannel(values: FormDataEntryValue[]) {
  const first = values.find((value) => typeof value === "string");
  return typeof first === "string" ? first : "";
}

function channelLabel(channel: string) {
  if (channel === "sentinel") return "Microsoft Sentinel";
  return channel.slice(0, 1).toUpperCase() + channel.slice(1);
}
