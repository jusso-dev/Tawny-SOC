"use client";

import { Bot, CalendarPlus, Pause, Play, Radar, RotateCcw } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";
import { notify } from "@/components/toast-provider";
import type { HuntSchedule } from "@/lib/war-room";

type AlertOption = { id: string; title: string; severity: string; hostname?: string };

export function AgentMeshLauncher({ alerts }: { alerts: AlertOption[] }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [alertId, setAlertId] = useState(alerts[0]?.id ?? "");

  return <form className="mesh-launcher" onSubmit={(event) => {
    event.preventDefault();
    startTransition(async () => {
      const result = await post({ action: "run-agent-mesh", alertId });
      notify(result.message, result.ok ? "success" : "error");
      if (result.ok) router.refresh();
    });
  }}>
    <label><span>Focus alert</span><select value={alertId} onChange={(event) => setAlertId(event.target.value)} disabled={!alerts.length}>
      {alerts.map((alert) => <option key={alert.id} value={alert.id}>{alert.severity.toUpperCase()} · {alert.title} · {alert.hostname ?? "unknown host"}</option>)}
    </select></label>
    <button className="primary-action" type="submit" disabled={pending || !alertId}><Bot size={15} aria-hidden /> {pending ? "Agents working..." : "Run agent mesh"}</button>
  </form>;
}

export function HuntScheduleControls({ schedules }: { schedules: HuntSchedule[] }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();

  function execute(payload: Record<string, unknown>) {
    startTransition(async () => {
      const result = await post(payload);
      notify(result.message, result.ok ? "success" : "error");
      if (result.ok) router.refresh();
    });
  }

  return <div className="hunt-schedule-layout">
    <form className="hunt-schedule-form" onSubmit={(event) => {
      event.preventDefault();
      const data = new FormData(event.currentTarget);
      execute({ action: "create-hunt-schedule", name: data.get("name"), hypothesis: data.get("hypothesis"), query: data.get("query"), schedule: data.get("schedule"), timezone: data.get("timezone") });
      event.currentTarget.reset();
    }}>
      <div className="panel-heading"><div><p className="eyebrow">New autonomous hunt</p><h2>Schedule a hypothesis</h2></div><CalendarPlus size={18} aria-hidden /></div>
      <label><span>Name</span><input name="name" required placeholder="Impossible travel follow-up" /></label>
      <label><span>Hypothesis</span><textarea name="hypothesis" required placeholder="Compromised identity is authenticating from a new country and touching privileged resources." /></label>
      <label><span>YAAQL query</span><textarea name="query" required spellCheck={false} placeholder="eventType=SignIn and severity in (critical, high)" /></label>
      <div className="schedule-fields">
        <label><span>Cadence</span><select name="schedule" defaultValue="15 * * * *"><option value="*/15 * * * *">Every 15 minutes</option><option value="15 * * * *">Hourly</option><option value="0 8 * * *">Daily at 08:00</option><option value="0 9 * * 1-5">Weekdays at 09:00</option><option value="0 7 * * 1">Mondays at 07:00</option></select></label>
        <label><span>Timezone</span><input name="timezone" defaultValue="Australia/Sydney" required /></label>
      </div>
      <button className="primary-action" disabled={pending}><Radar size={15} aria-hidden /> Create schedule</button>
    </form>

    <section className="schedule-list" aria-label="Proactive hunt schedules">
      {schedules.map((schedule) => <article key={schedule.id}>
        <div><span className={`status ${schedule.enabled ? "status-healthy" : "status-watch"}`}>{schedule.enabled ? "active" : "paused"}</span><strong>{schedule.name}</strong><p>{schedule.hypothesis}</p><code>{schedule.query}</code><small>{schedule.schedule} · {schedule.timezone} · last: {schedule.lastRunAt ? `${schedule.lastStatus}, ${schedule.lastFindingCount} findings` : "never"}</small></div>
        <div className="schedule-actions"><button className="text-button" disabled={pending} onClick={() => execute({ action: "run-hunt-schedule", id: schedule.id })}><Play size={14} aria-hidden /> Run now</button><button className="text-button" disabled={pending} onClick={() => execute({ action: "toggle-hunt-schedule", id: schedule.id, enabled: !schedule.enabled })}>{schedule.enabled ? <Pause size={14} aria-hidden /> : <RotateCcw size={14} aria-hidden />}{schedule.enabled ? "Pause" : "Resume"}</button></div>
      </article>)}
      {!schedules.length ? <div className="empty-state compact"><Radar size={22} aria-hidden /><p>No proactive hunts scheduled.</p></div> : null}
    </section>
  </div>;
}

async function post(payload: Record<string, unknown>) {
  try {
    const response = await fetch("/api/war-room", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
    const body = await response.json().catch(() => ({})) as { message?: string; error?: string };
    return { ok: response.ok, message: response.ok ? body.message ?? "Done." : body.error ?? "Action failed." };
  } catch {
    return { ok: false, message: "War room request failed. Check server logs." };
  }
}
