import { Bot, MessagesSquare, Workflow } from "lucide-react";
import Link from "next/link";
import { AgentMeshLauncher, HuntScheduleControls } from "@/components/war-room-controls";
import { PageHeader, SocShell } from "@/components/soc-shell";
import { getAiSettings } from "@/lib/ai";
import { socAgentProfiles } from "@/lib/ai/agents/catalog";
import { agentWorkflows } from "@/lib/agent-workflows";
import { getSocData, relativeTime } from "@/lib/soc-domain";
import { listAgentRuns, listHuntSchedules } from "@/lib/war-room";

export default async function WarRoomPage() {
  const { alerts, tenantId } = await getSocData();
  const [runs, schedules, settings] = await Promise.all([listAgentRuns(tenantId), listHuntSchedules(tenantId), getAiSettings(tenantId)]);
  const aiSteps = runs.flatMap((run) => run.steps).filter((step) => step.engine === "ai").length;
  const completed = runs.filter((run) => run.status === "completed").length;

  return <SocShell active="/war-room">
    <PageHeader eyebrow="Hermes Bot Mode war room" title="Every bot. Every message. Every tool call." description="Thirteen named Hermes profiles collaborate through native Bot Mode while Tawny preserves one ordered, tenant-scoped investigation trace." actions={<Link className="text-button" href="/integrations#hermes"><Bot size={15} aria-hidden /> Install bot profiles</Link>} />

    <section className="war-room-hero">
      <div><span className={`mesh-status ${settings.enabled ? "live" : "fallback"}`}><i /> {settings.enabled ? "AI engine online" : "Deterministic fallback"}</span><h2>Pick mission. Open shared room.</h2><p>Workflow defines bot order, scoped tools, handoffs, and approval gates. Hermes handles conversation; Tawny records attributed evidence and execution trace.</p></div>
      <AgentMeshLauncher workflows={agentWorkflows} alerts={alerts.slice(0, 30).map((alert) => ({ id: alert.id, title: alert.title, severity: alert.severity, hostname: alert.hostname }))} />
    </section>

    <section className="workflow-catalog" aria-label="Multi-agent workflows">
      {agentWorkflows.map((workflow) => <article key={workflow.id}><div><Workflow size={15} aria-hidden /><strong>{workflow.name}</strong><span>{workflow.phases.length} phases</span></div><p>{workflow.description}</p><small>{workflow.phases.map((phase) => phase.agent.replaceAll("_", " ")).join(" / ")}</small></article>)}
    </section>

    <section className="agent-library-panel">
      <div className="panel-heading"><div><p className="eyebrow">Specialist library</p><h2>13 purpose-built SOC agents</h2><p>Each profile owns methodology, evidence interfaces, model budget, and workflow role.</p></div></div>
      <div className="agent-contract" aria-label="SOC specialist agents">
        {socAgentProfiles.map((agent) => <article key={agent.id}><i style={{ background: agent.color }}>{agent.initials}</i><div><h2>{agent.name}</h2><p>{agent.description}</p><small>{agent.tools.length} scoped tools · {agent.deepReasoning ? "deep reasoning" : "fast path"}</small></div></article>)}
      </div>
    </section>

    <section className="war-room-grid">
      <article className="panel ledger-panel">
        <div className="panel-heading"><div><p className="eyebrow">Shared investigation rooms</p><h2>Complete collaboration trace</h2><p>{completed} completed rooms · {aiSteps} AI-backed steps</p></div><MessagesSquare size={18} aria-hidden /></div>
        <div className="agent-run-list">
          {runs.map((run) => <details key={run.id} open={runs[0]?.id === run.id}>
            <summary><span className={`run-state ${run.status}`}>{run.status}</span><div><strong>{run.title}</strong><small>{run.workflowId ?? "scheduled hunt"} · {run.trigger} · {run.initiatedBy} · {relativeTime(run.startedAt)}</small></div><b>{run.events.length} events</b></summary>
            <p className="run-summary">{run.summary}</p>
            <section className="room-transcript" aria-label={`Trace for ${run.title}`}>
              {run.events.map((event) => <article className={`room-event ${event.status}`} key={event.id}>
                <div><span>#{event.sequence}</span><strong>{event.agentId?.replaceAll("_", " ") ?? event.actorName}</strong>{event.targetAgentId ? <small>to {event.targetAgentId.replaceAll("_", " ")}</small> : null}<em>{event.eventType}</em><time dateTime={event.createdAt}>{relativeTime(event.createdAt)}</time></div>
                <p>{event.summary}</p>
                {event.toolName ? <code>{event.toolName}</code> : null}
                {Object.keys(event.detail).length ? <details><summary>Trace payload</summary><pre>{JSON.stringify(event.detail, null, 2)}</pre></details> : null}
              </article>)}
              {!run.events.length ? <p className="legacy-room-note">Legacy run: specialist steps retained, no room-event stream.</p> : null}
            </section>
            <div className="run-steps">{run.steps.map((step, index) => <article key={`${run.id}-${step.phaseId ?? step.agent}-${index}`}><div><span>{step.agent}</span><em>{step.engine}</em>{step.approvalRequired ? <em className="approval-chip">approval gate</em> : null}{step.confidence !== undefined ? <b>{Math.round(step.confidence * 100)}%</b> : null}</div>{step.phaseName ? <h3>{step.phaseName}</h3> : null}<p>{step.summary}</p>{step.actions.slice(0, 3).map((action) => <small key={action}>{action}</small>)}</article>)}</div>
          </details>)}
          {!runs.length ? <div className="empty-state"><Bot size={22} aria-hidden /><p>Select workflow and alert to create first specialist ledger.</p></div> : null}
        </div>
      </article>

      <aside className="panel hermes-callout"><div className="panel-heading"><div><p className="eyebrow">Hermes Bot Mode</p><h2>Real profiles, shared memory</h2></div><Bot size={18} aria-hidden /></div><p>Each specialist installs as named Hermes profile with own <code>SOUL.md</code>, model context, scoped Tawny MCP tools, and native bot-to-bot messaging.</p><ul><li>Per-bot token attribution</li><li>Automatic tool input and output trace</li><li>Mirrored messages and handoffs</li><li>Owner-approved containment only</li></ul><Link className="primary-action" href="/integrations#hermes">Install profiles</Link></aside>
    </section>

    <HuntScheduleControls schedules={schedules} />
  </SocShell>;
}
