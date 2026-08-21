import { Bot, BrainCircuit, Crosshair, RadioTower, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { AgentMeshLauncher, HuntScheduleControls } from "@/components/war-room-controls";
import { PageHeader, SocShell } from "@/components/soc-shell";
import { getAiSettings } from "@/lib/ai";
import { getSocData, relativeTime } from "@/lib/soc-domain";
import { listAgentRuns, listHuntSchedules } from "@/lib/war-room";

const agentContract = [
  { name: "Detect", icon: RadioTower, role: "Fuse alerts and telemetry into attack chains.", output: "Correlated signal set" },
  { name: "Triage", icon: BrainCircuit, role: "Decide what matters and how urgent it is.", output: "Verdict and confidence" },
  { name: "Hunt", icon: Crosshair, role: "Generate and run evidence-backed YAAQL pivots.", output: "Hypotheses and findings" },
  { name: "Respond", icon: ShieldCheck, role: "Plan reversible response and gated containment.", output: "Governed action plan" },
] as const;

export default async function WarRoomPage() {
  const { alerts, tenantId } = await getSocData();
  const [runs, schedules, settings] = await Promise.all([listAgentRuns(tenantId), listHuntSchedules(tenantId), getAiSettings(tenantId)]);
  const aiSteps = runs.flatMap((run) => run.steps).filter((step) => step.engine === "ai").length;
  const completed = runs.filter((run) => run.status === "completed").length;

  return <SocShell active="/war-room">
    <PageHeader eyebrow="AI war room" title="Agents investigate. Analysts command." description="Detect, Triage, Hunt, and Respond share one evidence ledger. Response remains approval-gated." actions={<Link className="text-button" href="/integrations#hermes"><Bot size={15} aria-hidden /> Connect Hermes</Link>} />

    <section className="war-room-hero">
      <div><span className={`mesh-status ${settings.enabled ? "live" : "fallback"}`}><i /> {settings.enabled ? "AI engine online" : "Deterministic fallback"}</span><h2>Launch a full investigation in one move.</h2><p>Each agent receives scoped tenant evidence. Every summary, evidence pivot, action, model mode, and timestamp lands in replayable run history.</p></div>
      <AgentMeshLauncher alerts={alerts.slice(0, 30).map((alert) => ({ id: alert.id, title: alert.title, severity: alert.severity, hostname: alert.hostname }))} />
    </section>

    <section className="agent-contract" aria-label="Four agent pipeline">
      {agentContract.map((agent, index) => { const Icon = agent.icon; return <article key={agent.name}><span>{String(index + 1).padStart(2, "0")}</span><Icon size={18} aria-hidden /><h2>{agent.name}</h2><p>{agent.role}</p><small>{agent.output}</small></article>; })}
    </section>

    <section className="war-room-grid">
      <article className="panel ledger-panel">
        <div className="panel-heading"><div><p className="eyebrow">Investigation ledger</p><h2>Agent runs</h2><p>{completed} completed runs · {aiSteps} AI-backed steps</p></div></div>
        <div className="agent-run-list">
          {runs.map((run) => <details key={run.id} open={runs[0]?.id === run.id}>
            <summary><span className={`run-state ${run.status}`}>{run.status}</span><div><strong>{run.title}</strong><small>{run.trigger} · {run.initiatedBy} · {relativeTime(run.startedAt)}</small></div><b>{run.steps.length} steps</b></summary>
            <p className="run-summary">{run.summary}</p>
            <div className="run-steps">{run.steps.map((step) => <article key={`${run.id}-${step.agent}`}><div><span>{step.agent}</span><em>{step.engine}</em>{step.confidence !== undefined ? <b>{Math.round(step.confidence * 100)}%</b> : null}</div><p>{step.summary}</p>{step.actions.slice(0, 3).map((action) => <small key={action}>{action}</small>)}</article>)}</div>
          </details>)}
          {!runs.length ? <div className="empty-state"><Bot size={22} aria-hidden /><p>Select an alert and run agent mesh to create first ledger.</p></div> : null}
        </div>
      </article>

      <aside className="panel hermes-callout"><div className="panel-heading"><div><p className="eyebrow">Hermes native</p><h2>Bot-ready MCP</h2></div><Bot size={18} aria-hidden /></div><p>Hermes connects directly to <code>/api/mcp</code>. Bots can investigate alerts, run agent mesh, execute scheduled hunts, and inspect ledgers without another AI harness.</p><ul><li>Bearer token scopes filter tools</li><li>Read-only investigation by default</li><li>Containment stays owner-approved</li></ul><Link className="primary-action" href="/integrations#hermes">Open setup</Link></aside>
    </section>

    <HuntScheduleControls schedules={schedules} />
  </SocShell>;
}
