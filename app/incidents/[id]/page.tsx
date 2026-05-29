import { ClipboardList, ExternalLink, PlayCircle, Send, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ActionButton } from "@/components/action-button";
import { PageHeader, SocShell } from "@/components/soc-shell";
import { getSocData, relativeTime, severityClass } from "@/lib/soc-domain";

export default async function IncidentDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { incidents, alerts } = await getSocData();
  const incident = incidents.find((item) => item.id === id);
  if (!incident) notFound();
  const linkedAlerts = alerts.filter((alert) => incident.linkedAlertIds.includes(alert.id));

  return (
    <SocShell active="/incidents">
      <PageHeader
        eyebrow="Case detail"
        title={`${incident.number}: ${incident.title}`}
        description={`${incident.status} · ${incident.assignee ?? "Unassigned"} · ${incident.kelpieSyncStatus.replace("_", " ")}`}
        actions={incident.kelpieUrl ? (
          <Link className="text-button" href={incident.kelpieUrl}><ExternalLink size={15} aria-hidden /> Open in Kelpie</Link>
        ) : (
          <ActionButton className="text-button" action="sync-incident-kelpie" payload={{ incidentId: incident.id }}><Send size={15} aria-hidden /> Promote to Kelpie</ActionButton>
        )}
      />

      <section className="action-bar">
        <ActionButton action="change-incident-state" payload={{ incidentId: incident.id }}><ShieldCheck size={15} aria-hidden /> Change state</ActionButton>
        <ActionButton action="run-playbook" payload={{ incidentId: incident.id }}><PlayCircle size={15} aria-hidden /> Run playbook</ActionButton>
        <ActionButton action="add-task" payload={{ incidentId: incident.id }}><ClipboardList size={15} aria-hidden /> Add task</ActionButton>
        <ActionButton action="sync-comments" payload={{ incidentId: incident.id }}><Send size={15} aria-hidden /> Sync comments</ActionButton>
      </section>

      <div className="grid detail-layout">
        <section className="panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Overview</p>
              <h2>State, entities, and evidence</h2>
            </div>
            <span className={severityClass(incident.severity)}>{incident.severity}</span>
          </div>
          <dl className="detail-grid">
            <div><dt>Priority</dt><dd>{incident.priority}</dd></div>
            <div><dt>Status</dt><dd>{incident.status}</dd></div>
            <div><dt>TLP / PAP</dt><dd>{incident.tlp} / {incident.pap}</dd></div>
            <div><dt>Classification</dt><dd>{incident.classification.replace("_", " ")}</dd></div>
            <div><dt>Hosts</dt><dd>{incident.linkedHosts.join(", ") || "None"}</dd></div>
            <div><dt>MITRE</dt><dd>{incident.mitreTechniques.join(", ") || "Needs mapping"}</dd></div>
          </dl>

          <h2 className="section-title">Linked alerts</h2>
          <div className="linked-list">
            {linkedAlerts.map((alert) => (
              <Link key={alert.id} href={`/alerts/${alert.id}`}>
                <span className={severityClass(alert.severity)}>{alert.severity}</span>
                <strong>{alert.title}</strong>
                <small>{alert.hostname ?? "unknown"} · {relativeTime(alert.timestamp)}</small>
              </Link>
            ))}
          </div>

          <h2 className="section-title">Observables</h2>
          <div className="ioc-list">
            {incident.observables.map((ioc) => (
              <article key={ioc.id}>
                <strong>{ioc.value}</strong>
                <span>{ioc.type} · {ioc.sourceFeed} · {ioc.confidence}%</span>
              </article>
            ))}
          </div>
        </section>

        <aside className="side-stack">
          <section className="panel">
            <p className="eyebrow">Tasks</p>
            <h2>Playbook work</h2>
            <div className="task-list">
              {incident.tasks.map((task) => (
                <article key={task.id}>
                  <strong>{task.title}</strong>
                  <span>{task.owner} · {task.status} · due {relativeTime(task.dueAt)}</span>
                  <small>{task.requiredEvidence.join(", ")}</small>
                </article>
              ))}
            </div>
          </section>

          <section className="panel">
            <p className="eyebrow">Timeline</p>
            <h2>Audit log</h2>
            <div className="timeline-list">
              {incident.timeline.map((item) => (
                <p key={item.id}><strong>{item.actor}</strong> {item.action}: {item.detail}</p>
              ))}
            </div>
          </section>

          <section className="panel">
            <p className="eyebrow">Comments</p>
            <h2>Analyst notes</h2>
            <div className="timeline-list">
              {incident.comments.map((comment) => (
                <p key={comment.id}><strong>{comment.author}</strong> {comment.body}</p>
              ))}
            </div>
          </section>
        </aside>
      </div>
    </SocShell>
  );
}
