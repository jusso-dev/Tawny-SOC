import { AlertTriangle, Braces, FolderPlus, Send, ShieldCheck, TerminalSquare } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";
import { PageHeader, SocShell } from "@/components/soc-shell";
import { getSocData, relativeTime, severityClass } from "@/lib/soc-domain";

export default async function AlertDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { alerts, incidents } = await getSocData();
  const alert = alerts.find((item) => item.id === id);
  if (!alert) notFound();
  const relatedCase = incidents.find((incident) => incident.linkedAlertIds.includes(alert.id));

  return (
    <SocShell active="/alerts">
      <PageHeader
        eyebrow="Alert detail"
        title={alert.title}
        description={`${alert.hostname ?? "unknown host"} · ${relativeTime(alert.timestamp)} · ${Math.round(alert.confidence * 100)}% confidence`}
        actions={<span className={severityClass(alert.severity)}>{alert.severity}</span>}
      />

      <section className="action-bar">
        <button><ShieldCheck size={15} aria-hidden /> Assign</button>
        <button><AlertTriangle size={15} aria-hidden /> Change status</button>
        <button><FolderPlus size={15} aria-hidden /> Create Tawny case</button>
        <button><Send size={15} aria-hidden /> Send to Kelpie</button>
        <button><Braces size={15} aria-hidden /> Suppress rule</button>
      </section>

      <div className="grid detail-layout">
        <section className="panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Evidence</p>
              <h2>Matched telemetry and raw payload</h2>
            </div>
            <TerminalSquare size={18} aria-hidden />
          </div>
          <dl className="detail-grid">
            <div><dt>Rule</dt><dd>{alert.matchedRules[0] ?? "Tawny rule"}</dd></div>
            <div><dt>Source</dt><dd>{alert.source}</dd></div>
            <div><dt>Host</dt><dd>{alert.hostname ?? "unknown"}</dd></div>
            <div><dt>User</dt><dd>{alert.user ?? "unknown"}</dd></div>
            <div><dt>Process</dt><dd>{alert.process ?? "unknown"}</dd></div>
            <div><dt>Command line</dt><dd>{alert.commandLine || "Not captured"}</dd></div>
            <div><dt>Network</dt><dd>{alert.externalIps?.join(", ") || "No external IP captured"}</dd></div>
            <div><dt>Related case</dt><dd>{relatedCase ? <Link href={`/incidents/${relatedCase.id}`}>{relatedCase.number}</Link> : "None"}</dd></div>
          </dl>
          <pre className="json-block">{JSON.stringify(alert.payload, null, 2)}</pre>
        </section>

        <aside className="side-stack">
          <section className="panel">
            <p className="eyebrow">Threat intelligence</p>
            <h2>IOC matches</h2>
            <div className="ioc-list">
              {(alert.tiMatches ?? []).map((ioc) => (
                <article key={ioc.id}>
                  <strong>{ioc.value}</strong>
                  <span>{ioc.type} · {ioc.sourceFeed} · {ioc.confidence}%</span>
                  <small>{ioc.tags.join(", ")}</small>
                </article>
              ))}
              {!(alert.tiMatches ?? []).length ? <p className="muted-copy">No IOC matches yet.</p> : null}
            </div>
          </section>

          <section className="panel">
            <p className="eyebrow">MITRE ATT&CK</p>
            <h2>Technique mapping</h2>
            <div className="tag-row">
              {alert.mitreTechniques.map((technique) => <span key={technique}>{technique}</span>)}
            </div>
          </section>

          <section className="panel">
            <p className="eyebrow">Analyst timeline</p>
            <h2>Actions</h2>
            <div className="timeline-list">
              <p><strong>Tawny-SOC</strong> created alert from Tawny ingest.</p>
              <p><strong>AI triage</strong> selected {alert.recommendedPlaybook}.</p>
              <p><strong>Analyst</strong> review pending.</p>
            </div>
          </section>
        </aside>
      </div>
    </SocShell>
  );
}
