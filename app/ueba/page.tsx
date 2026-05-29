import { AlertCircle, BrainCircuit, Search } from "lucide-react";
import Link from "next/link";
import { PageHeader, SocShell } from "@/components/soc-shell";
import { getSocData, relativeTime, severityClass } from "@/lib/soc-domain";
import { buildBehaviorRecords, summarizeBehaviorEntities, type UebaBehaviorCategory } from "@/lib/ueba";

export default async function UebaPage() {
  const { alerts, events } = await getSocData();
  const behaviors = buildBehaviorRecords([...alerts, ...events]);
  const entitySummaries = summarizeBehaviorEntities(behaviors);
  const riskyEntities = entitySummaries.filter((summary) => summary.riskScore >= 60).length;
  const explainedSignals = behaviors.reduce((total, behavior) => total + behavior.reasons.length, 0);
  const categoryCounts = countCategories(behaviors.map((behavior) => behavior.category));

  return (
    <SocShell active="/ueba">
      <PageHeader
        eyebrow="UEBA behavior layer"
        title="Explain low-level telemetry as readable entity behavior."
        description="Behavior records are deterministic and evidence-backed: every summary shows the event fields and rules that produced it."
      />

      <section className="metric-row behavior-metrics">
        <div><span>{behaviors.length.toLocaleString()}</span><p>Behavior records</p><small>Derived from retained alerts and telemetry</small></div>
        <div><span>{entitySummaries.length.toLocaleString()}</span><p>Entities summarized</p><small>User, host, process, and IP actors</small></div>
        <div><span>{riskyEntities.toLocaleString()}</span><p>Risky entities</p><small>Risk score 60 or higher</small></div>
        <div><span>{explainedSignals.toLocaleString()}</span><p>Evidence reasons</p><small>Transparent contributing fields</small></div>
      </section>

      <section className="panel behavior-category-band">
        <div className="panel-heading">
          <div>
            <h2>Behavior coverage</h2>
            <p>Categories are extracted from source fields, titles, event types, detections, and normalized payload values.</p>
          </div>
        </div>
        <div className="behavior-category-grid">
          {(["authentication", "process", "network", "privilege", "data_access", "threat_intel"] as UebaBehaviorCategory[]).map((category) => (
            <div key={category}>
              <span>{category.replace("_", " ")}</span>
              <strong>{(categoryCounts[category] ?? 0).toLocaleString()}</strong>
            </div>
          ))}
        </div>
      </section>

      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Entity risk summaries</h2>
            <p>Risk is explainable and capped. It combines source severity, behavior type, repeated observations, and detection context.</p>
          </div>
          <BrainCircuit size={18} aria-hidden />
        </div>
        <div className="table-wrap">
          <table className="soc-table">
            <thead>
              <tr><th>Entity</th><th>Risk</th><th>Behaviors</th><th>Categories</th><th>Last seen</th><th>Top reasons</th></tr>
            </thead>
            <tbody>
              {entitySummaries.slice(0, 12).map((summary) => (
                <tr key={`${summary.tenantId}-${summary.entity.kind}-${summary.entity.value}`}>
                  <td><strong>{summary.entity.value}</strong><span>{summary.entity.kind} / {summary.tenantId}</span></td>
                  <td><span className={severityClass(severityForRisk(summary.riskScore))}>{summary.riskScore}</span></td>
                  <td>{summary.behaviorCount}</td>
                  <td>{summary.categories.map((category) => category.replace("_", " ")).join(", ")}</td>
                  <td>{relativeTime(summary.lastSeen)}</td>
                  <td>{summary.topReasons.slice(0, 2).join(" ")}</td>
                </tr>
              ))}
              {!entitySummaries.length ? <tr><td colSpan={6}>No behavior records yet. Ingest Tawny telemetry or connector records to populate entity behavior.</td></tr> : null}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Behavior timeline</h2>
            <p>Each row is an analyst-readable explanation built from one source event.</p>
          </div>
          <Link className="text-button" href="/hunt"><Search size={14} aria-hidden /> Open hunt</Link>
        </div>
        <div className="table-wrap">
          <table className="soc-table behavior-table">
            <thead>
              <tr><th>Behavior</th><th>Actor</th><th>Target</th><th>Risk</th><th>Observed</th><th>Why</th></tr>
            </thead>
            <tbody>
              {behaviors.slice(0, 100).map((behavior) => (
                <tr key={behavior.id}>
                  <td><strong>{behavior.summary}</strong><span>{behavior.category} / {behavior.behavior}</span></td>
                  <td>{behavior.actor.value}<span>{behavior.actor.kind}</span></td>
                  <td>{behavior.target?.value ?? "None"}<span>{behavior.target?.kind ?? "not set"}</span></td>
                  <td><span className={severityClass(severityForRisk(behavior.riskScore))}>{behavior.riskScore}</span></td>
                  <td>{relativeTime(behavior.observedAt)}<span>{behavior.sourceEventIds.join(", ")}</span></td>
                  <td>
                    <div className="behavior-reasons">
                      {behavior.reasons.slice(0, 3).map((reason) => <span key={reason}>{reason}</span>)}
                    </div>
                  </td>
                </tr>
              ))}
              {!behaviors.length ? (
                <tr>
                  <td colSpan={6}>
                    <div className="hunt-empty-row">
                      <AlertCircle size={16} aria-hidden />
                      <span>No behavior records could be derived from retained records yet.</span>
                    </div>
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </section>
    </SocShell>
  );
}

function countCategories(categories: UebaBehaviorCategory[]) {
  return categories.reduce<Partial<Record<UebaBehaviorCategory, number>>>((acc, category) => {
    acc[category] = (acc[category] ?? 0) + 1;
    return acc;
  }, {});
}

function severityForRisk(score: number) {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 35) return "medium";
  return "low";
}
