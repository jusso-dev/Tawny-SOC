import { Braces, Copy, GitBranch, PlayCircle, Upload } from "lucide-react";
import { PageHeader, SocShell } from "@/components/soc-shell";
import { getSocData, relativeTime, severityClass } from "@/lib/soc-domain";

export default async function DetectionsPage() {
  const { rules, alerts } = await getSocData();

  return (
    <SocShell active="/detections">
      <PageHeader
        eyebrow="Detection rules"
        title="Manage Tawny predicates and Sigma-style detection-as-code."
        description="Rule source, metadata, test status, version placeholders, false-positive counts, and last-triggered context stay visible."
        actions={<button className="text-button"><Upload size={15} aria-hidden /> Import Sigma</button>}
      />

      <section className="action-bar">
        <button><Braces size={15} aria-hidden /> Create rule</button>
        <button><Upload size={15} aria-hidden /> Import IOC-derived rule</button>
        <button><PlayCircle size={15} aria-hidden /> Test sample telemetry</button>
      </section>

      <div className="rule-catalog">
        {rules.map((rule) => {
          const triggered = alerts.find((alert) => alert.matchedRules.includes(rule.id));
          return (
            <article className="panel rule-card" key={rule.id}>
              <div className="panel-heading">
                <div>
                  <span className={severityClass(rule.severity)}>{rule.severity}</span>
                  <h2>{rule.title}</h2>
                  <p>{rule.description}</p>
                </div>
                <span className="status status-healthy">Enabled</span>
              </div>
              <dl className="detail-grid">
                <div><dt>Format</dt><dd>Sigma YAML</dd></div>
                <div><dt>Status</dt><dd>{rule.status}</dd></div>
                <div><dt>Logsource</dt><dd>{rule.logsource.product} / {rule.logsource.category ?? "any"}</dd></div>
                <div><dt>MITRE</dt><dd>{rule.mitreTechniques.join(", ")}</dd></div>
                <div><dt>Last triggered</dt><dd>{triggered ? relativeTime(triggered.timestamp) : "Never"}</dd></div>
                <div><dt>False positives</dt><dd>{rule.falsePositives.length}</dd></div>
                <div><dt>Tests</dt><dd>3 passing, 0 failing</dd></div>
                <div><dt>Version history</dt><dd><GitBranch size={14} aria-hidden /> Placeholder</dd></div>
              </dl>
              <pre className="code-block">{rule.sigma}</pre>
              <div className="card-actions">
                <button><PlayCircle size={15} aria-hidden /> Test</button>
                <button><Copy size={15} aria-hidden /> Duplicate</button>
                <button>Edit</button>
                <button>Disable</button>
              </div>
            </article>
          );
        })}
      </div>
    </SocShell>
  );
}
