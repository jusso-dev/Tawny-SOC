import { Braces, Copy, GitBranch, PlayCircle, Upload } from "lucide-react";
import Link from "next/link";
import { ActionButton } from "@/components/action-button";
import { PageHeader, SocShell } from "@/components/soc-shell";
import { SigmaImportForm } from "@/components/sigma-import-form";
import { getSocData, relativeTime, severityClass } from "@/lib/soc-domain";

export default async function DetectionsPage() {
  const { rules, alerts } = await getSocData();

  return (
    <SocShell active="/detections">
      <PageHeader
        eyebrow="Detection rules"
        title="Manage Tawny predicates and Sigma-style detection-as-code."
        description="Rule source, metadata, status, false-positive notes, and last-triggered context stay visible."
        actions={<SigmaImportForm />}
      />

      <section className="action-bar">
        <Link className="primary-action" href="#import-sigma"><Braces size={15} aria-hidden /> Create rule</Link>
        <Link className="primary-action" href="/threat-intel"><Upload size={15} aria-hidden /> Import IOC-derived rule</Link>
        <Link className="primary-action" href="/hunt"><PlayCircle size={15} aria-hidden /> Test telemetry</Link>
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
                <div><dt>Tests</dt><dd>Run against current telemetry</dd></div>
                <div><dt>Version history</dt><dd><GitBranch size={14} aria-hidden /> Current revision</dd></div>
              </dl>
              <pre className="code-block">{rule.sigma}</pre>
              <div className="card-actions">
                <Link className="primary-action" href={`/hunt?q=${encodeURIComponent(`rule:${rule.id}`)}`}><PlayCircle size={15} aria-hidden /> Test</Link>
                <ActionButton action="duplicate-rule" payload={{ ruleId: rule.id }}><Copy size={15} aria-hidden /> Duplicate</ActionButton>
                <Link className="primary-action" href={`/hunt?q=${encodeURIComponent(`rule:${rule.id}`)}`}>Edit</Link>
                <ActionButton action="disable-rule" payload={{ ruleId: rule.id }}>Disable</ActionButton>
              </div>
            </article>
          );
        })}
      </div>
    </SocShell>
  );
}
