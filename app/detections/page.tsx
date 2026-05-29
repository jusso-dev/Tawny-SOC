import { Braces, Copy, GitBranch, PlayCircle, Upload } from "lucide-react";
import Link from "next/link";
import { ActionButton } from "@/components/action-button";
import { PageHeader, SocShell } from "@/components/soc-shell";
import { SigmaImportForm } from "@/components/sigma-import-form";
import {
  runSummaryRules,
  starterDetectionPack,
  validateDetectionPack,
} from "@/lib/detections";
import { getSocData, relativeTime, severityClass } from "@/lib/soc-domain";
import type { SocEvent } from "@/lib/types";

export default async function DetectionsPage() {
  const { rules, alerts, events } = await getSocData();
  const records = [...alerts, ...events];
  const packIssues = validateDetectionPack(starterDetectionPack);
  const summarySignals = runSummaryRules(records, starterDetectionPack.summaryRules, { now: latestRecordTime(records) ?? new Date() }).slice(0, 6);

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

      <section className="panel detection-pack-panel">
        <div className="panel-heading">
          <div>
            <span className="status status-watch">GitOps ready</span>
            <h2>{starterDetectionPack.name}</h2>
            <p>{starterDetectionPack.description}</p>
          </div>
          <span className={packIssues.some((issue) => issue.level === "error") ? "severity severity-high" : "status status-healthy"}>
            {packIssues.some((issue) => issue.level === "error") ? "Needs work" : "Valid pack"}
          </span>
        </div>
        <dl className="detail-grid">
          <div><dt>Version</dt><dd>{starterDetectionPack.version}</dd></div>
          <div><dt>Rules</dt><dd>{starterDetectionPack.detections.length}</dd></div>
          <div><dt>Summary rules</dt><dd>{starterDetectionPack.summaryRules.length}</dd></div>
          <div><dt>Repository path</dt><dd>{starterDetectionPack.repository?.path}</dd></div>
          <div><dt>CI command</dt><dd>{starterDetectionPack.repository?.ciCommand}</dd></div>
          <div><dt>Validation</dt><dd>{packIssues.length ? `${packIssues.length} issue${packIssues.length === 1 ? "" : "s"}` : "No issues"}</dd></div>
        </dl>
        <div className="table-wrap">
          <table className="soc-table">
            <thead>
              <tr><th>Summary signal</th><th>Severity</th><th>Group</th><th>Count</th><th>Window</th><th>Evidence</th></tr>
            </thead>
            <tbody>
              {summarySignals.map((signal) => (
                <tr key={`${signal.ruleId}-${signal.groupKey}`}>
                  <td><strong>{signal.ruleName}</strong><span>{signal.summary}</span></td>
                  <td><span className={severityClass(signal.severity)}>{signal.severity}</span></td>
                  <td>{Object.entries(signal.groupValues).map(([key, value]) => `${key}: ${value}`).join(", ")}</td>
                  <td>{signal.uniqueCount ? `${signal.uniqueCount} unique / ${signal.count} records` : signal.count}</td>
                  <td>{relativeTime(signal.startedAt)} to {relativeTime(signal.endedAt)}</td>
                  <td>{signal.recordIds.slice(0, 4).join(", ")}{signal.recordIds.length > 4 ? "..." : ""}</td>
                </tr>
              ))}
              {!summarySignals.length ? <tr><td colSpan={6}>No summary signals crossed a threshold in the current retained records.</td></tr> : null}
            </tbody>
          </table>
        </div>
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

function latestRecordTime(records: SocEvent[]) {
  const timestamps = records
    .map((record) => Date.parse(record.timestamp))
    .filter((timestamp) => Number.isFinite(timestamp));
  if (!timestamps.length) return undefined;
  return new Date(Math.max(...timestamps));
}
