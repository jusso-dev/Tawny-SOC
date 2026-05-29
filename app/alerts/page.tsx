import { CheckSquare, Filter, FolderPlus, PlayCircle, UserPlus } from "lucide-react";
import Link from "next/link";
import { ActionButton } from "@/components/action-button";
import { PageHeader, SocShell } from "@/components/soc-shell";
import { getSocData, relativeTime, severityClass } from "@/lib/soc-domain";
import { filterWithYaaql } from "@/lib/yaaql";

export default async function AlertsPage({ searchParams }: { searchParams?: Promise<{ q?: string }> }) {
  const params = searchParams ? await searchParams : {};
  const { alerts } = await getSocData();
  const filtered = filterWithYaaql(alerts, params.q ?? "");
  const visibleAlerts = filtered.error ? [] : filtered.records;
  const firstAlert = visibleAlerts[0];
  const filters = [
    { label: "Critical/high", query: "severity in (critical, high)" },
    { label: "Open", query: "status=open" },
    { label: "Windows", query: "os=Windows" },
    { label: "PowerShell", query: "powershell" },
    { label: "MITRE mapped", query: "has:mitre" },
    { label: "Unassigned", query: "not has:assignee" },
  ];

  return (
    <SocShell active="/alerts">
      <PageHeader
        eyebrow="Alert queue"
        title="Triage Tawny alerts with entity context, MITRE mapping, and bulk actions."
        actions={<Link className="text-button" href="/alerts?q=status%3Dopen"><Filter size={15} aria-hidden /> Open alerts</Link>}
      />

      <section className="filter-bar" aria-label="Alert filters">
        {filters.map((filter) => (
          <Link className="filter-link" key={filter.label} href={`/alerts?q=${encodeURIComponent(filter.query)}`}>{filter.label}</Link>
        ))}
      </section>
      {filtered.error ? <p className="query-error" role="alert">{filtered.error}</p> : null}

      <section className="bulk-bar" aria-label="Bulk alert actions">
        <ActionButton action="assign-alert" disabled={!firstAlert} payload={{ alertId: firstAlert?.id }}><UserPlus size={15} aria-hidden /> Assign first result</ActionButton>
        <ActionButton action="dismiss-alert" disabled={!firstAlert} payload={{ alertId: firstAlert?.id }}><CheckSquare size={15} aria-hidden /> Dismiss first result</ActionButton>
        <ActionButton action="create-case" disabled={!firstAlert} payload={{ alertId: firstAlert?.id }}><FolderPlus size={15} aria-hidden /> Create case</ActionButton>
        <Link className="primary-action" href="/incidents"><FolderPlus size={15} aria-hidden /> Add to case</Link>
        <Link className="primary-action" href="/playbooks"><PlayCircle size={15} aria-hidden /> Run playbook</Link>
      </section>

      <section className="panel">
        <div className="table-wrap">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Alert</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Status</th>
                <th>Rule</th>
                <th>Source</th>
                <th>Host / user</th>
                <th>Process</th>
                <th>MITRE</th>
                <th>TI</th>
                <th>Assignee</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {visibleAlerts.map((alert) => (
                <tr key={alert.id}>
                  <td>
                    <Link href={`/alerts/${alert.id}`}><strong>{alert.title}</strong></Link>
                    <span>{alert.id}</span>
                  </td>
                  <td><span className={severityClass(alert.severity)}>{alert.severity}</span></td>
                  <td>{Math.round(alert.confidence * 100)}%</td>
                  <td>{alert.status}</td>
                  <td>{alert.matchedRules[0] ?? "Tawny rule"}</td>
                  <td>{alert.source}</td>
                  <td>{alert.hostname ?? "unknown"}<span>{alert.user ?? "unknown user"}</span></td>
                  <td>{alert.process ?? "unknown"}</td>
                  <td>{alert.mitreTechniques.join(", ") || "Needs mapping"}</td>
                  <td>{alert.tiMatches?.length ?? 0}</td>
                  <td>{alert.assignee ?? "Unassigned"}</td>
                  <td>{relativeTime(alert.timestamp)}</td>
                </tr>
              ))}
              {!visibleAlerts.length ? (
                <tr>
                  <td colSpan={12}>No alerts matched.</td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </section>
    </SocShell>
  );
}
