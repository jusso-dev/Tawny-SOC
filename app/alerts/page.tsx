import { CheckSquare, Filter, FolderPlus, PlayCircle, UserPlus } from "lucide-react";
import Link from "next/link";
import { PageHeader, SocShell } from "@/components/soc-shell";
import { getSocData, relativeTime, severityClass } from "@/lib/soc-domain";

export default async function AlertsPage() {
  const { alerts } = await getSocData();

  return (
    <SocShell active="/alerts">
      <PageHeader
        eyebrow="Alert queue"
        title="Triage Tawny alerts with entity context, MITRE mapping, and bulk actions."
        actions={<button className="text-button"><Filter size={15} aria-hidden /> Filters</button>}
      />

      <section className="filter-bar" aria-label="Alert filters">
        {["Severity", "Status", "Source", "Host", "User", "MITRE", "Rule", "TI match", "Assigned"].map((filter) => (
          <button key={filter}>{filter}</button>
        ))}
      </section>

      <section className="bulk-bar" aria-label="Bulk alert actions">
        <button><UserPlus size={15} aria-hidden /> Assign</button>
        <button><CheckSquare size={15} aria-hidden /> Dismiss</button>
        <button><FolderPlus size={15} aria-hidden /> Create case</button>
        <button><FolderPlus size={15} aria-hidden /> Add to case</button>
        <button><PlayCircle size={15} aria-hidden /> Run playbook</button>
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
              {alerts.map((alert) => (
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
            </tbody>
          </table>
        </div>
      </section>
    </SocShell>
  );
}
