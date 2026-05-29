import { FolderPlus, Send } from "lucide-react";
import Link from "next/link";
import { ActionButton } from "@/components/action-button";
import { PageHeader, SocShell } from "@/components/soc-shell";
import { getSocData, relativeTime, severityClass } from "@/lib/soc-domain";

export default async function IncidentsPage() {
  const { incidents } = await getSocData();

  return (
    <SocShell active="/incidents">
      <PageHeader
        eyebrow="Incidents and cases"
        title="Group alerts into native Tawny cases, then sync to Kelpie when the investigation needs case management depth."
        actions={<Link className="text-button" href="/alerts"><FolderPlus size={15} aria-hidden /> New case from alert</Link>}
      />

      <section className="panel">
        <div className="table-wrap">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Case</th>
                <th>Severity</th>
                <th>Priority</th>
                <th>Status</th>
                <th>Assignee</th>
                <th>TLP / PAP</th>
                <th>Classification</th>
                <th>Hosts</th>
                <th>Alerts</th>
                <th>Kelpie</th>
                <th>Updated</th>
              </tr>
            </thead>
            <tbody>
              {incidents.map((incident) => (
                <tr key={incident.id}>
                  <td>
                    <Link href={`/incidents/${incident.id}`}><strong>{incident.number}</strong></Link>
                    <span>{incident.title}</span>
                  </td>
                  <td><span className={severityClass(incident.severity)}>{incident.severity}</span></td>
                  <td>{incident.priority}</td>
                  <td>{incident.status}</td>
                  <td>{incident.assignee ?? "Unassigned"}</td>
                  <td>{incident.tlp} / {incident.pap}</td>
                  <td>{incident.classification.replace("_", " ")}</td>
                  <td>{incident.linkedHosts.join(", ") || "None"}</td>
                  <td>{incident.linkedAlertIds.length}</td>
                  <td>
                    {incident.kelpieUrl ? (
                      <Link href={incident.kelpieUrl}>Open</Link>
                    ) : (
                      <ActionButton className="inline-action" action="sync-incident-kelpie" payload={{ incidentId: incident.id }}><Send size={14} aria-hidden /> Sync</ActionButton>
                    )}
                    <span>{incident.kelpieSyncStatus.replace("_", " ")}</span>
                  </td>
                  <td>{relativeTime(incident.updatedAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </SocShell>
  );
}
