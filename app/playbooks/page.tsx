import { PlayCircle } from "lucide-react";
import Link from "next/link";
import { ActionButton } from "@/components/action-button";
import { PageHeader, SocShell } from "@/components/soc-shell";
import { getSocData, severityClass } from "@/lib/soc-domain";

export default async function PlaybooksPage() {
  const { playbooks, incidents } = await getSocData();
  const targetIncident = incidents[0];

  return (
    <SocShell active="/playbooks">
      <PageHeader
        eyebrow="Playbooks"
        title="Run ordered SOC workflows against cases and create tasks with evidence requirements."
        actions={targetIncident ? (
          <ActionButton className="text-button" action="run-playbook" payload={{ incidentId: targetIncident.id }}><PlayCircle size={15} aria-hidden /> Run on newest case</ActionButton>
        ) : (
          <Link className="text-button" href="/alerts"><PlayCircle size={15} aria-hidden /> Create a case first</Link>
        )}
      />

      <div className="playbook-catalog">
        {playbooks.map((playbook) => (
          <article className="panel playbook-card" key={playbook.id}>
            <div className="panel-heading">
              <div>
                <span className={severityClass(playbook.severity)}>{playbook.severity}</span>
                <h2>{playbook.name}</h2>
                <p>{playbook.description}</p>
              </div>
              <ActionButton className="primary-action" action="run-playbook" disabled={!targetIncident} payload={{ incidentId: targetIncident?.id, playbookId: playbook.id }}>
                <PlayCircle size={15} aria-hidden /> Run
              </ActionButton>
            </div>
            <div className="tag-row">
              {playbook.triggers.map((trigger) => <span key={trigger}>{trigger}</span>)}
            </div>
            <div className="phase-list">
              {playbook.phases.map((phase, index) => (
                <article key={phase.name}>
                  <span>{index + 1}</span>
                  <div>
                    <strong>{phase.name}</strong>
                    <p>{phase.objective}</p>
                    <small>Owner: {phase.owner} · Evidence: {phase.actions.slice(0, 2).join(", ")}</small>
                  </div>
                </article>
              ))}
            </div>
          </article>
        ))}
      </div>
    </SocShell>
  );
}
