import { notFound } from "next/navigation";
import type { ReactNode } from "react";
import { ActionButton } from "@/components/action-button";
import { AdminAccessForms } from "@/components/admin-access-forms";
import { ApiTokenForms } from "@/components/api-token-forms";
import { NotificationRoutingForm } from "@/components/notification-routing-form";
import { RetentionPolicyForm } from "@/components/retention-policy-form";
import {
  SettingsTabs,
  settingsSections,
  type SettingsSectionId,
} from "@/components/settings-navigation";
import { PageHeader, SocShell } from "@/components/soc-shell";
import { SettingsConfigForm } from "@/components/settings-config-form";
import { getSocData } from "@/lib/soc-domain";
import { listApiTokens } from "@/lib/store";
import { requireSession } from "@/lib/session";
import { activeOrganizationId, getTeamState } from "@/lib/team-admin";

type SettingsSectionPageProps = {
  params: Promise<{ section: string }>;
};

export async function generateStaticParams() {
  return settingsSections.map((section) => ({ section: section.id }));
}

export default async function SettingsSectionPage({ params }: SettingsSectionPageProps) {
  const { section: sectionParam } = await params;
  const section = settingsSections.find((item) => item.id === sectionParam);
  if (!section) notFound();

  return (
    <SocShell active="/settings">
      <PageHeader
        eyebrow="Administration"
        title={section.label}
        description={section.description}
      />
      <SettingsTabs active={section.id} />
      <SettingsSectionContent sectionId={section.id} />
    </SocShell>
  );
}

async function SettingsSectionContent({ sectionId }: { sectionId: SettingsSectionId }) {
  if (sectionId === "access") return <AccessSettings />;
  const data = await getSocData();

  if (sectionId === "severity") {
    return (
      <SettingsPanel title="Severity mapping">
        <SettingsConfigForm settingKey="severity" fields={[
          { key: "critical", label: "Critical priority", value: data.settings.severity.critical },
          { key: "high", label: "High priority", value: data.settings.severity.high },
          { key: "medium", label: "Medium priority", value: data.settings.severity.medium },
          { key: "low", label: "Low priority", value: data.settings.severity.low },
        ]} />
      </SettingsPanel>
    );
  }

  if (sectionId === "notifications") {
    return (
      <SettingsPanel title="Notification routing">
        <NotificationRoutingForm channels={data.integrationChannels} routing={data.settings.routing} />
      </SettingsPanel>
    );
  }

  if (sectionId === "suppression") {
    return (
      <SettingsPanel title="Suppression rules">
        <SettingsConfigForm settingKey="suppression" fields={[
          { key: "defaultExpiryHours", label: "Default expiry hours", type: "number", value: data.settings.suppression.defaultExpiryHours },
          { key: "requireReason", label: "Require reason", type: "checkbox", value: data.settings.suppression.requireReason },
        ]} />
      </SettingsPanel>
    );
  }

  if (sectionId === "threat-intel") {
    return (
      <SettingsPanel title="Threat intel retention">
        <SettingsConfigForm settingKey="threatIntel" fields={[
          { key: "defaultTtlDays", label: "Default IOC TTL days", type: "number", min: 1, max: 365, value: data.settings.threatIntel.defaultTtlDays },
        ]} />
      </SettingsPanel>
    );
  }

  if (sectionId === "cases") {
    return (
      <SettingsPanel title="Case numbering">
        <SettingsConfigForm settingKey="caseNumbering" fields={[
          { key: "prefix", label: "Prefix", value: data.settings.caseNumbering.prefix },
          { key: "nextNumber", label: "Next number", type: "number", value: data.settings.caseNumbering.nextNumber },
        ]} />
      </SettingsPanel>
    );
  }

  if (sectionId === "sla") {
    return (
      <SettingsPanel title="SLA rules">
        <SettingsConfigForm settingKey="sla" fields={[
          { key: "criticalMinutes", label: "Critical minutes", type: "number", value: data.settings.sla.criticalMinutes },
          { key: "highMinutes", label: "High minutes", type: "number", value: data.settings.sla.highMinutes },
          { key: "mediumMinutes", label: "Medium minutes", type: "number", value: data.settings.sla.mediumMinutes },
        ]} />
      </SettingsPanel>
    );
  }

  if (sectionId === "permissions") {
    return (
      <SettingsPanel title="Role permissions">
        <SettingsConfigForm settingKey="permissions" fields={[
          { key: "dismissRole", label: "Dismiss role", value: data.settings.permissions.dismissRole },
          { key: "suppressRole", label: "Suppress role", value: data.settings.permissions.suppressRole },
          { key: "kelpieRole", label: "Kelpie role", value: data.settings.permissions.kelpieRole },
        ]} />
      </SettingsPanel>
    );
  }

  if (sectionId === "api-keys") {
    const tokens = await listApiTokens(data.tenantId);
    return <ApiTokenForms tokens={tokens} />;
  }

  if (sectionId === "retention") {
    return (
      <section className="panel">
        <div className="retention-grid">
          {data.retentionPolicies.map((policy) => <RetentionPolicyForm key={policy.target} policy={policy} />)}
        </div>
      </section>
    );
  }

  if (sectionId === "compliance") {
    return (
      <section className="panel">
        <div className="action-bar">
          {["pci-dss", "iso-27001", "nist", "soc-2", "essential-eight"].map((framework) => (
            <ActionButton key={framework} className="primary-action" action="generate-compliance-report" payload={{ framework }}>
              Generate {framework}
            </ActionButton>
          ))}
        </div>
        <div className="table-wrap">
          <table className="soc-table">
            <thead>
              <tr><th>Framework</th><th>Title</th><th>Status</th><th>Generated</th><th>Evidence</th></tr>
            </thead>
            <tbody>
              {data.complianceReports.map((report) => (
                <tr key={report.id}>
                  <td>{report.framework}</td>
                  <td>{report.title}<span>{report.id}</span></td>
                  <td>{report.status}</td>
                  <td>{report.generatedAt ? new Date(report.generatedAt).toLocaleString() : "Not generated"}</td>
                  <td>{report.evidence.join(", ")}</td>
                </tr>
              ))}
              {!data.complianceReports.length ? <tr><td colSpan={5}>No compliance reports have been generated.</td></tr> : null}
            </tbody>
          </table>
        </div>
      </section>
    );
  }

  if (sectionId === "audit") {
    return (
      <section className="panel">
        <div className="table-wrap">
          <table className="soc-table">
            <thead>
              <tr><th>Action</th><th>Actor</th><th>Resource</th><th>Detail</th><th>Time</th></tr>
            </thead>
            <tbody>
              {data.auditLogs.map((entry) => (
                <tr key={entry.id}>
                  <td>{entry.action}</td>
                  <td>{entry.actorName ?? entry.actorId ?? "system"}</td>
                  <td>{entry.resourceType}<span>{entry.resourceId ?? ""}</span></td>
                  <td>{entry.detail ?? "None"}</td>
                  <td>{new Date(entry.createdAt).toLocaleString()}</td>
                </tr>
              ))}
              {!data.auditLogs.length ? <tr><td colSpan={5}>No audit log entries recorded yet.</td></tr> : null}
            </tbody>
          </table>
        </div>
      </section>
    );
  }

  notFound();
}

function SettingsPanel({ children, title }: { children: ReactNode; title: string }) {
  return (
    <section className="panel settings-section-panel">
      <div className="panel-heading">
        <h2>{title}</h2>
      </div>
      {children}
    </section>
  );
}

async function AccessSettings() {
  const session = await requireSession();
  const state = await getTeamState(session.user.id, activeOrganizationId(session));
  const twoFactorEnabled = (session.user as { twoFactorEnabled?: boolean }).twoFactorEnabled === true;

  return (
    <>
      <section className="panel">
        <div className="team-grid">
          <div>
            <span>Members</span>
            <strong>{state.members.length}</strong>
            <p>Users with access to this tenant.</p>
          </div>
          <div>
            <span>Teams</span>
            <strong>{state.teams.length}</strong>
            <p>BetterAuth organization team records.</p>
          </div>
          <div>
            <span>Invites</span>
            <strong>{state.invitations.length}</strong>
            <p>Pending, accepted, and canceled invitations.</p>
          </div>
        </div>
        {!state.available ? (
          <p className="form-message">Postgres is not reachable yet. Start the local database with docker compose up -d db, then run migrations.</p>
        ) : null}
      </section>
      <AdminAccessForms members={state.members} invitations={state.invitations} twoFactorEnabled={twoFactorEnabled} />
    </>
  );
}
