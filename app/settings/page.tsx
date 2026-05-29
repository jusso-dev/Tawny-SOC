import { Bell, Clock, LockKeyhole, RadioTower, Route, ShieldAlert, SlidersHorizontal, UsersRound, type LucideIcon } from "lucide-react";
import Link from "next/link";
import { PageHeader, SocShell } from "@/components/soc-shell";
import { SettingsConfigForm } from "@/components/settings-config-form";
import { getSocData } from "@/lib/soc-domain";

type SettingSection = {
  icon: LucideIcon;
  title: string;
  detail: string;
  settingKey?: string;
  href?: string;
  fields?: Array<{ key: string; label: string; max?: number; min?: number; type?: "text" | "number" | "checkbox"; value?: unknown }>;
};

export default async function SettingsPage() {
  const { settings } = await getSocData();
  const sections: SettingSection[] = [
    {
      icon: ShieldAlert,
      title: "Severity mapping",
      detail: "Normalize Tawny, Sigma, IOC, and AI severity into SOC severity and priority.",
      settingKey: "severity",
      fields: [
        { key: "critical", label: "Critical priority", value: settings.severity.critical },
        { key: "high", label: "High priority", value: settings.severity.high },
        { key: "medium", label: "Medium priority", value: settings.severity.medium },
        { key: "low", label: "Low priority", value: settings.severity.low },
      ],
    },
    {
      icon: Bell,
      title: "Notification routing",
      detail: "Route critical alerts to Slack, Kelpie, Sentinel, webhooks, or email by rule and tenant.",
      settingKey: "routing",
      fields: [
        { key: "criticalChannel", label: "Critical channel", value: settings.routing.criticalChannel },
        { key: "highChannel", label: "High channel", value: settings.routing.highChannel },
        { key: "defaultAssignee", label: "Default assignee", value: settings.routing.defaultAssignee },
      ],
    },
    {
      icon: SlidersHorizontal,
      title: "Suppression rules",
      detail: "Quiet noisy rules by tenant, host, user, severity, rule ID, and expiry window.",
      settingKey: "suppression",
      fields: [
        { key: "defaultExpiryHours", label: "Default expiry hours", type: "number", value: settings.suppression.defaultExpiryHours },
        { key: "requireReason", label: "Require reason", type: "checkbox", value: settings.suppression.requireReason },
      ],
    },
    {
      icon: RadioTower,
      title: "Threat intel retention",
      detail: "Set the default time-to-live for OSINT indicators loaded from tenant feeds.",
      settingKey: "threatIntel",
      fields: [
        { key: "defaultTtlDays", label: "Default IOC TTL days", type: "number", min: 1, max: 365, value: settings.threatIntel.defaultTtlDays },
      ],
    },
    {
      icon: Route,
      title: "Case numbering",
      detail: "Configure SOC numbering, prefixes, and reset cadence.",
      settingKey: "caseNumbering",
      fields: [
        { key: "prefix", label: "Prefix", value: settings.caseNumbering.prefix },
        { key: "nextNumber", label: "Next number", type: "number", value: settings.caseNumbering.nextNumber },
      ],
    },
    {
      icon: Clock,
      title: "SLA rules",
      detail: "Set triage, containment, and closure timers by severity and priority.",
      settingKey: "sla",
      fields: [
        { key: "criticalMinutes", label: "Critical minutes", type: "number", value: settings.sla.criticalMinutes },
        { key: "highMinutes", label: "High minutes", type: "number", value: settings.sla.highMinutes },
        { key: "mediumMinutes", label: "Medium minutes", type: "number", value: settings.sla.mediumMinutes },
      ],
    },
    {
      icon: LockKeyhole,
      title: "Role permissions",
      detail: "Control who can dismiss alerts, suppress rules, promote to Kelpie, and run response actions.",
      settingKey: "permissions",
      fields: [
        { key: "dismissRole", label: "Dismiss role", value: settings.permissions.dismissRole },
        { key: "suppressRole", label: "Suppress role", value: settings.permissions.suppressRole },
        { key: "kelpieRole", label: "Kelpie role", value: settings.permissions.kelpieRole },
      ],
    },
    {
      icon: UsersRound,
      title: "Team admin",
      detail: "Manage SOC access, organization members, teams, invitations, and MFA posture.",
      href: "/admin",
    },
  ];

  return (
    <SocShell active="/settings">
      <PageHeader
        eyebrow="Administration"
        title="SOC settings for routing, suppression, SLAs, threat intel, Kelpie sync, and permissions."
      />

      <div className="settings-grid">
        {sections.map((section) => {
          const Icon = section.icon;
          return (
            <section className="panel settings-card" key={section.title}>
              <Icon size={18} aria-hidden />
              <h2>{section.title}</h2>
              <p>{section.detail}</p>
              {section.href ? (
                <Link className="primary-action" href={section.href}>Open</Link>
              ) : section.settingKey && section.fields ? (
                <SettingsConfigForm settingKey={section.settingKey} fields={section.fields} />
              ) : (
                null
              )}
            </section>
          );
        })}
      </div>
    </SocShell>
  );
}
