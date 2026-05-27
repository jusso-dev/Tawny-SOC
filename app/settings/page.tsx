import { Bell, Clock, LockKeyhole, Route, ShieldAlert, SlidersHorizontal } from "lucide-react";
import { PageHeader, SocShell } from "@/components/soc-shell";

export default function SettingsPage() {
  const sections = [
    { icon: ShieldAlert, title: "Severity mapping", detail: "Normalize Tawny, Sigma, IOC, and AI severity into SOC severity and priority." },
    { icon: Bell, title: "Notification routing", detail: "Route critical alerts to Slack, Kelpie, Sentinel, webhooks, or email by rule and tenant." },
    { icon: SlidersHorizontal, title: "Suppression rules", detail: "Quiet noisy rules by tenant, host, user, severity, rule ID, and expiry window." },
    { icon: Route, title: "Case numbering", detail: "Configure SOC-* numbering, prefixes, and reset cadence." },
    { icon: Clock, title: "SLA rules", detail: "Set triage, containment, and closure timers by severity and priority." },
    { icon: LockKeyhole, title: "Role permissions", detail: "Control who can dismiss alerts, suppress rules, promote to Kelpie, and run response actions." },
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
              <button>Configure</button>
            </section>
          );
        })}
      </div>
    </SocShell>
  );
}
