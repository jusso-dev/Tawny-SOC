import Link from "next/link";
import {
  SettingsTabs,
  settingsCategories,
  settingsSections,
  type SettingsCategory,
} from "@/components/settings-navigation";
import { PageHeader, SocShell } from "@/components/soc-shell";

type SettingsPageProps = {
  searchParams?: Promise<{ tab?: string }>;
};

function parseTab(value?: string): SettingsCategory | "all" {
  return value === "operations" || value === "access" || value === "integrations" || value === "governance" ? value : "all";
}

export default async function SettingsPage({ searchParams }: SettingsPageProps) {
  const params = searchParams ? await searchParams : {};
  const activeTab = parseTab(params.tab);
  const sections = activeTab === "all"
    ? settingsSections
    : settingsSections.filter((section) => section.category === activeTab);

  return (
    <SocShell active="/settings">
      <PageHeader
        eyebrow="Administration"
        title="SOC settings"
        description="Pick a section to configure routing, access, API tokens, retention, compliance, and audit controls."
      />

      <SettingsTabs active="overview" />

      <div className="settings-filter-tabs" role="tablist" aria-label="Settings category filters">
        {settingsCategories.map((category) => (
          <Link
            aria-selected={activeTab === category.id}
            className={activeTab === category.id ? "active" : ""}
            href={category.id === "all" ? "/settings" : `/settings?tab=${category.id}`}
            key={category.id}
          >
            {category.label}
          </Link>
        ))}
      </div>

      <div className="settings-grid">
        {sections.map((section) => {
          const Icon = section.icon;
          return (
            <section className="panel settings-card" key={section.id}>
              <Icon size={18} aria-hidden />
              <h2>{section.label}</h2>
              <p>{section.description}</p>
              <Link className="primary-action" href={section.href}>Open</Link>
            </section>
          );
        })}
      </div>
    </SocShell>
  );
}
