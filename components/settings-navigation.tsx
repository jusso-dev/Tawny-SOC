import {
  Bell,
  Clock,
  FileText,
  KeyRound,
  LockKeyhole,
  RadioTower,
  Route,
  ScrollText,
  ShieldAlert,
  SlidersHorizontal,
  UsersRound,
  type LucideIcon,
} from "lucide-react";
import Link from "next/link";

export type SettingsSectionId =
  | "severity"
  | "notifications"
  | "suppression"
  | "threat-intel"
  | "cases"
  | "sla"
  | "permissions"
  | "api-keys"
  | "access"
  | "retention"
  | "compliance"
  | "audit";

export type SettingsCategory = "operations" | "access" | "integrations" | "governance";

export type SettingsSection = {
  category: SettingsCategory;
  description: string;
  href: string;
  icon: LucideIcon;
  id: SettingsSectionId;
  label: string;
};

export const settingsCategories: Array<{ id: "all" | SettingsCategory; label: string }> = [
  { id: "all", label: "All" },
  { id: "operations", label: "Operations" },
  { id: "access", label: "Access" },
  { id: "integrations", label: "Integrations" },
  { id: "governance", label: "Governance" },
];

export const settingsSections: SettingsSection[] = [
  {
    category: "operations",
    description: "Normalize Tawny, Sigma, IOC, and AI severities into SOC priorities.",
    href: "/settings/severity",
    icon: ShieldAlert,
    id: "severity",
    label: "Severity mapping",
  },
  {
    category: "operations",
    description: "Route alert severities to configured channels and escalation policies.",
    href: "/settings/notifications",
    icon: Bell,
    id: "notifications",
    label: "Notification routing",
  },
  {
    category: "operations",
    description: "Control noisy rule suppression defaults and required analyst context.",
    href: "/settings/suppression",
    icon: SlidersHorizontal,
    id: "suppression",
    label: "Suppression rules",
  },
  {
    category: "operations",
    description: "Set the default TTL for indicators loaded from threat intelligence feeds.",
    href: "/settings/threat-intel",
    icon: RadioTower,
    id: "threat-intel",
    label: "Threat intel",
  },
  {
    category: "operations",
    description: "Configure case numbering and SLA timers for incident handling.",
    href: "/settings/cases",
    icon: Route,
    id: "cases",
    label: "Case numbering",
  },
  {
    category: "operations",
    description: "Set triage and response timers by severity.",
    href: "/settings/sla",
    icon: Clock,
    id: "sla",
    label: "SLA rules",
  },
  {
    category: "access",
    description: "Control roles for sensitive alert, detection, integration, and settings actions.",
    href: "/settings/permissions",
    icon: LockKeyhole,
    id: "permissions",
    label: "Role permissions",
  },
  {
    category: "access",
    description: "Manage members, invitations, magic links, and MFA posture.",
    href: "/settings/access",
    icon: UsersRound,
    id: "access",
    label: "Team access",
  },
  {
    category: "integrations",
    description: "Create tenant API tokens with role-limited scopes.",
    href: "/settings/api-keys",
    icon: KeyRound,
    id: "api-keys",
    label: "API tokens",
  },
  {
    category: "governance",
    description: "Control hot, archive, and deletion windows across SOC data.",
    href: "/settings/retention",
    icon: ScrollText,
    id: "retention",
    label: "Retention policies",
  },
  {
    category: "governance",
    description: "Generate audit evidence packs for common compliance frameworks.",
    href: "/settings/compliance",
    icon: FileText,
    id: "compliance",
    label: "Compliance reports",
  },
  {
    category: "governance",
    description: "Review tenant configuration, workflow, token, and integration audit events.",
    href: "/settings/audit",
    icon: ScrollText,
    id: "audit",
    label: "Audit log",
  },
];

export function SettingsTabs({ active }: { active?: SettingsSectionId | "overview" }) {
  return (
    <div aria-label="Settings sections" className="settings-tabs" role="tablist">
      <Link className={active === "overview" ? "active" : ""} href="/settings">Overview</Link>
      {settingsSections.map((section) => (
        <Link className={active === section.id ? "active" : ""} href={section.href} key={section.id}>{section.label}</Link>
      ))}
    </div>
  );
}
