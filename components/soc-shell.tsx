import {
  Activity,
  AlertTriangle,
  Braces,
  ClipboardList,
  DatabaseZap,
  FolderKanban,
  RadioTower,
  Search,
  Settings,
  ShieldAlert,
  Workflow,
} from "lucide-react";
import Link from "next/link";
import { ThemeToggle } from "@/components/theme-toggle";

const nav = [
  { href: "/", label: "SOC Overview", icon: Activity },
  { href: "/alerts", label: "Alert Queue", icon: AlertTriangle },
  { href: "/incidents", label: "Incidents", icon: FolderKanban },
  { href: "/detections", label: "Detection Rules", icon: Braces },
  { href: "/threat-intel", label: "Threat Intel", icon: RadioTower },
  { href: "/playbooks", label: "Playbooks", icon: Workflow },
  { href: "/hunt", label: "Search / Hunt", icon: Search },
  { href: "/integrations", label: "Integrations", icon: DatabaseZap },
  { href: "/settings", label: "SOC Settings", icon: Settings },
];

export function SocShell({ children, active }: { children: React.ReactNode; active: string }) {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <Link href="/" className="brand" aria-label="Tawny-SOC overview">
          <div className="brand-mark">
            <ShieldAlert size={18} aria-hidden />
          </div>
          <div>
            <strong>Tawny-SOC</strong>
            <span>EDR-native SIEM</span>
          </div>
        </Link>
        <nav aria-label="SIEM navigation">
          {nav.map((item) => {
            const Icon = item.icon;
            return (
              <Link key={item.href} className={active === item.href ? "active" : undefined} href={item.href}>
                <Icon size={16} aria-hidden />
                {item.label}
              </Link>
            );
          })}
        </nav>
        <div className="sidebar-actions">
          <Link className="text-button full" href="/admin">
            <ClipboardList size={15} aria-hidden />
            Team admin
          </Link>
          <ThemeToggle />
        </div>
        <div className="trust-box">
          <ShieldAlert size={16} aria-hidden />
          <p>Every alert, case change, Kelpie sync, suppression, and playbook task should stay audit-ready.</p>
        </div>
      </aside>
      <main className="workspace">{children}</main>
    </div>
  );
}

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow: string;
  title: string;
  description?: string;
  actions?: React.ReactNode;
}) {
  return (
    <header className="topbar page-header">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h1>{title}</h1>
        {description ? <p className="page-description">{description}</p> : null}
      </div>
      {actions ? <div className="topbar-actions">{actions}</div> : null}
    </header>
  );
}
