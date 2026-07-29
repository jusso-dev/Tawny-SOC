import {
  Activity,
  AlertTriangle,
  BrainCircuit,
  Braces,
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
import { requireSession } from "@/lib/session";

const navGroups = [
  {
    label: "Operations",
    items: [
      { href: "/", label: "SOC Overview", icon: Activity },
      { href: "/alerts", label: "Alert Queue", icon: AlertTriangle },
      { href: "/incidents", label: "Incidents", icon: FolderKanban },
    ],
  },
  {
    label: "Detection",
    items: [
      { href: "/detections", label: "Detection Rules", icon: Braces },
      { href: "/ueba", label: "UEBA Behavior", icon: BrainCircuit },
      { href: "/threat-intel", label: "Threat Intel", icon: RadioTower },
      { href: "/playbooks", label: "Playbooks", icon: Workflow },
      { href: "/hunt", label: "Search / Hunt", icon: Search },
    ],
  },
  {
    label: "Platform",
    items: [
      { href: "/integrations", label: "Integrations", icon: DatabaseZap },
      { href: "/settings", label: "SOC Settings", icon: Settings },
    ],
  },
];

function isActive(active: string, href: string) {
  if (href === "/") return active === "/";
  return active === href || active.startsWith(`${href}/`);
}

export async function SocShell({ children, active }: { children: React.ReactNode; active: string }) {
  const session = await requireSession();
  const email = session.user?.email ?? "analyst";
  const name = session.user?.name ?? email.split("@")[0];

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-inner">
          <div className="sidebar-header">
            <Link href="/" className="brand" aria-label="Tawny-SOC overview">
              <div className="brand-mark">
                <ShieldAlert size={18} aria-hidden />
              </div>
              <div className="brand-copy">
                <strong>Tawny-SOC</strong>
                <span>EDR-native SIEM</span>
              </div>
            </Link>
            <span className="brand-badge">v0.1</span>
          </div>

          <nav className="sidebar-nav" aria-label="SIEM navigation">
            {navGroups.map((group) => (
              <div key={group.label} className="nav-group">
                <p className="nav-group-label">{group.label}</p>
                <div className="nav-group-items">
                  {group.items.map((item) => {
                    const Icon = item.icon;
                    const activeItem = isActive(active, item.href);
                    return (
                      <Link
                        key={item.href}
                        className={activeItem ? "nav-item active" : "nav-item"}
                        href={item.href}
                        aria-current={activeItem ? "page" : undefined}
                      >
                        <Icon size={16} aria-hidden />
                        <span>{item.label}</span>
                      </Link>
                    );
                  })}
                </div>
              </div>
            ))}
          </nav>

          <div className="sidebar-footer">
            <div className="nav-user">
              <div className="nav-user-avatar" aria-hidden>
                {name.slice(0, 1).toUpperCase()}
              </div>
              <div className="nav-user-copy">
                <strong>{name}</strong>
                <span>{email}</span>
              </div>
            </div>
            <div className="trust-box">
              <ShieldAlert size={14} aria-hidden />
              <p>Operational changes are recorded in the SOC timeline.</p>
            </div>
          </div>
        </div>
      </aside>

      <div className="shell-inset">
        <header className="shell-header">
          <div className="shell-header-left">
            <p className="shell-kicker">Tawny-SOC</p>
            <p className="shell-header-title">Analyst workspace</p>
          </div>
          <div className="shell-header-actions">
            <ThemeToggle />
          </div>
        </header>
        <main className="workspace">{children}</main>
      </div>
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
