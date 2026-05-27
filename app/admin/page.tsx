import { desc } from "drizzle-orm";
import { UsersRound } from "lucide-react";
import { requireSession } from "@/lib/session";
import { db, schema } from "@/lib/db/client";
import { ThemeToggle } from "@/components/theme-toggle";

async function getTeamState() {
  try {
    const [members, teams, invitations] = await Promise.all([
      db.select().from(schema.member).orderBy(desc(schema.member.createdAt)).limit(20),
      db.select().from(schema.team).orderBy(desc(schema.team.createdAt)).limit(20),
      db.select().from(schema.invitation).orderBy(desc(schema.invitation.createdAt)).limit(20),
    ]);
    return { members, teams, invitations, available: true };
  } catch {
    return { members: [], teams: [], invitations: [], available: false };
  }
}

export default async function AdminPage() {
  const session = await requireSession();
  const state = await getTeamState();

  return (
    <main className="workspace standalone">
      <header className="topbar">
        <div>
          <p className="eyebrow">Team management</p>
          <h1>Manage SOC access, teams, invitations, and MFA posture.</h1>
        </div>
        <ThemeToggle />
      </header>

      <section className="panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Signed in</p>
            <h2>{session.user.email}</h2>
          </div>
          <UsersRound size={18} aria-hidden />
        </div>
        <div className="team-grid">
          <div>
            <span>Members</span>
            <strong>{state.members.length}</strong>
            <p>BetterAuth organization members.</p>
          </div>
          <div>
            <span>Teams</span>
            <strong>{state.teams.length}</strong>
            <p>Team records are enabled through the organization plugin.</p>
          </div>
          <div>
            <span>Invites</span>
            <strong>{state.invitations.length}</strong>
            <p>Invitation rows support role and team assignment.</p>
          </div>
        </div>
        {!state.available ? (
          <p className="form-message">Postgres is not reachable yet. Start Docker or run migrations before managing teams.</p>
        ) : null}
      </section>
    </main>
  );
}
