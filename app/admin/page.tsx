import { desc, eq } from "drizzle-orm";
import { UsersRound } from "lucide-react";
import { AdminAccessForms } from "@/components/admin-access-forms";
import { PageHeader, SocShell } from "@/components/soc-shell";
import { db, schema } from "@/lib/db/client";
import { requireSession } from "@/lib/session";

async function getTeamState(userId: string, sessionOrgId?: string | null) {
  try {
    const tenantId = sessionOrgId ?? (await db.select().from(schema.member).where(eq(schema.member.userId, userId)).limit(1))[0]?.organizationId ?? "local-tenant";
    const [members, invitations, teams] = await Promise.all([
      db.select({
        id: schema.member.id,
        role: schema.member.role,
        createdAt: schema.member.createdAt,
        email: schema.user.email,
        name: schema.user.name,
      })
        .from(schema.member)
        .leftJoin(schema.user, eq(schema.member.userId, schema.user.id))
        .where(eq(schema.member.organizationId, tenantId))
        .orderBy(desc(schema.member.createdAt))
        .limit(100),
      db.select().from(schema.invitation)
        .where(eq(schema.invitation.organizationId, tenantId))
        .orderBy(desc(schema.invitation.createdAt))
        .limit(100),
      db.select().from(schema.team)
        .where(eq(schema.team.organizationId, tenantId))
        .orderBy(desc(schema.team.createdAt))
        .limit(20),
    ]);
    return {
      tenantId,
      members: members.map((member) => ({
        id: member.id,
        role: member.role,
        createdAt: member.createdAt.toISOString(),
        email: member.email ?? "unknown",
        name: member.name ?? "Unknown user",
      })),
      invitations: invitations.map((invite) => ({
        id: invite.id,
        email: invite.email,
        role: invite.role,
        status: invite.status,
        createdAt: invite.createdAt.toISOString(),
        expiresAt: invite.expiresAt?.toISOString(),
      })),
      teams,
      available: true,
    };
  } catch {
    return { tenantId: "local-tenant", members: [], invitations: [], teams: [], available: false };
  }
}

export default async function AdminPage() {
  const session = await requireSession();
  const sessionOrgId = (session.session as { activeOrganizationId?: string | null }).activeOrganizationId;
  const state = await getTeamState(session.user.id, sessionOrgId);
  const twoFactorEnabled = (session.user as { twoFactorEnabled?: boolean }).twoFactorEnabled === true;

  return (
    <SocShell active="/settings">
      <PageHeader
        eyebrow="Team management"
        title="Manage SOC access, invitations, magic links, and MFA posture."
        description={`Signed in as ${session.user.email}`}
      />

      <section className="panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Tenant</p>
            <h2>{state.tenantId}</h2>
          </div>
          <UsersRound size={18} aria-hidden />
        </div>
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
    </SocShell>
  );
}
