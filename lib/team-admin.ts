import { desc, eq } from "drizzle-orm";
import { db, schema } from "@/lib/db/client";
import type { AuthSession } from "@/lib/auth";

export async function getTeamState(userId: string, sessionOrgId?: string | null) {
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
      available: true,
      invitations: invitations.map((invite) => ({
        id: invite.id,
        email: invite.email,
        role: invite.role,
        status: invite.status,
        createdAt: invite.createdAt.toISOString(),
        expiresAt: invite.expiresAt?.toISOString(),
      })),
      members: members.map((member) => ({
        id: member.id,
        role: member.role,
        createdAt: member.createdAt.toISOString(),
        email: member.email ?? "unknown",
        name: member.name ?? "Unknown user",
      })),
      teams,
      tenantId,
    };
  } catch {
    return { tenantId: "local-tenant", members: [], invitations: [], teams: [], available: false };
  }
}

export function activeOrganizationId(session: AuthSession) {
  return (session.session as { activeOrganizationId?: string | null }).activeOrganizationId;
}
