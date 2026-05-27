import { relations } from "drizzle-orm";
import { index, pgTable, text, timestamp, uniqueIndex } from "drizzle-orm/pg-core";
import { user } from "./auth";

export const organization = pgTable("organization", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  slug: text("slug").notNull().unique(),
  logo: text("logo"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export const member = pgTable("member", {
  id: text("id").primaryKey(),
  organizationId: text("organization_id").notNull().references(() => organization.id, { onDelete: "cascade" }),
  userId: text("user_id").notNull().references(() => user.id, { onDelete: "cascade" }),
  role: text("role").notNull().default("member"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("member_org_idx").on(table.organizationId),
  index("member_user_idx").on(table.userId),
  uniqueIndex("member_org_user_idx").on(table.organizationId, table.userId),
]);

export const invitation = pgTable("invitation", {
  id: text("id").primaryKey(),
  organizationId: text("organization_id").notNull().references(() => organization.id, { onDelete: "cascade" }),
  email: text("email").notNull(),
  role: text("role").notNull().default("member"),
  status: text("status").notNull().default("pending"),
  teamId: text("team_id"),
  expiresAt: timestamp("expires_at", { withTimezone: true }),
  inviterId: text("inviter_id").notNull().references(() => user.id, { onDelete: "cascade" }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("invitation_org_idx").on(table.organizationId),
  index("invitation_email_idx").on(table.email),
]);

export const team = pgTable("team", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  organizationId: text("organization_id").notNull().references(() => organization.id, { onDelete: "cascade" }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("team_org_idx").on(table.organizationId),
]);

export const teamMember = pgTable("team_member", {
  id: text("id").primaryKey(),
  teamId: text("team_id").notNull().references(() => team.id, { onDelete: "cascade" }),
  userId: text("user_id").notNull().references(() => user.id, { onDelete: "cascade" }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("team_member_team_idx").on(table.teamId),
  index("team_member_user_idx").on(table.userId),
  uniqueIndex("team_member_team_user_idx").on(table.teamId, table.userId),
]);

export const organizationRelations = relations(organization, ({ many }) => ({
  members: many(member),
  invitations: many(invitation),
  teams: many(team),
}));
