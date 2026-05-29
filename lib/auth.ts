import { drizzleAdapter } from "@better-auth/drizzle-adapter";
import { betterAuth } from "better-auth";
import { haveIBeenPwned, magicLink, organization, twoFactor } from "better-auth/plugins";
import { nextCookies } from "better-auth/next-js";
import { db, schema } from "@/lib/db/client";
import { sendEmail } from "@/emails/send";

const appUrl = process.env.NEXT_PUBLIC_APP_URL ?? process.env.BETTER_AUTH_URL ?? "http://localhost:3001";

export const auth = betterAuth({
  appName: "Tawny-SOC",
  baseURL: process.env.BETTER_AUTH_URL ?? appUrl,
  secret: process.env.BETTER_AUTH_SECRET ?? "dev-only-change-me-change-me-change-me",
  trustedOrigins: [appUrl],
  database: drizzleAdapter(db, {
    provider: "pg",
    schema,
  }),
  emailAndPassword: {
    enabled: true,
    requireEmailVerification: false,
  },
  plugins: [
    organization({
      teams: {
        enabled: true,
        maximumTeams: 25,
        allowRemovingAllTeams: false,
      },
      requireEmailVerificationOnInvitation: false,
      sendInvitationEmail: async ({ id, email, organization }) => {
        const inviteUrl = `${appUrl}/accept-invite?invitationId=${encodeURIComponent(id)}`;
        await sendEmail({
          to: email,
          subject: `Join ${organization.name} on Tawny-SOC`,
          text: `Use this link to join ${organization.name} on Tawny-SOC: ${inviteUrl}`,
          tenantId: organization.id,
        });
      },
    }),
    twoFactor({
      issuer: "Tawny-SOC",
      allowPasswordless: true,
    }),
    magicLink({
      sendMagicLink: async ({ email, url, metadata }) => {
        await sendEmail({
          to: email,
          subject: "Sign in to Tawny-SOC",
          text: `Use this link to sign in to Tawny-SOC: ${url}`,
          tenantId: typeof metadata?.tenantId === "string" ? metadata.tenantId : undefined,
        });
      },
    }),
    haveIBeenPwned(),
    nextCookies(),
  ],
});

export type AuthSession = typeof auth.$Infer.Session;
