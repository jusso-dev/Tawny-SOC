import { drizzleAdapter } from "@better-auth/drizzle-adapter";
import { betterAuth } from "better-auth";
import { admin, haveIBeenPwned, magicLink, organization, twoFactor } from "better-auth/plugins";
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
    }),
    twoFactor({
      issuer: "Tawny-SOC",
      allowPasswordless: true,
    }),
    magicLink({
      sendMagicLink: async ({ email, url }) => {
        await sendEmail({
          to: email,
          subject: "Sign in to Tawny-SOC",
          text: `Use this link to sign in to Tawny-SOC: ${url}`,
        });
      },
    }),
    haveIBeenPwned(),
    admin(),
    nextCookies(),
  ],
});

export type AuthSession = typeof auth.$Infer.Session;
