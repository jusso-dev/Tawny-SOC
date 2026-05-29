import Link from "next/link";
import { requireSession } from "@/lib/session";
import { AcceptInviteForm } from "./accept-invite-form";

export default async function AcceptInvitePage({ searchParams }: { searchParams: Promise<{ invitationId?: string }> }) {
  await requireSession();
  const { invitationId = "" } = await searchParams;

  return (
    <main className="auth-page">
      <section className="auth-panel">
        <p className="eyebrow">Tawny-SOC</p>
        <h1>Accept tenant invitation</h1>
        <p className="auth-copy">Join the SOC tenant tied to this invitation.</p>
        {invitationId ? <AcceptInviteForm invitationId={invitationId} /> : <p className="form-message">The invitation link is missing its invitation ID.</p>}
        <p className="auth-footer">
          Need a different account? <Link href="/sign-in">Sign in</Link>
        </p>
      </section>
    </main>
  );
}
