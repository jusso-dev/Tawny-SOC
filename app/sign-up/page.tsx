import Link from "next/link";
import { SignUpForm } from "./sign-up-form";

export default function SignUpPage() {
  return (
    <main className="auth-page">
      <section className="auth-panel">
        <p className="eyebrow">Tawny-SOC</p>
        <h1>Create your SOC account</h1>
        <p className="auth-copy">BetterAuth protects the workspace, while the organization plugin manages team membership and invitations.</p>
        <SignUpForm />
        <p className="auth-footer">
          Already have access? <Link href="/sign-in">Sign in</Link>
        </p>
      </section>
    </main>
  );
}
