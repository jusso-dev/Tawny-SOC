import Link from "next/link";
import { SignInForm } from "./sign-in-form";

export default async function SignInPage({
  searchParams,
}: {
  searchParams: Promise<{ next?: string }>;
}) {
  const next = (await searchParams).next ?? "/";
  return (
    <main className="auth-page">
      <section className="auth-panel">
        <p className="eyebrow">Tawny-SOC</p>
        <h1>Sign in to your SOC workspace</h1>
        <p className="auth-copy">Use email and password, or request a magic link. MFA is enforced for accounts that enable it.</p>
        <SignInForm next={next} />
        <p className="auth-footer">
          New workspace? <Link href="/sign-up">Create an account</Link>
        </p>
      </section>
    </main>
  );
}
