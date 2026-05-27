import { MfaForm } from "./mfa-form";

export default function MfaPage() {
  return (
    <main className="auth-page">
      <section className="auth-panel">
        <p className="eyebrow">Multi-factor authentication</p>
        <h1>Verify your one-time code</h1>
        <p className="auth-copy">Enter the TOTP code from your authenticator app to finish sign in.</p>
        <MfaForm />
      </section>
    </main>
  );
}
