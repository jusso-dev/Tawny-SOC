"use client";

import { useState, useTransition } from "react";

export function SignInForm({ next }: { next: string }) {
  const [message, setMessage] = useState("");
  const [pending, startTransition] = useTransition();

  function submit(formData: FormData, mode: "password" | "magic") {
    setMessage("");
    startTransition(async () => {
      const email = String(formData.get("email") ?? "");
      const body = mode === "password"
        ? { email, password: String(formData.get("password") ?? ""), callbackURL: next }
        : { email, callbackURL: next };
      const path = mode === "password" ? "/api/auth/sign-in/email" : "/api/auth/sign-in/magic-link";
      const res = await fetch(path, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });

      if (!res.ok) {
        setMessage("Sign in failed. Check your details and try again.");
        return;
      }
      if (mode === "magic") {
        setMessage("Magic link generated. In development, check the server logs for the link.");
        return;
      }
      window.location.href = next;
    });
  }

  return (
    <form className="auth-form" action={(formData) => submit(formData, "password")}>
      <label>
        Email
        <input name="email" type="email" autoComplete="email" required />
      </label>
      <label>
        Password
        <input name="password" type="password" autoComplete="current-password" required />
      </label>
      <div className="auth-actions">
        <button type="submit" disabled={pending}>Sign in</button>
        <button type="button" className="secondary" disabled={pending} onClick={(event) => {
          const form = event.currentTarget.form;
          if (form) submit(new FormData(form), "magic");
        }}>
          Magic link
        </button>
      </div>
      {message ? <p className="form-message">{message}</p> : null}
    </form>
  );
}
