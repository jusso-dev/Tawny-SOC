"use client";

import { useState, useTransition } from "react";

export function SignUpForm() {
  const [message, setMessage] = useState("");
  const [pending, startTransition] = useTransition();

  function submit(formData: FormData) {
    setMessage("");
    startTransition(async () => {
      const res = await fetch("/api/auth/sign-up/email", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          name: String(formData.get("name") ?? ""),
          email: String(formData.get("email") ?? ""),
          password: String(formData.get("password") ?? ""),
          callbackURL: "/",
        }),
      });
      if (!res.ok) {
        setMessage("Could not create the account. Use a stronger password and try again.");
        return;
      }
      window.location.href = "/";
    });
  }

  return (
    <form className="auth-form" action={submit}>
      <label>
        Name
        <input name="name" autoComplete="name" required />
      </label>
      <label>
        Email
        <input name="email" type="email" autoComplete="email" required />
      </label>
      <label>
        Password
        <input name="password" type="password" autoComplete="new-password" minLength={12} required />
      </label>
      <button type="submit" disabled={pending}>Create account</button>
      {message ? <p className="form-message">{message}</p> : null}
    </form>
  );
}
