"use client";

import { useState, useTransition } from "react";
import { notify } from "@/components/toast-provider";

export function SignUpForm({ email = "" }: { email?: string }) {
  const [message, setMessage] = useState("");
  const [pending, startTransition] = useTransition();

  function submit(formData: FormData) {
    setMessage("");
    startTransition(async () => {
      const password = String(formData.get("password") ?? "");
      const confirmPassword = String(formData.get("confirmPassword") ?? "");
      if (password !== confirmPassword) {
        setMessage("Passwords do not match.");
        notify("Passwords do not match.", "error");
        return;
      }

      const res = await fetch("/api/auth/sign-up/email", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          name: String(formData.get("name") ?? ""),
          email: String(formData.get("email") ?? ""),
          password,
          callbackURL: "/",
        }),
      });
      if (!res.ok) {
        setMessage("Could not create the account. Use a stronger password and try again.");
        notify("Account creation failed.", "error");
        return;
      }
      notify("Account created.", "success");
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
        <input name="email" type="email" autoComplete="email" defaultValue={email} required />
      </label>
      <label>
        Password
        <input name="password" type="password" autoComplete="new-password" minLength={12} required />
      </label>
      <label>
        Confirm password
        <input name="confirmPassword" type="password" autoComplete="new-password" minLength={12} required />
      </label>
      <button type="submit" disabled={pending}>Create account</button>
      {message ? <p className="form-message">{message}</p> : null}
    </form>
  );
}
