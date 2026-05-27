"use client";

import { useState, useTransition } from "react";

export function MfaForm() {
  const [message, setMessage] = useState("");
  const [pending, startTransition] = useTransition();

  function submit(formData: FormData) {
    setMessage("");
    startTransition(async () => {
      const res = await fetch("/api/auth/two-factor/verify-totp", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          code: String(formData.get("code") ?? ""),
          trustDevice: true,
        }),
      });
      if (!res.ok) {
        setMessage("Code verification failed.");
        return;
      }
      window.location.href = "/";
    });
  }

  return (
    <form className="auth-form" action={submit}>
      <label>
        Code
        <input name="code" inputMode="numeric" autoComplete="one-time-code" required />
      </label>
      <button type="submit" disabled={pending}>Verify</button>
      {message ? <p className="form-message">{message}</p> : null}
    </form>
  );
}
