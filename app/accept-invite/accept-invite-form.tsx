"use client";

import { CheckCircle2 } from "lucide-react";
import { useState, useTransition } from "react";
import { notify } from "@/components/toast-provider";

export function AcceptInviteForm({ invitationId }: { invitationId: string }) {
  const [message, setMessage] = useState("");
  const [pending, startTransition] = useTransition();

  function submit() {
    setMessage("");
    startTransition(async () => {
      const res = await fetch("/api/auth/organization/accept-invitation", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ invitationId }),
      });
      const body = await res.json().catch(() => ({})) as { message?: string };
      if (!res.ok) {
        setMessage(body.message ?? "Invitation acceptance failed.");
        notify("Invitation acceptance failed.", "error");
        return;
      }
      notify("Invitation accepted.", "success");
      window.location.href = "/settings";
    });
  }

  return (
    <form className="auth-form" action={submit}>
      <button type="submit" disabled={pending || !invitationId}>
        <CheckCircle2 size={15} aria-hidden /> Accept invitation
      </button>
      {message ? <p className="form-message">{message}</p> : null}
    </form>
  );
}
