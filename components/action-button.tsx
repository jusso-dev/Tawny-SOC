"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { notify } from "@/components/toast-provider";

type ActionButtonProps = {
  action: string;
  className?: string;
  children: React.ReactNode;
  disabled?: boolean;
  payload?: Record<string, unknown>;
};

export function ActionButton({ action, className, children, disabled, payload = {} }: ActionButtonProps) {
  const router = useRouter();
  const [pending, setPending] = useState(false);

  async function runAction() {
    setPending(true);
    try {
      const res = await fetch("/api/soc/actions", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ action, ...payload }),
      });
      const body = await res.json().catch(() => ({})) as { message?: string; error?: string };
      if (!res.ok) {
        notify(body.error ?? "Action failed.", "error");
        return;
      }
      notify(body.message ?? "Action completed.", "success");
      router.refresh();
    } catch {
      notify("Action failed. Check the server logs.", "error");
    } finally {
      setPending(false);
    }
  }

  return (
    <button className={className} type="button" disabled={disabled || pending} onClick={runAction}>
      {pending ? "Working..." : children}
    </button>
  );
}
