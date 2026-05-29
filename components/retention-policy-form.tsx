"use client";

import { Save } from "lucide-react";
import { useRouter } from "next/navigation";
import { useTransition } from "react";
import { notify } from "@/components/toast-provider";
import type { RetentionPolicy } from "@/lib/governance";

export function RetentionPolicyForm({ policy }: { policy: RetentionPolicy }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();

  function submit(formData: FormData) {
    startTransition(async () => {
      const res = await fetch("/api/soc/actions", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          action: "save-retention-policy",
          target: policy.target,
          hotDays: Number(formData.get("hotDays")),
          archiveDays: Number(formData.get("archiveDays")),
          deleteAfterDays: Number(formData.get("deleteAfterDays")),
          preserveCaseEvidence: formData.get("preserveCaseEvidence") === "on",
          legalHold: formData.get("legalHold") === "on",
        }),
      });
      const body = await res.json().catch(() => ({})) as { message?: string; error?: string };
      if (!res.ok) {
        notify(body.error ?? "Retention update failed.", "error");
        return;
      }
      notify(body.message ?? "Retention policy saved.", "success");
      router.refresh();
    });
  }

  return (
    <form className="config-form compact-form" action={submit}>
      <strong>{policy.target}</strong>
      <label><span>Hot days</span><input name="hotDays" type="number" min={1} defaultValue={policy.hotDays} /></label>
      <label><span>Archive days</span><input name="archiveDays" type="number" min={1} defaultValue={policy.archiveDays} /></label>
      <label><span>Delete after days</span><input name="deleteAfterDays" type="number" min={1} defaultValue={policy.deleteAfterDays} /></label>
      <label className="checkbox-field"><input name="preserveCaseEvidence" type="checkbox" defaultChecked={policy.preserveCaseEvidence} /><span>Preserve case evidence</span></label>
      <label className="checkbox-field"><input name="legalHold" type="checkbox" defaultChecked={policy.legalHold} /><span>Legal hold</span></label>
      <button type="submit" disabled={pending}><Save size={15} aria-hidden /> Save</button>
    </form>
  );
}
