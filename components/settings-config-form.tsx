"use client";

import { useRouter } from "next/navigation";
import { useTransition } from "react";
import { notify } from "@/components/toast-provider";

type Field = {
  key: string;
  label: string;
  max?: number;
  min?: number;
  type?: "text" | "number" | "checkbox";
  value?: unknown;
};

export function SettingsConfigForm({ settingKey, fields }: { settingKey: string; fields: Field[] }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();

  function submit(formData: FormData) {
    const values: Record<string, unknown> = {};
    for (const field of fields) {
      if (field.type === "checkbox") {
        values[field.key] = formData.get(field.key) === "on";
      } else if (field.type === "number") {
        values[field.key] = Number(formData.get(field.key) ?? 0);
      } else {
        values[field.key] = String(formData.get(field.key) ?? "");
      }
    }

    startTransition(async () => {
      const res = await fetch("/api/soc/actions", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ action: "save-soc-setting", settingKey, values }),
      });
      const body = await res.json().catch(() => ({})) as { message?: string; error?: string };
      if (!res.ok) {
        notify(body.error ?? "Setting update failed.", "error");
        return;
      }
      notify(body.message ?? "Setting saved.", "success");
      router.refresh();
    });
  }

  return (
    <form className="config-form" action={submit}>
      {fields.map((field) => (
        <label key={field.key}>
          <span>{field.label}</span>
          <input
            name={field.key}
            type={field.type === "checkbox" ? "checkbox" : field.type ?? "text"}
            defaultChecked={field.type === "checkbox" ? field.value === true : undefined}
            defaultValue={field.type === "checkbox" ? undefined : String(field.value ?? "")}
            min={field.type === "number" ? field.min : undefined}
            max={field.type === "number" ? field.max : undefined}
          />
        </label>
      ))}
      <button type="submit" disabled={pending}>{pending ? "Saving..." : "Save"}</button>
    </form>
  );
}
