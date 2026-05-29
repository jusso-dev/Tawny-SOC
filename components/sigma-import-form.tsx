"use client";

import { Upload } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";
import { notify } from "@/components/toast-provider";

const sampleSigma = `title: Suspicious PowerShell Download
id: tawny-custom-powershell-download
status: test
description: Detects PowerShell downloading remote content.
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - powershell
      - iwr
      - downloadstring
  condition: selection
level: high
tags:
  - attack.t1059.001
  - attack.t1105`;

export function SigmaImportForm() {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [sigma, setSigma] = useState("");
  const [pending, startTransition] = useTransition();

  function importRule() {
    startTransition(async () => {
      const res = await fetch("/api/rules", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sigma }),
      });
      const body = await res.json().catch(() => ({})) as { message?: string; error?: string };
      if (!res.ok) {
        notify(body.error ?? "Sigma import failed.", "error");
        return;
      }
      notify(body.message ?? "Sigma rule imported.", "success");
      setOpen(false);
      router.refresh();
    });
  }

  return (
    <div className="import-shell" id="import-sigma">
      <button className="text-button" type="button" onClick={() => setOpen((value) => !value)}>
        <Upload size={15} aria-hidden /> Import Sigma
      </button>
      {open ? (
        <section className="panel import-panel">
          <label className="query-input">
            <span>Sigma YAML</span>
            <textarea value={sigma} onChange={(event) => setSigma(event.target.value)} rows={14} />
          </label>
          <div className="card-actions">
            <button type="button" onClick={importRule} disabled={pending}>{pending ? "Importing..." : "Import rule"}</button>
            <button type="button" onClick={() => setSigma(sampleSigma)}>Load example</button>
            <button type="button" onClick={() => setOpen(false)}>Cancel</button>
          </div>
        </section>
      ) : null}
    </div>
  );
}
