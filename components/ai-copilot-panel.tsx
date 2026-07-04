"use client";

import { Bot, FileText, Radar, Sparkles } from "lucide-react";
import Link from "next/link";
import { useState, useTransition } from "react";
import { notify } from "@/components/toast-provider";
import type { CaseDraftResult } from "@/lib/ai/agents/case-writer";
import type { EnrichmentAgentResult } from "@/lib/ai/agents/enrichment";
import type { TriageAgentResult } from "@/lib/ai/agents/triage";
import type { AgentRunMeta } from "@/lib/ai/types";

async function runAgent<T>(payload: Record<string, unknown>): Promise<T> {
  const res = await fetch("/api/ai/agents", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error((body as { error?: string }).error ?? "Agent run failed.");
  return body as T;
}

function EngineBadge({ meta }: { meta: AgentRunMeta }) {
  return (
    <small className="muted-copy">
      {meta.engine === "ai"
        ? `${meta.provider === "aws-bedrock" ? "AWS Bedrock" : "Azure OpenAI"} · ${meta.model} · ${meta.latencyMs}ms`
        : meta.note ?? "Deterministic fallback"}
      {meta.engine === "deterministic" ? <> · <Link href="/settings/ai">Configure AI engine</Link></> : null}
    </small>
  );
}

export function AlertCopilotPanel({ alertId }: { alertId: string }) {
  const [pending, startTransition] = useTransition();
  const [busy, setBusy] = useState("");
  const [triage, setTriage] = useState<TriageAgentResult | null>(null);
  const [enrichment, setEnrichment] = useState<EnrichmentAgentResult | null>(null);

  function run(agent: "triage" | "enrichment") {
    setBusy(agent);
    startTransition(async () => {
      try {
        if (agent === "triage") setTriage(await runAgent<TriageAgentResult>({ agent, alertId }));
        else setEnrichment(await runAgent<EnrichmentAgentResult>({ agent, alertId }));
      } catch (error) {
        notify(error instanceof Error ? error.message : "Agent run failed.", "error");
      } finally {
        setBusy("");
      }
    });
  }

  return (
    <section className="panel">
      <p className="eyebrow">AI copilot</p>
      <h2>Agent assistance</h2>
      <div className="action-bar">
        <button className="primary-action" type="button" disabled={pending} onClick={() => run("triage")}>
          <Bot size={15} aria-hidden /> {busy === "triage" ? "Triaging..." : "Run triage agent"}
        </button>
        <button className="primary-action" type="button" disabled={pending} onClick={() => run("enrichment")}>
          <Radar size={15} aria-hidden /> {busy === "enrichment" ? "Enriching..." : "Run TI enrichment"}
        </button>
      </div>

      {triage ? (
        <article className="ai-agent-result">
          <strong>Verdict: {triage.verdict.replace("_", " ")} · {Math.round(triage.confidence * 100)}% confidence</strong>
          <p>{triage.summary}</p>
          {triage.rationale.length ? (
            <ul>{triage.rationale.map((line, index) => <li key={index}>{line}</li>)}</ul>
          ) : null}
          <p><em>Next actions:</em></p>
          <ul>{triage.recommendedActions.map((action, index) => <li key={index}>{action}</li>)}</ul>
          <p>Suggested playbook: <code>{triage.suggestedPlaybook}</code></p>
          <EngineBadge meta={triage.meta} />
        </article>
      ) : null}

      {enrichment ? (
        <article className="ai-agent-result">
          <strong>Threat intel enrichment</strong>
          <p>{enrichment.summary}</p>
          {enrichment.indicators.length ? (
            <ul>
              {enrichment.indicators.map((indicator, index) => (
                <li key={index}><code>{indicator.value}</code> ({indicator.type}, {indicator.risk} risk) — {indicator.assessment}</li>
              ))}
            </ul>
          ) : null}
          {enrichment.huntQueries.length ? (
            <>
              <p><em>Hunt pivots:</em></p>
              <ul>
                {enrichment.huntQueries.map((query, index) => (
                  <li key={index}><Link href={`/hunt?q=${encodeURIComponent(query)}`}><code>{query}</code></Link></li>
                ))}
              </ul>
            </>
          ) : null}
          {enrichment.hypotheses.length ? (
            <>
              <p><em>Hypotheses:</em></p>
              <ul>{enrichment.hypotheses.map((line, index) => <li key={index}>{line}</li>)}</ul>
            </>
          ) : null}
          <EngineBadge meta={enrichment.meta} />
        </article>
      ) : null}

      {!triage && !enrichment ? (
        <p className="muted-copy"><Sparkles size={13} aria-hidden /> Run agents to get an AI verdict, indicator context, and hunt pivots for this alert.</p>
      ) : null}
    </section>
  );
}

export function CaseCopilotPanel({ incidentId }: { incidentId: string }) {
  const [pending, startTransition] = useTransition();
  const [draft, setDraft] = useState<CaseDraftResult | null>(null);

  function run() {
    startTransition(async () => {
      try {
        setDraft(await runAgent<CaseDraftResult>({ agent: "case-writer", incidentId }));
      } catch (error) {
        notify(error instanceof Error ? error.message : "Agent run failed.", "error");
      }
    });
  }

  async function copyDraft() {
    if (!draft) return;
    const text = [
      draft.title,
      "",
      "## Executive summary",
      draft.executiveSummary,
      "",
      "## Technical narrative",
      draft.technicalNarrative,
      "",
      "## Impact assessment",
      draft.impactAssessment,
      "",
      "## Recommendations",
      ...draft.recommendations.map((item) => `- ${item}`),
    ].join("\n");
    await navigator.clipboard.writeText(text);
    notify("Case draft copied to clipboard.", "success");
  }

  return (
    <section className="panel">
      <p className="eyebrow">AI copilot</p>
      <h2>Case writing agent</h2>
      <div className="action-bar">
        <button className="primary-action" type="button" disabled={pending} onClick={run}>
          <FileText size={15} aria-hidden /> {pending ? "Drafting..." : "Draft case write-up"}
        </button>
        {draft ? (
          <button className="secondary" type="button" onClick={copyDraft}>Copy draft</button>
        ) : null}
      </div>

      {draft ? (
        <article className="ai-agent-result">
          <strong>{draft.title}</strong>
          <p><em>Executive summary:</em> {draft.executiveSummary}</p>
          <p><em>Technical narrative:</em></p>
          <pre className="json-block" style={{ whiteSpace: "pre-wrap" }}>{draft.technicalNarrative}</pre>
          <p><em>Impact:</em> {draft.impactAssessment}</p>
          <p><em>Recommendations:</em></p>
          <ul>{draft.recommendations.map((item, index) => <li key={index}>{item}</li>)}</ul>
          <EngineBadge meta={draft.meta} />
        </article>
      ) : (
        <p className="muted-copy">Generate an executive summary, technical narrative, and recommendations from the case record and linked alerts.</p>
      )}
    </section>
  );
}
