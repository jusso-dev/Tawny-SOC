"use client";

import {
  AlertCircle,
  Braces,
  Clock3,
  Columns3,
  Database,
  FileSearch,
  History,
  Play,
  Save,
  Search,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { useMemo, useRef, useState, useTransition, type ReactNode } from "react";
import { notify } from "@/components/toast-provider";

export type HuntListItem = {
  detail?: string;
  label: string;
  query: string;
};

export type HuntRecordRow = {
  hostname: string;
  id: string;
  kind: string;
  rules: string;
  seen: string;
  severity: string;
  severityClass: string;
  timestamp: string;
  title: string;
  type: string;
};

export type HuntFieldGroup = {
  emptyLabel: string;
  items: Array<{
    count: number;
    query: string;
    value: string;
  }>;
  label: string;
};

type SyntaxNote = {
  detail: string;
  term: string;
};

type HuntConsoleProps = {
  examples: HuntListItem[];
  fieldGroups: HuntFieldGroup[];
  initialQuery: string;
  pivots: HuntListItem[];
  queryError?: string;
  records: HuntRecordRow[];
  resultCount: number;
  savedSearches: HuntListItem[];
  syntaxNotes: SyntaxNote[];
  totalCount: number;
};

type ResultView = "events" | "fields";

export function HuntConsole({
  examples,
  fieldGroups,
  initialQuery,
  pivots,
  queryError,
  records,
  resultCount,
  savedSearches,
  syntaxNotes,
  totalCount,
}: HuntConsoleProps) {
  const editorRef = useRef<HTMLTextAreaElement>(null);
  const router = useRouter();
  const [query, setQuery] = useState(initialQuery);
  const [resultView, setResultView] = useState<ResultView>("events");
  const [saving, setSaving] = useState(false);
  const [isNavigating, startTransition] = useTransition();
  const fieldCount = useMemo(
    () => fieldGroups.reduce((count, group) => count + group.items.length, 0),
    [fieldGroups],
  );

  function loadQuery(nextQuery: string) {
    setQuery(nextQuery);
    editorRef.current?.focus();
  }

  function runSearch(nextQuery = query) {
    const normalizedQuery = nextQuery.trim();
    const href = normalizedQuery ? `/hunt?q=${encodeURIComponent(normalizedQuery)}` : "/hunt";
    startTransition(() => router.push(href));
  }

  async function saveSearch() {
    const normalizedQuery = query.trim();
    if (!normalizedQuery) {
      notify("Enter a query before saving it.", "error");
      return;
    }

    setSaving(true);
    try {
      const res = await fetch("/api/soc/actions", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ action: "save-search", query: normalizedQuery }),
      });
      const body = await res.json().catch(() => ({})) as { error?: string; message?: string };
      if (!res.ok) {
        notify(body.error ?? "Search could not be saved.", "error");
        return;
      }
      notify(body.message ?? "Search saved.", "success");
      router.refresh();
    } catch {
      notify("Search could not be saved. Check the server logs.", "error");
    } finally {
      setSaving(false);
    }
  }

  return (
    <section className="hunt-workbench" aria-label="Threat hunt workbench">
      <aside className="hunt-rail" aria-label="Hunt controls">
        <section className="hunt-rail-section">
          <div className="hunt-rail-title">
            <Database size={15} aria-hidden />
            <h2>Search scope</h2>
          </div>
          <dl className="hunt-scope-list">
            <div><dt>Dataset</dt><dd>Alerts and telemetry</dd></div>
            <div><dt>Window</dt><dd>All retained records</dd></div>
            <div><dt>Filter</dt><dd>Controlled by YAAQL</dd></div>
          </dl>
        </section>

        <HuntLoadSection
          emptyLabel="No saved searches yet."
          icon={<History size={14} aria-hidden />}
          items={savedSearches}
          onLoad={loadQuery}
          title="Saved searches"
        />

        <HuntLoadSection
          emptyLabel="No alert pivots available until alerts are ingested."
          icon={<FileSearch size={14} aria-hidden />}
          items={pivots}
          onLoad={loadQuery}
          title="Alert pivots"
        />

        <HuntLoadSection
          emptyLabel="No examples configured."
          icon={<Search size={14} aria-hidden />}
          items={examples}
          onLoad={loadQuery}
          title="Examples"
        />

        <section className="hunt-rail-section">
          <div className="hunt-rail-title">
            <Braces size={15} aria-hidden />
            <h2>YAAQL reference</h2>
          </div>
          <dl className="hunt-syntax-list">
            {syntaxNotes.map((note) => (
              <div key={note.term}>
                <dt><code>{note.term}</code></dt>
                <dd>{note.detail}</dd>
              </div>
            ))}
          </dl>
        </section>
      </aside>

      <div className="hunt-main">
        <form className="hunt-editor" onSubmit={(event) => {
          event.preventDefault();
          runSearch();
        }}>
          <div className="hunt-editor-topline">
            <div>
              <span className="hunt-kicker">Tawny hunt query</span>
              <label htmlFor="hunt-query">Search retained SOC records</label>
            </div>
            <div className="hunt-editor-status" aria-live="polite">
              {queryError ? (
                <span className="hunt-status-error"><AlertCircle size={14} aria-hidden /> Parser error</span>
              ) : (
                <span><Clock3 size={14} aria-hidden /> {resultCount} of {totalCount} records</span>
              )}
            </div>
          </div>

          <textarea
            ref={editorRef}
            id="hunt-query"
            name="q"
            autoComplete="off"
            spellCheck={false}
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder={'severity in (critical, high) and host:win-* and "powershell.exe"'}
          />

          {queryError ? <p className="hunt-query-error" role="alert">{queryError}</p> : null}

          <div className="hunt-command-row">
            <button className="text-button" type="button" disabled={!query.trim()} onClick={() => loadQuery("")}>
              Clear
            </button>
            <button className="text-button" type="button" disabled={saving || !query.trim()} onClick={saveSearch}>
              <Save size={14} aria-hidden /> {saving ? "Saving..." : "Save"}
            </button>
            <button className="primary-action" type="submit" disabled={isNavigating}>
              <Play size={14} aria-hidden /> {isNavigating ? "Running..." : "Run search"}
            </button>
          </div>
        </form>

        <section className="hunt-results-panel" aria-label="Hunt results">
          <div className="hunt-result-header">
            <div>
              <span className="hunt-kicker">Results</span>
              <h2>Matching records</h2>
            </div>
            <div className="hunt-result-tabs" aria-label="Result view">
              <button
                type="button"
                aria-pressed={resultView === "events"}
                className={resultView === "events" ? "active" : undefined}
                onClick={() => setResultView("events")}
              >
                <Search size={14} aria-hidden /> Events <span>{resultCount}</span>
              </button>
              <button
                type="button"
                aria-pressed={resultView === "fields"}
                className={resultView === "fields" ? "active" : undefined}
                onClick={() => setResultView("fields")}
              >
                <Columns3 size={14} aria-hidden /> Fields <span>{fieldCount}</span>
              </button>
            </div>
          </div>

          {resultView === "events" ? (
            <div className="table-wrap">
              <table className="soc-table hunt-table">
                <thead>
                  <tr><th>Event</th><th>Severity</th><th>Host</th><th>Kind</th><th>Type</th><th>Rule matches</th><th>Seen</th></tr>
                </thead>
                <tbody>
                  {records.length > 0 ? records.map((event) => (
                    <tr key={event.id}>
                      <td><strong>{event.title}</strong><span>{event.id}</span></td>
                      <td><span className={event.severityClass}>{event.severity}</span></td>
                      <td>{event.hostname}</td>
                      <td>{event.kind}</td>
                      <td>{event.type}</td>
                      <td>{event.rules}</td>
                      <td><time dateTime={event.timestamp}>{event.seen}</time></td>
                    </tr>
                  )) : (
                    <tr>
                      <td colSpan={7}>
                        <div className="hunt-empty-row">
                          <Search size={16} aria-hidden />
                          <span>No records matched. Broaden the query or send Tawny telemetry to <code>POST /api/ingest/tawny</code>.</span>
                        </div>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="hunt-fields-grid">
              {fieldGroups.map((group) => (
                <section className="hunt-field-group" key={group.label}>
                  <div className="hunt-field-heading">
                    <h3>{group.label}</h3>
                    <span>{group.items.length}</span>
                  </div>
                  {group.items.length > 0 ? (
                    <div className="hunt-field-list">
                      {group.items.map((item) => (
                        <button key={`${group.label}-${item.value}`} type="button" onClick={() => loadQuery(item.query)}>
                          <span>{item.value}</span>
                          <strong>{item.count}</strong>
                        </button>
                      ))}
                    </div>
                  ) : (
                    <p>{group.emptyLabel}</p>
                  )}
                </section>
              ))}
            </div>
          )}
        </section>
      </div>
    </section>
  );
}

type HuntLoadSectionProps = {
  emptyLabel: string;
  icon: ReactNode;
  items: HuntListItem[];
  onLoad: (query: string) => void;
  title: string;
};

function HuntLoadSection({ emptyLabel, icon, items, onLoad, title }: HuntLoadSectionProps) {
  return (
    <section className="hunt-rail-section">
      <div className="hunt-rail-title">
        {icon}
        <h2>{title}</h2>
      </div>
      <div className="hunt-load-list">
        {items.map((item) => (
          <button key={`${title}-${item.query}`} type="button" onClick={() => onLoad(item.query)}>
            <span>
              <strong>{item.label}</strong>
              {item.detail ? <small>{item.detail}</small> : null}
              <code>{item.query}</code>
            </span>
          </button>
        ))}
        {!items.length ? <p>{emptyLabel}</p> : null}
      </div>
    </section>
  );
}
