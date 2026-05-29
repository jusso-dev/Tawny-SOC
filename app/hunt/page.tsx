import {
  HuntConsole,
  type HuntFieldGroup,
  type HuntListItem,
  type HuntRecordRow,
} from "@/components/hunt-console";
import { PageHeader, SocShell } from "@/components/soc-shell";
import { getSocData, relativeTime, severityClass } from "@/lib/soc-domain";
import { listSavedSearches } from "@/lib/store";
import type { SocEvent } from "@/lib/types";
import { filterWithYaaql, quoteYaaqlValue } from "@/lib/yaaql";

type HuntPageProps = {
  searchParams?: Promise<Record<string, string | string[] | undefined>>;
};

function firstParam(value: string | string[] | undefined) {
  return Array.isArray(value) ? value[0] : value;
}

const queryExamples = [
  {
    detail: "Phrase match plus boolean exclusion",
    label: "Free text phrase",
    query: '"powershell.exe" and not severity=low',
  },
  {
    detail: "Hostname wildcard with rule-id pivot",
    label: "Field aliases",
    query: "host:mac-* and rule:tawny-sigma-*",
  },
  {
    detail: "ISO timestamp comparison and numeric confidence",
    label: "Timestamp window",
    query: "time>=2026-05-27T00:00:00Z and confidence>=0.8",
  },
  {
    detail: "ATT&CK technique and encoded command sweep",
    label: "Technique hunt",
    query: "mitre=T1059.001 or cmd:*encoded*",
  },
  {
    detail: "Critical and high alert queue",
    label: "High severity triage",
    query: "kind=alert and severity in (critical, high)",
  },
  {
    detail: "Process telemetry containing PowerShell",
    label: "Endpoint process hunt",
    query: "type=ProcessLaunch and cmd:*powershell*",
  },
  {
    detail: "IOC-bearing telemetry or alerts",
    label: "Network IOC sweep",
    query: "has:ip or has:domain",
  },
  {
    detail: "Confidence threshold for alert review",
    label: "High confidence alerts",
    query: "confidence>=0.8 and kind=alert",
  },
];

const syntaxNotes = [
  { term: "field:value", detail: "contains match, useful for host, title, cmd, rule, ip, domain, and mitre" },
  { term: "field=value", detail: "exact match for values such as kind=alert or type=ProcessLaunch" },
  { term: "in (...)", detail: "match any value, for example severity in (critical, high)" },
  { term: "has:field", detail: "require a field or alias to exist, for example has:domain" },
  { term: "and, or, not", detail: "combine clauses; adjacent terms are treated as and" },
  { term: "*, ?, quotes", detail: "use wildcards and quote phrases or values with spaces" },
  { term: ">, >=, <, <=", detail: "compare numbers or timestamps such as confidence>=0.8" },
];

export default async function HuntPage({ searchParams }: HuntPageProps) {
  const params = searchParams ? await searchParams : {};
  const { events, alerts } = await getSocData();
  const userSavedSearches = await listSavedSearches();
  const explicitQuery = firstParam(params.q);
  const hostPivot = firstParam(params.host);
  const query = explicitQuery ?? (hostPivot ? `host:${quoteYaaqlValue(hostPivot)}` : "");
  const records = [...alerts, ...events].sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp));
  const searchResult = filterWithYaaql(records, query);
  const matchingRecords = searchResult.records;
  const allSavedSearches = userSavedSearches.filter((search, index, all) => (
    all.findIndex((item) => item.query === search.query) === index
  ));
  const resultRows: HuntRecordRow[] = matchingRecords.map((event) => ({
    hostname: event.hostname ?? "unknown",
    id: event.id,
    kind: event.kind,
    rules: event.matchedRules.join(", ") || "None",
    seen: relativeTime(event.timestamp),
    severity: event.severity,
    severityClass: severityClass(event.severity),
    timestamp: event.timestamp,
    title: event.title,
    type: event.eventType ?? "telemetry",
  }));
  const savedSearches: HuntListItem[] = allSavedSearches.map((savedSearch) => ({
    detail: "Saved query",
    label: savedSearch.name,
    query: savedSearch.query,
  }));
  const pivots: HuntListItem[] = alerts
    .filter((alert) => Boolean(alert.hostname))
    .filter((alert, index, all) => all.findIndex((item) => item.hostname === alert.hostname) === index)
    .slice(0, 6)
    .map((alert) => ({
      detail: alert.title,
      label: alert.hostname ?? "unknown",
      query: `host:${quoteYaaqlValue(alert.hostname ?? "")}`,
    }));
  const fieldGroups = buildFieldGroups(matchingRecords);

  return (
    <SocShell active="/hunt">
      <PageHeader
        eyebrow="Search / hunt"
        title="Hunt across retained Tawny telemetry with a query-first analyst console."
      />
      <HuntConsole
        examples={queryExamples}
        fieldGroups={fieldGroups}
        initialQuery={query}
        key={query}
        pivots={pivots}
        queryError={searchResult.error}
        records={resultRows}
        resultCount={matchingRecords.length}
        savedSearches={savedSearches}
        syntaxNotes={syntaxNotes}
        totalCount={records.length}
      />
    </SocShell>
  );
}

function buildFieldGroups(records: SocEvent[]): HuntFieldGroup[] {
  return [
    {
      emptyLabel: "No host values in the current result set.",
      items: topValues(records.map((record) => record.hostname), (value) => `host:${quoteYaaqlValue(value)}`),
      label: "Hosts",
    },
    {
      emptyLabel: "No severities in the current result set.",
      items: topValues(records.map((record) => record.severity), (value) => `severity=${value}`),
      label: "Severity",
    },
    {
      emptyLabel: "No event types in the current result set.",
      items: topValues(records.map((record) => record.eventType ?? record.kind), (value) => (
        value === "alert" || value === "telemetry" ? `kind=${value}` : `type=${quoteYaaqlValue(value)}`
      )),
      label: "Kinds and types",
    },
    {
      emptyLabel: "No rule matches in the current result set.",
      items: topValues(records.flatMap((record) => record.matchedRules), (value) => `rule:${quoteYaaqlValue(value)}`),
      label: "Rules",
    },
    {
      emptyLabel: "No ATT&CK techniques in the current result set.",
      items: topValues(records.flatMap((record) => record.mitreTechniques), (value) => `mitre=${quoteYaaqlValue(value)}`),
      label: "ATT&CK",
    },
  ];
}

function topValues(values: Array<string | undefined>, queryFor: (value: string) => string) {
  const counts = new Map<string, number>();
  for (const rawValue of values) {
    const value = rawValue?.trim();
    if (!value) continue;
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  return [...counts.entries()]
    .sort(([, left], [, right]) => right - left)
    .slice(0, 8)
    .map(([value, count]) => ({ count, query: queryFor(value), value }));
}
