import { ChevronDown, ChevronLeft, ChevronRight, ChevronUp, Search } from "lucide-react";
import Link from "next/link";
import { ActionButton } from "@/components/action-button";
import { PageHeader, SocShell } from "@/components/soc-shell";
import { ThreatFeedForm } from "@/components/threat-feed-form";
import { ThreatIntelControls } from "@/components/threat-intel-controls";
import { getSocData, relativeTime, timeUntil } from "@/lib/soc-domain";
import {
  listThreatIntelIndicatorsPage,
  type ThreatIntelIndicatorPage,
  type ThreatIntelSortDirection,
  type ThreatIntelSortKey,
} from "@/lib/store";
import type { ThreatIntelMatch } from "@/lib/types";
import { quoteYaaqlValue } from "@/lib/yaaql";

type ThreatIntelPageProps = {
  searchParams?: Promise<Record<string, string | string[] | undefined>>;
};

const indicatorTypes: Array<ThreatIntelMatch["type"]> = ["ip", "cidr", "domain", "url", "hash", "email", "file", "cve"];

const sortLabels: Record<ThreatIntelSortKey, string> = {
  confidence: "Confidence",
  expiresAt: "Expires",
  firstSeen: "First seen",
  lastSeen: "Last seen",
  sourceFeed: "Source feed",
  type: "Type",
  value: "IOC",
};

function firstParam(value: string | string[] | undefined) {
  return Array.isArray(value) ? value[0] : value;
}

function parsePage(value: string | undefined) {
  const page = Number.parseInt(value ?? "", 10);
  return Number.isFinite(page) && page > 0 ? page : 1;
}

function parseSort(value: string | undefined): ThreatIntelSortKey {
  if (value === "value" || value === "type" || value === "sourceFeed" || value === "confidence" || value === "firstSeen" || value === "lastSeen" || value === "expiresAt") return value;
  return "lastSeen";
}

function parseDirection(value: string | undefined): ThreatIntelSortDirection {
  return value === "asc" ? "asc" : "desc";
}

function parseIndicatorType(value: string | undefined): ThreatIntelMatch["type"] | "" {
  return indicatorTypes.includes(value as ThreatIntelMatch["type"]) ? value as ThreatIntelMatch["type"] : "";
}

type ThreatIntelUrlOverrides = Partial<{
  direction: ThreatIntelSortDirection;
  page: number;
  search: string;
  sort: ThreatIntelSortKey;
  sourceFeed: string;
  type: ThreatIntelMatch["type"] | "";
}>;

function threatIntelUrl(state: ThreatIntelIndicatorPage, overrides: ThreatIntelUrlOverrides = {}) {
  const next = { ...state, ...overrides };
  const params = new URLSearchParams();
  if (next.search) params.set("q", next.search);
  if (next.type) params.set("type", next.type);
  if (next.sourceFeed) params.set("sourceFeed", next.sourceFeed);
  if (next.sort !== "lastSeen") params.set("sort", next.sort);
  if (next.direction !== "desc") params.set("direction", next.direction);
  if (next.page > 1) params.set("page", String(next.page));
  const query = params.toString();
  return query ? `/threat-intel?${query}` : "/threat-intel";
}

function SortHeader({ indicatorPage, sort }: { indicatorPage: ThreatIntelIndicatorPage; sort: ThreatIntelSortKey }) {
  const active = indicatorPage.sort === sort;
  const direction = active && indicatorPage.direction === "desc" ? "asc" : "desc";
  const Icon = !active ? null : indicatorPage.direction === "asc" ? ChevronUp : ChevronDown;

  return (
    <Link
      aria-label={`Sort by ${sortLabels[sort]} ${direction === "asc" ? "ascending" : "descending"}`}
      className={active ? "sort-link is-active" : "sort-link"}
      href={threatIntelUrl(indicatorPage, { direction, page: 1, sort })}
      scroll={false}
    >
      {sortLabels[sort]}
      {Icon ? <Icon size={13} aria-hidden /> : null}
    </Link>
  );
}

export default async function ThreatIntelPage({ searchParams }: ThreatIntelPageProps) {
  const params = searchParams ? await searchParams : {};
  const search = firstParam(params.q)?.trim() ?? "";
  const type = parseIndicatorType(firstParam(params.type));
  const sourceFeed = firstParam(params.sourceFeed)?.trim() ?? "";
  const sort = parseSort(firstParam(params.sort));
  const direction = parseDirection(firstParam(params.direction));
  const page = parsePage(firstParam(params.page));
  const { threatIntelFeeds, alerts, incidents, tenantId } = await getSocData();
  const indicatorPage = await listThreatIntelIndicatorsPage(tenantId, {
    direction,
    page,
    pageSize: 100,
    search,
    sort,
    sourceFeed,
    type,
  });
  const sourceFeedOptions = Array.from(new Set([
    ...threatIntelFeeds.map((feed) => feed.name),
    ...(indicatorPage.sourceFeed ? [indicatorPage.sourceFeed] : []),
  ])).sort((a, b) => a.localeCompare(b));
  const alertMatchCounts = new Map<string, number>();
  const caseMatchCounts = new Map<string, number>();

  for (const alert of alerts) {
    for (const match of alert.tiMatches ?? []) {
      alertMatchCounts.set(match.id, (alertMatchCounts.get(match.id) ?? 0) + 1);
    }
  }
  for (const incident of incidents) {
    for (const match of incident.observables) {
      caseMatchCounts.set(match.id, (caseMatchCounts.get(match.id) ?? 0) + 1);
    }
  }

  const pageStart = indicatorPage.total === 0 ? 0 : (indicatorPage.page - 1) * indicatorPage.pageSize + 1;
  const pageEnd = Math.min(indicatorPage.page * indicatorPage.pageSize, indicatorPage.total);
  const hasPreviousPage = indicatorPage.page > 1;
  const hasNextPage = indicatorPage.page < indicatorPage.totalPages;

  return (
    <SocShell active="/threat-intel">
      <PageHeader
        eyebrow="Threat intelligence"
        title="Configure feed endpoints, test ingestion, enrich alerts, and retro-hunt Tawny telemetry."
        actions={<ActionButton className="primary-action" action="sync-enabled-threat-feeds">Sync enabled feeds</ActionButton>}
      />

      <div className="grid overview-grid">
        <section className="panel">
          <div className="panel-heading">
            <h2>Feed management</h2>
            <span className="status status-healthy">{threatIntelFeeds.filter((feed) => feed.enabled).length} enabled</span>
          </div>
          <ThreatFeedForm feeds={threatIntelFeeds} />
        </section>

        <section className="panel">
          <div className="panel-heading">
            <h2>Mapping</h2>
            <Search size={18} aria-hidden />
          </div>
          <dl className="detail-grid">
            <div><dt>Related alerts</dt><dd>{alerts.filter((alert) => (alert.tiMatches ?? []).length > 0).length}</dd></div>
            <div><dt>Related cases</dt><dd>{incidents.filter((incident) => incident.observables.length > 0).length}</dd></div>
            <div><dt>Retro-hunt mode</dt><dd>Query historical Tawny telemetry by IOC value</dd></div>
            <div><dt>Configured feeds</dt><dd>{threatIntelFeeds.length}</dd></div>
          </dl>
        </section>
      </div>

      <section className="panel">
        <div className="panel-heading threat-intel-heading">
          <div>
            <h2>Indicators</h2>
            <p>Active IOCs, filtered at the database and shown 100 per page.</p>
          </div>
          <span className="status status-healthy">{indicatorPage.total.toLocaleString()} active</span>
        </div>

        <ThreatIntelControls
          direction={indicatorPage.direction}
          search={indicatorPage.search}
          sort={indicatorPage.sort}
          sourceFeed={indicatorPage.sourceFeed}
          sourceFeedOptions={sourceFeedOptions}
          type={indicatorPage.type}
          types={indicatorTypes}
        />

        <div className="table-wrap">
          <table className="soc-table threat-intel-table">
            <thead>
              <tr>
                <th><SortHeader indicatorPage={indicatorPage} sort="value" /></th>
                <th><SortHeader indicatorPage={indicatorPage} sort="type" /></th>
                <th><SortHeader indicatorPage={indicatorPage} sort="sourceFeed" /></th>
                <th><SortHeader indicatorPage={indicatorPage} sort="confidence" /></th>
                <th>Tags</th>
                <th><SortHeader indicatorPage={indicatorPage} sort="firstSeen" /></th>
                <th><SortHeader indicatorPage={indicatorPage} sort="lastSeen" /></th>
                <th><SortHeader indicatorPage={indicatorPage} sort="expiresAt" /></th>
                <th>Related alerts</th>
                <th>Related cases</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {indicatorPage.indicators.map((ioc) => (
                <tr key={ioc.id}>
                  <td><strong>{ioc.value}</strong></td>
                  <td>{ioc.type}</td>
                  <td>{ioc.sourceFeed}</td>
                  <td>{ioc.confidence}%</td>
                  <td>{ioc.tags.join(", ")}</td>
                  <td>{relativeTime(ioc.firstSeen)}</td>
                  <td>{relativeTime(ioc.lastSeen)}</td>
                  <td>{timeUntil(ioc.expiry)}</td>
                  <td>{alertMatchCounts.get(ioc.id) ?? 0}</td>
                  <td>{caseMatchCounts.get(ioc.id) ?? 0}</td>
                  <td><Link className="inline-action" href={`/hunt?q=${encodeURIComponent(`${ioc.type}:${quoteYaaqlValue(ioc.value)}`)}`}><Search size={14} aria-hidden /> Retro-hunt</Link></td>
                </tr>
              ))}
              {!indicatorPage.indicators.length ? <tr><td colSpan={11}>No indicators matched. Adjust the search or test a feed.</td></tr> : null}
            </tbody>
          </table>
        </div>

        <div className="pagination-bar">
          <span>Showing {pageStart.toLocaleString()}-{pageEnd.toLocaleString()} of {indicatorPage.total.toLocaleString()}</span>
          <div className="pagination-actions">
            {hasPreviousPage ? (
              <Link className="filter-link" href={threatIntelUrl(indicatorPage, { page: indicatorPage.page - 1 })} scroll={false}><ChevronLeft size={15} aria-hidden /> Previous</Link>
            ) : (
              <span className="pagination-disabled"><ChevronLeft size={15} aria-hidden /> Previous</span>
            )}
            <span>Page {indicatorPage.page.toLocaleString()} of {indicatorPage.totalPages.toLocaleString()}</span>
            {hasNextPage ? (
              <Link className="filter-link" href={threatIntelUrl(indicatorPage, { page: indicatorPage.page + 1 })} scroll={false}>Next <ChevronRight size={15} aria-hidden /></Link>
            ) : (
              <span className="pagination-disabled">Next <ChevronRight size={15} aria-hidden /></span>
            )}
          </div>
        </div>
      </section>
    </SocShell>
  );
}
