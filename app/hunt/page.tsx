import { Save, Search } from "lucide-react";
import { PageHeader, SocShell } from "@/components/soc-shell";
import { getSocData, relativeTime, severityClass } from "@/lib/soc-domain";
import { filterWithYaaql, quoteYaaqlValue } from "@/lib/yaaql";

type HuntPageProps = {
  searchParams?: Promise<Record<string, string | string[] | undefined>>;
};

function firstParam(value: string | string[] | undefined) {
  return Array.isArray(value) ? value[0] : value;
}

export default async function HuntPage({ searchParams }: HuntPageProps) {
  const params = searchParams ? await searchParams : {};
  const { events, alerts } = await getSocData();
  const explicitQuery = firstParam(params.q);
  const hostPivot = firstParam(params.host);
  const query = explicitQuery ?? (hostPivot ? `host:${quoteYaaqlValue(hostPivot)}` : "");
  const records = [...alerts, ...events].sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp));
  const searchResult = filterWithYaaql(records, query);
  const matchingRecords = searchResult.records;

  return (
    <SocShell active="/hunt">
      <PageHeader
        eyebrow="Search / hunt"
        title="Search Tawny telemetry and alerts with YAAQL, then pivot from alerts into scoped hunts."
        actions={<button className="text-button"><Save size={15} aria-hidden /> Save search</button>}
      />

      <section className="panel query-builder">
        <div className="panel-heading">
          <h2>YAAQL search</h2>
          <div className="query-meta">
            <span>{matchingRecords.length} of {records.length} records</span>
          </div>
        </div>
        <form className="query-form" action="/hunt">
          <label className="query-input">
            <span>YAAQL</span>
            <input
              autoComplete="off"
              name="q"
              defaultValue={query}
              placeholder='severity in (critical, high) and host:win-* and "powershell.exe"'
            />
          </label>
          <button className="primary-action" type="submit"><Search size={15} aria-hidden /> Run search</button>
        </form>
        {searchResult.error ? <p className="query-error" role="alert">{searchResult.error}</p> : null}
      </section>

      <div className="grid overview-grid">
        <section className="panel">
          <div className="panel-heading">
            <h2>Matching records</h2>
          </div>
          <div className="table-wrap">
            <table className="soc-table">
              <thead>
                <tr><th>Event</th><th>Severity</th><th>Host</th><th>Kind</th><th>Type</th><th>Rule matches</th><th>Seen</th></tr>
              </thead>
              <tbody>
                {matchingRecords.length > 0 ? matchingRecords.map((event) => (
                  <tr key={event.id}>
                    <td><strong>{event.title}</strong><span>{event.id}</span></td>
                    <td><span className={severityClass(event.severity)}>{event.severity}</span></td>
                    <td>{event.hostname ?? "unknown"}</td>
                    <td>{event.kind}</td>
                    <td>{event.eventType ?? "telemetry"}</td>
                    <td>{event.matchedRules.join(", ") || "None"}</td>
                    <td>{relativeTime(event.timestamp)}</td>
                  </tr>
                )) : (
                  <tr>
                    <td colSpan={7}>No records matched.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section className="panel">
          <div className="panel-heading">
            <h2>Saved searches</h2>
          </div>
          <div className="feed-list">
            <article><strong>Critical and high alerts</strong><span>kind:alert and severity in (critical, high)</span></article>
            <article><strong>Encoded PowerShell by host</strong><span>eventType=ProcessLaunch and commandLine:powershell*</span></article>
            <article><strong>Retro-hunt suspicious domains</strong><span>has:domain and (eventType=DnsQuery or title:dns)</span></article>
          </div>
          <h2 className="section-title">Alert pivots</h2>
          <div className="linked-list">
            {alerts.slice(0, 4).map((alert) => (
              <a key={alert.id} href={`/hunt?host=${encodeURIComponent(alert.hostname ?? "")}`}>
                <strong>{alert.hostname ?? "unknown"}</strong>
                <small>{alert.title}</small>
              </a>
            ))}
          </div>
        </section>
      </div>
    </SocShell>
  );
}
