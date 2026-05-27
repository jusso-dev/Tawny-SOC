import { RadioTower, Search } from "lucide-react";
import { PageHeader, SocShell } from "@/components/soc-shell";
import { getSocData, relativeTime } from "@/lib/soc-domain";

export default async function ThreatIntelPage() {
  const { threatIntelFeeds, threatIntelMatches, alerts, incidents } = await getSocData();

  return (
    <SocShell active="/threat-intel">
      <PageHeader
        eyebrow="Threat intelligence"
        title="Manage feeds, browse IOCs, enrich alerts, and retro-hunt historical Tawny telemetry."
        actions={<button className="text-button"><RadioTower size={15} aria-hidden /> Add feed</button>}
      />

      <div className="grid overview-grid">
        <section className="panel">
          <div className="panel-heading">
            <h2>Feed management</h2>
            <span className="status status-healthy">{threatIntelFeeds.filter((feed) => feed.enabled).length} enabled</span>
          </div>
          <div className="feed-list">
            {threatIntelFeeds.map((feed) => (
              <article key={feed.id}>
                <strong>{feed.name}</strong>
                <span>{feed.type} · {feed.indicatorCount.toLocaleString()} indicators · {feed.status}</span>
                <small>{feed.url}</small>
              </article>
            ))}
          </div>
        </section>

        <section className="panel">
          <div className="panel-heading">
            <h2>Automatic mapping</h2>
            <Search size={18} aria-hidden />
          </div>
          <dl className="detail-grid">
            <div><dt>Related alerts</dt><dd>{alerts.filter((alert) => (alert.tiMatches ?? []).length > 0).length}</dd></div>
            <div><dt>Related cases</dt><dd>{incidents.filter((incident) => incident.observables.length > 0).length}</dd></div>
            <div><dt>Retro-hunt mode</dt><dd>Query historical Tawny telemetry by IOC value</dd></div>
            <div><dt>Supported formats</dt><dd>STIX, OpenIOC, CSV, TXT, MISP, OTX, URLhaus, custom URL</dd></div>
          </dl>
        </section>
      </div>

      <section className="panel">
        <div className="table-wrap">
          <table className="soc-table">
            <thead>
              <tr>
                <th>IOC</th>
                <th>Type</th>
                <th>Source feed</th>
                <th>Confidence</th>
                <th>Tags</th>
                <th>First seen</th>
                <th>Last seen</th>
                <th>Related alerts</th>
                <th>Related cases</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {threatIntelMatches.map((ioc) => (
                <tr key={ioc.id}>
                  <td><strong>{ioc.value}</strong></td>
                  <td>{ioc.type}</td>
                  <td>{ioc.sourceFeed}</td>
                  <td>{ioc.confidence}%</td>
                  <td>{ioc.tags.join(", ")}</td>
                  <td>{relativeTime(ioc.firstSeen)}</td>
                  <td>{relativeTime(ioc.lastSeen)}</td>
                  <td>{alerts.filter((alert) => (alert.tiMatches ?? []).some((match) => match.id === ioc.id)).length}</td>
                  <td>{incidents.filter((incident) => incident.observables.some((match) => match.id === ioc.id)).length}</td>
                  <td><button className="inline-action"><Search size={14} aria-hidden /> Retro-hunt</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </SocShell>
  );
}
