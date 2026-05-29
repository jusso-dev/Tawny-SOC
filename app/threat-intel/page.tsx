import { Search } from "lucide-react";
import Link from "next/link";
import { PageHeader, SocShell } from "@/components/soc-shell";
import { ThreatFeedForm } from "@/components/threat-feed-form";
import { getSocData, relativeTime, timeUntil } from "@/lib/soc-domain";
import { quoteYaaqlValue } from "@/lib/yaaql";

export default async function ThreatIntelPage() {
  const { threatIntelFeeds, threatIntelMatches, alerts, incidents } = await getSocData();

  return (
    <SocShell active="/threat-intel">
      <PageHeader
        eyebrow="Threat intelligence"
        title="Configure feed endpoints, test ingestion, enrich alerts, and retro-hunt Tawny telemetry."
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
                <th>Expires</th>
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
                  <td>{timeUntil(ioc.expiry)}</td>
                  <td>{alerts.filter((alert) => (alert.tiMatches ?? []).some((match) => match.id === ioc.id)).length}</td>
                  <td>{incidents.filter((incident) => incident.observables.some((match) => match.id === ioc.id)).length}</td>
                  <td><Link className="inline-action" href={`/hunt?q=${encodeURIComponent(`${ioc.type}:${quoteYaaqlValue(ioc.value)}`)}`}><Search size={14} aria-hidden /> Retro-hunt</Link></td>
                </tr>
              ))}
              {!threatIntelMatches.length ? <tr><td colSpan={11}>No indicators loaded yet. Add and test a feed first.</td></tr> : null}
            </tbody>
          </table>
        </div>
      </section>
    </SocShell>
  );
}
