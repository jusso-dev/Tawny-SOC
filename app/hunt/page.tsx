import { Save, Search } from "lucide-react";
import { PageHeader, SocShell } from "@/components/soc-shell";
import { getSocData, relativeTime, severityClass } from "@/lib/soc-domain";

export default async function HuntPage() {
  const { events, alerts } = await getSocData();

  return (
    <SocShell active="/hunt">
      <PageHeader
        eyebrow="Search / hunt"
        title="Build SIEM-style searches over Tawny telemetry, then pivot from alerts into scoped hunts."
        actions={<button className="text-button"><Save size={15} aria-hidden /> Save search</button>}
      />

      <section className="panel query-builder">
        <div className="panel-heading">
          <h2>Query builder</h2>
          <button className="primary-action"><Search size={15} aria-hidden /> Run search</button>
        </div>
        <div className="query-grid">
          {["Event type", "Host", "User", "Process", "Hash", "IP", "Domain", "Time range"].map((field) => (
            <label key={field}>
              <span>{field}</span>
              <input placeholder={field === "Time range" ? "Last 24 hours" : `Filter ${field.toLowerCase()}`} />
            </label>
          ))}
        </div>
      </section>

      <div className="grid overview-grid">
        <section className="panel">
          <div className="panel-heading">
            <h2>Recent telemetry</h2>
          </div>
          <div className="table-wrap">
            <table className="soc-table">
              <thead>
                <tr><th>Event</th><th>Severity</th><th>Host</th><th>Type</th><th>Rule matches</th><th>Seen</th></tr>
              </thead>
              <tbody>
                {events.map((event) => (
                  <tr key={event.id}>
                    <td><strong>{event.title}</strong><span>{event.id}</span></td>
                    <td><span className={severityClass(event.severity)}>{event.severity}</span></td>
                    <td>{event.hostname ?? "unknown"}</td>
                    <td>{event.eventType ?? "telemetry"}</td>
                    <td>{event.matchedRules.join(", ") || "None"}</td>
                    <td>{relativeTime(event.timestamp)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="panel">
          <div className="panel-heading">
            <h2>Saved searches</h2>
          </div>
          <div className="feed-list">
            <article><strong>Encoded PowerShell by host</strong><span>eventType=ProcessLaunch process=powershell*</span></article>
            <article><strong>External IP from critical alerts</strong><span>severity in critical,high has:externalIp</span></article>
            <article><strong>Retro-hunt suspicious domains</strong><span>domain in threat_intel.watchlist</span></article>
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
