import { AlertTriangle, ArrowRight, Clock3, RadioTower, ShieldAlert, Users } from "lucide-react";
import Link from "next/link";
import { PageHeader, SocShell } from "@/components/soc-shell";
import { getSocData, relativeTime, severityClass } from "@/lib/soc-domain";

function Metric({ label, value, detail }: { label: string; value: string | number; detail: string }) {
  return (
    <div>
      <span>{typeof value === "number" ? value.toLocaleString() : value}</span>
      <p>{label}</p>
      <small>{detail}</small>
    </div>
  );
}

function TopList({ title, rows }: { title: string; rows: Array<{ name: string; count: number }> }) {
  return (
    <section className="panel compact-panel">
      <div className="panel-heading">
        <h2>{title}</h2>
      </div>
      <div className="rank-list">
        {rows.length ? rows.map((row, index) => (
          <div key={`${title}-${row.name}`}>
            <span>{index + 1}</span>
            <strong>{row.name}</strong>
            <em>{row.count}</em>
          </div>
        )) : <p className="muted-copy">No data yet.</p>}
      </div>
    </section>
  );
}

export default async function Home() {
  const { alerts, incidents, overview } = await getSocData();
  const topAlert = alerts[0];

  return (
    <SocShell active="/">
      <PageHeader
        eyebrow="SOC overview"
        title="Tawny endpoint signals, grouped into an analyst-ready SIEM workspace."
        description="Alert pressure, queue health, MITRE coverage, threat intel, and Kelpie sync state in one operational view."
      />

      <section className="metric-row soc-metrics" aria-label="SOC summary">
        <Metric label="alert volume" value={overview.alertVolume} detail="from Tawny alerts and telemetry" />
        <Metric label="incident volume" value={overview.incidentVolume} detail={`${overview.openCases} open cases`} />
        <Metric label="critical/high alerts" value={overview.criticalHigh} detail={`${overview.affectedHosts} affected hosts`} />
        <Metric label="alert-to-case rate" value={`${overview.alertToCaseRate}%`} detail="current conversion" />
      </section>

      <div className="grid overview-grid">
        <section className="panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Queue health</p>
              <h2>Needs attention</h2>
            </div>
            <AlertTriangle size={18} aria-hidden />
          </div>
          <div className="queue-health">
            <div><strong>{overview.unassignedAlerts}</strong><span>Unassigned alerts</span></div>
            <div><strong>{overview.staleAlerts}</strong><span>Stale alerts</span></div>
            <div><strong>{overview.slaBreaches}</strong><span>SLA breaches</span></div>
            <div><strong>{overview.noisyRules.length}</strong><span>Noisy rules</span></div>
          </div>
          <div className="attention-list">
            {overview.needsAttention.map((item) => <p key={item}>{item}</p>)}
          </div>
        </section>

        <section className="panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Trend</p>
              <h2>Alert and case timeline</h2>
            </div>
            <Clock3 size={18} aria-hidden />
          </div>
          {overview.trend.some((point) => point.alerts > 0 || point.cases > 0) ? (
            <>
              <div className="trend-chart" aria-label="Alert and case trend">
                {overview.trend.map((point) => (
                  <div key={point.label}>
                    <span style={{ height: `${point.alerts * 8}px` }} />
                    <i style={{ height: `${point.cases * 10}px` }} />
                    <small>{point.label}</small>
                  </div>
                ))}
              </div>
              <div className="chart-legend">
                <span><b className="legend-alert" /> Alerts</span>
                <span><b className="legend-case" /> Cases</span>
              </div>
            </>
          ) : (
            <div className="empty-state compact">
              <Clock3 size={22} aria-hidden />
              <p>No alert or case timeline data yet.</p>
            </div>
          )}
        </section>
      </div>

      <div className="grid overview-grid wide-left">
        <section className="panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Priority alert</p>
              <h2>What happened, where, why it matters</h2>
            </div>
            <ShieldAlert size={18} aria-hidden />
          </div>
          {topAlert ? (
            <article className="spotlight-alert">
              <div>
                <span className={severityClass(topAlert.severity)}>{topAlert.severity}</span>
                <h3>{topAlert.title}</h3>
                <p>{topAlert.aiSummary}</p>
              </div>
              <dl className="detail-grid">
                <div><dt>Host</dt><dd>{topAlert.hostname ?? "unknown"}</dd></div>
                <div><dt>User</dt><dd>{topAlert.user ?? "unknown"}</dd></div>
                <div><dt>Process</dt><dd>{topAlert.process ?? "unknown"}</dd></div>
                <div><dt>MITRE</dt><dd>{topAlert.mitreTechniques.join(", ") || "Needs mapping"}</dd></div>
                <div><dt>TI matches</dt><dd>{topAlert.tiMatches?.length ?? 0}</dd></div>
                <div><dt>Seen</dt><dd>{relativeTime(topAlert.timestamp)}</dd></div>
              </dl>
              <Link className="primary-action" href={`/alerts/${topAlert.id}`}>
                Open alert detail <ArrowRight size={15} aria-hidden />
              </Link>
            </article>
          ) : (
            <div className="empty-state">
              <ShieldAlert size={22} aria-hidden />
              <p>No Tawny alerts have landed yet. Send Tawny telemetry to <code>POST /api/ingest/tawny</code>.</p>
            </div>
          )}
        </section>

        <section className="panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Open incidents</p>
              <h2>Case ownership</h2>
            </div>
            <Users size={18} aria-hidden />
          </div>
          <div className="case-stack">
            {incidents.slice(0, 4).map((incident) => (
              <Link href={`/incidents/${incident.id}`} key={incident.id}>
                <span className={severityClass(incident.severity)}>{incident.severity}</span>
                <strong>{incident.number}</strong>
                <p>{incident.title}</p>
                <small>{incident.assignee ?? "Unassigned"} · {incident.kelpieSyncStatus.replace("_", " ")}</small>
              </Link>
            ))}
          </div>
        </section>
      </div>

      <div className="grid intel-grid">
        <TopList title="Top rules" rows={overview.topRules} />
        <TopList title="Top MITRE tactics" rows={overview.topTactics} />
        <TopList title="Top users" rows={overview.topUsers} />
        <TopList title="Top processes" rows={overview.topProcesses} />
        <TopList title="Top external IPs" rows={overview.topExternalIps} />
      </div>

      <section className="panel ingestion-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Tawny log sink</p>
            <h2>Native EDR telemetry intake</h2>
          </div>
          <RadioTower size={18} aria-hidden />
        </div>
        <div className="endpoint">
          <code>POST /api/ingest/tawny</code>
          <span>{process.env.TAWNY_SOC_INGEST_TOKEN ? "Bearer token required" : "No ingest token configured"}</span>
        </div>
      </section>
    </SocShell>
  );
}
