import { Activity, Cloud, Globe2, RadioTower, ShieldAlert } from "lucide-react";
import { PageHeader, SocShell } from "@/components/soc-shell";
import { countryPoints, getWorldViewData } from "@/lib/cloudflare-radar";
import { getSocData } from "@/lib/soc-domain";

export default async function WorldPage() {
  const { alerts } = await getSocData();
  const world = await getWorldViewData(alerts);
  const cloudflare = world.signals.filter((signal) => signal.source === "cloudflare-radar");
  const tawny = world.signals.filter((signal) => signal.source === "tawny");
  const locations = new Set(world.signals.flatMap((signal) => [signal.originCode, signal.targetCode])).size;

  return (
    <SocShell active="/world">
      <PageHeader eyebrow="Global threat view" title="See attack pressure outside your perimeter." description="Cloudflare Radar Layer 7 attack pairs overlaid with geo-attributed Tawny alerts. Global context stays separate from tenant evidence." />
      <section className="world-metrics" aria-label="World view summary">
        <WorldMetric icon={Cloud} label="Radar feed" value={world.status === "live" ? "Live" : world.status === "degraded" ? "Degraded" : "Needs token"} detail={world.lastUpdated ? `Updated ${new Date(world.lastUpdated).toLocaleString()}` : "15 minute cache"} />
        <WorldMetric icon={Globe2} label="Locations" value={locations} detail="origin and target countries" />
        <WorldMetric icon={Activity} label="Global paths" value={cloudflare.length} detail="Cloudflare L7 attack pairs" />
        <WorldMetric icon={ShieldAlert} label="Tenant signals" value={tawny.length} detail="geo-attributed Tawny alerts" />
      </section>

      <section className="world-grid">
        <article className="panel world-map-panel">
          <div className="panel-heading">
            <div><p className="eyebrow">Threat paths</p><h2>Internet attack pressure</h2></div>
            <span className={`status ${world.status === "live" ? "status-healthy" : "status-watch"}`}>{world.status.replace("_", " ")}</span>
          </div>
          <div className="world-map" role="img" aria-label="World map showing Cloudflare Radar attack paths and Tawny alert origins">
            <svg viewBox="0 0 1000 520" preserveAspectRatio="xMidYMid meet">
              <g className="world-land" aria-hidden>
                <path d="M65 95l90-48 102 17 53 68-18 69-72 13-36 66-57-20-17-76-58-27z" />
                <path d="M244 288l58 15 38 62-21 113-55-24-32-91z" />
                <path d="M430 93l77-31 94 23 21 42-45 31 16 50-72 26-61-57-52-18z" />
                <path d="M492 225l88-8 55 73-22 137-63 35-51-90-40-78z" />
                <path d="M604 91l164-37 151 43 27 83-84 34-34 82-81-23-50-68-86-21z" />
                <path d="M780 348l92-21 65 54-30 70-98 14-55-53z" />
              </g>
              <g>
                {world.signals.map((signal) => {
                  const origin = countryPoints[signal.originCode];
                  const target = countryPoints[signal.targetCode];
                  if (!origin || !target) return null;
                  const x1 = origin.x * 10; const y1 = origin.y * 5.2; const x2 = target.x * 10; const y2 = target.y * 5.2;
                  return <g key={signal.id} className={`world-path ${signal.source === "tawny" ? "tenant" : "radar"}`}>
                    <path d={`M ${x1} ${y1} Q ${(x1 + x2) / 2} ${Math.min(y1, y2) - 70} ${x2} ${y2}`} />
                    <circle cx={x1} cy={y1} r={signal.source === "tawny" ? 7 : 4}><title>{`${signal.originName} to ${signal.targetName}: ${signal.value}`}</title></circle>
                  </g>;
                })}
              </g>
            </svg>
            {!world.signals.length ? <div className="world-empty"><RadioTower size={22} aria-hidden /><strong>No geo signals yet</strong><span>Add Radar token or ingest alerts with source_country.</span></div> : null}
          </div>
          <div className="world-legend"><span><i className="radar-dot" /> Cloudflare Radar</span><span><i className="tawny-dot" /> Tawny tenant signal</span></div>
          {world.error ? <p className="world-warning">Radar error: {world.error}</p> : null}
          {!world.configured ? <p className="world-warning">Set <code>CLOUDFLARE_RADAR_API_TOKEN</code> with Account Radar Read permission for live global paths.</p> : null}
        </article>

        <article className="panel world-feed">
          <div className="panel-heading"><div><p className="eyebrow">Ranked routes</p><h2>Current pressure</h2></div></div>
          <div className="world-route-list">
            {world.signals.slice().sort((a, b) => b.value - a.value).slice(0, 12).map((signal, index) => (
              <article key={signal.id}>
                <span>{String(index + 1).padStart(2, "0")}</span>
                <div><strong>{signal.originName} <b>to</b> {signal.targetName}</strong><small>{signal.label} · {signal.source === "tawny" ? `${signal.value}% confidence` : `${signal.value.toFixed(2)}% share`}</small></div>
              </article>
            ))}
            {!world.signals.length ? <p className="muted-copy">No routes available.</p> : null}
          </div>
        </article>
      </section>
    </SocShell>
  );
}

function WorldMetric({ icon: Icon, label, value, detail }: { icon: typeof Globe2; label: string; value: string | number; detail: string }) {
  return <article><Icon size={17} aria-hidden /><div><span>{label}</span><strong>{value}</strong><small>{detail}</small></div></article>;
}
