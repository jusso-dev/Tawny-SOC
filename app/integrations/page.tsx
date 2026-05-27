import { RefreshCw, Send, Settings } from "lucide-react";
import { PageHeader, SocShell } from "@/components/soc-shell";
import { deliveryLog, getSocData } from "@/lib/soc-domain";

export default async function IntegrationsPage() {
  const { kelpieConfig } = await getSocData();
  const channels = [
    { name: "Email", state: "ready", detail: "Route SOC summaries and digest notifications" },
    { name: "Slack", state: "ready", detail: "Forward critical/high alerts to response channels" },
    { name: "Webhook", state: "ready", detail: "Generic outbound automation channel" },
    { name: "Microsoft Sentinel", state: "ready", detail: "Forward Tawny notable events to Log Analytics" },
    { name: "Wazuh", state: "ready", detail: "Forward decoded Tawny events to Wazuh" },
    { name: "Kelpie", state: kelpieConfig.enabled ? "enabled" : "disabled", detail: "Promote alerts and incidents to Kelpie cases" },
  ];

  return (
    <SocShell active="/integrations">
      <PageHeader
        eyebrow="Integrations"
        title="Configure outbound alert channels and Kelpie case promotion."
        actions={<button className="text-button"><Settings size={15} aria-hidden /> Configure</button>}
      />

      <div className="grid overview-grid">
        <section className="panel">
          <div className="panel-heading">
            <h2>Kelpie integration</h2>
            <span className={kelpieConfig.tokenConfigured ? "status status-healthy" : "status status-watch"}>
              {kelpieConfig.tokenConfigured ? "Token configured" : "Needs token"}
            </span>
          </div>
          <dl className="detail-grid">
            <div><dt>Base URL</dt><dd>{kelpieConfig.baseUrl}</dd></div>
            <div><dt>Dedupe</dt><dd>{kelpieConfig.dedupeBy}</dd></div>
            <div><dt>Alert endpoint</dt><dd>POST /api/v1/alerts</dd></div>
            <div><dt>Case endpoint</dt><dd>POST /api/v1/cases</dd></div>
            <div><dt>Sync fields</dt><dd>{kelpieConfig.syncFields.join(", ")}</dd></div>
            <div><dt>External refs</dt><dd>tawny-alert-* and tawny-case-*</dd></div>
          </dl>
          <div className="card-actions">
            <button><Send size={15} aria-hidden /> Send test alert</button>
            <button><RefreshCw size={15} aria-hidden /> Sync stale cases</button>
          </div>
        </section>

        <section className="panel">
          <div className="panel-heading">
            <h2>Outbound channels</h2>
          </div>
          <div className="feed-list">
            {channels.map((channel) => (
              <article key={channel.name}>
                <strong>{channel.name}</strong>
                <span>{channel.state}</span>
                <small>{channel.detail}</small>
              </article>
            ))}
          </div>
        </section>
      </div>

      <section className="panel">
        <div className="panel-heading">
          <h2>Delivery state</h2>
        </div>
        <div className="table-wrap">
          <table className="soc-table">
            <thead>
              <tr><th>Channel</th><th>Target</th><th>State</th><th>Attempts</th><th>External ref</th><th>Error</th></tr>
            </thead>
            <tbody>
              {deliveryLog.map((delivery) => (
                <tr key={delivery.id}>
                  <td>{delivery.channel}</td>
                  <td>{delivery.target}</td>
                  <td>{delivery.state}</td>
                  <td>{delivery.attempts}</td>
                  <td>{delivery.externalRef ?? "None"}</td>
                  <td>{delivery.error ?? "None"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </SocShell>
  );
}
