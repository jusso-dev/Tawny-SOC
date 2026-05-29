import { IntegrationConfigForm } from "@/components/integration-config-form";
import { PageHeader, SocShell } from "@/components/soc-shell";
import { getSocData } from "@/lib/soc-domain";

export default async function IntegrationsPage() {
  const { kelpieConfig, deliveryLog, integrationChannels } = await getSocData();

  return (
    <SocShell active="/integrations">
      <PageHeader
        eyebrow="Integrations"
        title="Configure outbound alert channels and Kelpie case promotion."
      />

      <IntegrationConfigForm kelpieConfig={kelpieConfig} channels={integrationChannels} />

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
              {!deliveryLog.length ? <tr><td colSpan={6}>No integration deliveries have been recorded.</td></tr> : null}
            </tbody>
          </table>
        </div>
      </section>
    </SocShell>
  );
}
