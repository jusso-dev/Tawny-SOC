import { IngestionConfigForms } from "@/components/ingestion-config-forms";
import { IntegrationConfigForm } from "@/components/integration-config-form";
import { PageHeader, SocShell } from "@/components/soc-shell";
import { getSocData } from "@/lib/soc-domain";

export default async function IntegrationsPage() {
  const { connectorCatalog, connectors, ingestDeadLetters, ingestSources, kelpieConfig, deliveryLog, integrationChannels } = await getSocData();

  return (
    <SocShell active="/integrations">
      <PageHeader
        eyebrow="Integrations"
        title="Configure outbound alert channels and Kelpie case promotion."
      />

      <IntegrationConfigForm kelpieConfig={kelpieConfig} channels={integrationChannels} />

      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Ingestion sources and connector catalog</h2>
            <p>Register source contracts, configure connector credentials, and validate parser mappings before logs are accepted.</p>
          </div>
        </div>
        <IngestionConfigForms catalog={connectorCatalog} connectors={connectors} sources={ingestSources} />
      </section>

      <section className="panel">
        <div className="panel-heading">
          <h2>Ingestion health</h2>
        </div>
        <div className="table-wrap">
          <table className="soc-table">
            <thead>
              <tr><th>Source</th><th>Type</th><th>Parser</th><th>Status</th><th>Last seen</th><th>Rejected</th></tr>
            </thead>
            <tbody>
              {ingestSources.map((source) => (
                <tr key={source.id}>
                  <td>{source.name}<span>{source.id}</span></td>
                  <td>{source.sourceType}</td>
                  <td>{source.parser}</td>
                  <td>{source.status}</td>
                  <td>{source.lastSeenAt ? new Date(source.lastSeenAt).toLocaleString() : "Never"}</td>
                  <td>{ingestDeadLetters.filter((letter) => letter.sourceId === source.id).length}</td>
                </tr>
              ))}
              {!ingestSources.length ? <tr><td colSpan={6}>No ingestion sources have been configured.</td></tr> : null}
            </tbody>
          </table>
        </div>
      </section>

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
