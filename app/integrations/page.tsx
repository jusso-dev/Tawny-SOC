import { Bot, Cable, ShieldCheck } from "lucide-react";
import Link from "next/link";
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

      <section className="panel hermes-integration" id="hermes">
        <div className="panel-heading">
          <div><p className="eyebrow">Hermes Bot Mode</p><h2>Install 13 named SOC bots with durable shared rooms.</h2><p>Each profile gets own <code>SOUL.md</code>, Bot Mode identity, scoped remote MCP tools, and complete Tawny-side collaboration trace.</p></div>
          <Bot size={20} aria-hidden />
        </div>
        <div className="hermes-setup-grid">
          <div>
            <span className="setup-number">01</span><h3>Create per-bot tokens</h3><p>Create one member token per profile. Include <code>agent-rooms:read</code> and <code>agent-rooms:write</code>; unique token names provide durable actor attribution.</p>
            <Link className="text-button" href="/settings/api-tokens">Open API tokens</Link>
          </div>
          <div>
            <span className="setup-number">02</span><h3>Install profiles</h3>
            <pre><code>{`pnpm hermes:profiles:install

# Existing profiles: review, then replace only managed files
pnpm hermes:profiles:install -- --force`}</code></pre>
          </div>
          <div>
            <span className="setup-number">03</span><h3>Add secrets and group</h3><p>Copy each profile&apos;s <code>.env.EXAMPLE</code> to <code>.env</code>, add its dedicated token, then create Hermes group <strong>Tawny SOC War Room</strong> and seat all profiles.</p>
          </div>
          <div>
            <span className="setup-number">04</span><h3>Reload and prove</h3><p>Reload MCP for each profile. Open alert mission in group; verify same room appears under <Link href="/war-room">War room</Link> with messages, tool inputs, outputs, handoffs, and timestamps.</p>
            <div className="hermes-proof"><Cable size={15} aria-hidden /><span>Native Bot Mode</span><ShieldCheck size={15} aria-hidden /><span>Per-bot audit</span></div>
          </div>
        </div>
      </section>

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
