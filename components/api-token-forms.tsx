"use client";

import { KeyRound, Save, Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";
import { notify } from "@/components/toast-provider";
import {
  allowedApiTokenScopesForRole,
  apiTokenScopes,
  type ApiTokenRole,
} from "@/lib/api-token-policy";
import type { ApiTokenRecord } from "@/lib/store";

export function ApiTokenForms({ tokens }: { tokens: ApiTokenRecord[] }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [busyKey, setBusyKey] = useState("");
  const [createdToken, setCreatedToken] = useState("");
  const [createRole, setCreateRole] = useState<ApiTokenRole>("member");

  function request(payload: Record<string, unknown>, busy: string, onSuccess?: (body: Record<string, unknown>) => void) {
    setBusyKey(busy);
    startTransition(async () => {
      const res = await fetch("/api/soc/actions", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      const body = await res.json().catch(() => ({})) as { message?: string; error?: string } & Record<string, unknown>;
      setBusyKey("");
      if (!res.ok) {
        notify(body.error ?? "API token action failed.", "error");
        return;
      }
      notify(body.message ?? "API token updated.", "success");
      onSuccess?.(body);
      router.refresh();
    });
  }

  function create(formData: FormData) {
    request({
      action: "create-api-token",
      name: formData.get("name"),
      role: formData.get("role"),
      scopes: formData.getAll("scopes"),
      expiresAt: formData.get("expiresAt"),
    }, "create", (body) => {
      setCreatedToken(typeof body.token === "string" ? body.token : "");
    });
  }

  function update(formData: FormData, tokenId: string) {
    request({
      action: "update-api-token",
      tokenId,
      name: formData.get("name"),
      role: formData.get("role"),
      scopes: formData.getAll("scopes"),
      status: formData.get("status"),
      expiresAt: formData.get("expiresAt"),
    }, `update-${tokenId}`);
  }

  function remove(tokenId: string) {
    request({ action: "delete-api-token", tokenId }, `delete-${tokenId}`);
  }

  return (
    <div className="api-token-stack">
      <form className="config-form" action={create}>
        <div className="config-form-heading">
          <div>
            <h3>Create API token</h3>
            <p>Tokens are scoped to this tenant. The secret is shown once.</p>
          </div>
          <KeyRound size={18} aria-hidden />
        </div>
        <div className="config-grid">
          <label>
            <span>Name</span>
            <input name="name" required placeholder="Tawny collector prod" />
          </label>
          <label>
            <span>Role</span>
            <select name="role" value={createRole} onChange={(event) => setCreateRole(event.target.value as ApiTokenRole)}>
              <option value="member">Member</option>
              <option value="admin">Admin</option>
              <option value="owner">Owner</option>
            </select>
          </label>
          <label>
            <span>Expires</span>
            <input name="expiresAt" type="date" />
          </label>
        </div>
        <ScopeGrid role={createRole} selected={["ingest:write"]} />
        <div className="config-actions">
          <button type="submit" disabled={pending && busyKey === "create"}><KeyRound size={15} aria-hidden /> {pending && busyKey === "create" ? "Creating..." : "Create token"}</button>
        </div>
      </form>

      {createdToken ? (
        <div className="secret-output">
          <span>New token secret</span>
          <code>{createdToken}</code>
        </div>
      ) : null}

      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Existing API tokens</h2>
            <p>Update names, roles, scopes, expiry, or delete tokens that should no longer authenticate.</p>
          </div>
        </div>
        <div className="api-token-list">
          {tokens.map((token) => (
            <TokenEditForm
              busyKey={busyKey}
              key={token.id}
              onDelete={remove}
              onUpdate={update}
              pending={pending}
              token={token}
            />
          ))}
          {!tokens.length ? <p className="muted-copy">No tenant API tokens have been created.</p> : null}
        </div>
      </section>
    </div>
  );
}

function TokenEditForm({
  busyKey,
  onDelete,
  onUpdate,
  pending,
  token,
}: {
  busyKey: string;
  onDelete: (tokenId: string) => void;
  onUpdate: (formData: FormData, tokenId: string) => void;
  pending: boolean;
  token: ApiTokenRecord;
}) {
  const [role, setRole] = useState<ApiTokenRole>(token.role);
  const expiresAt = token.expiresAt ? token.expiresAt.slice(0, 10) : "";

  return (
    <form className="config-form compact-form" action={(formData) => onUpdate(formData, token.id)}>
      <div className="config-form-heading">
        <div>
          <h3>{token.name}</h3>
          <p>{token.tokenPrefix} · created {new Date(token.createdAt).toLocaleDateString()}</p>
        </div>
        <span className={token.status === "active" ? "status status-healthy" : "status status-watch"}>{token.status}</span>
      </div>
      <div className="config-grid">
        <label>
          <span>Name</span>
          <input name="name" defaultValue={token.name} required />
        </label>
        <label>
          <span>Role</span>
          <select name="role" value={role} onChange={(event) => setRole(event.target.value as ApiTokenRole)}>
            <option value="member">Member</option>
            <option value="admin">Admin</option>
            <option value="owner">Owner</option>
          </select>
        </label>
        <label>
          <span>Status</span>
          <select name="status" defaultValue={token.status}>
            <option value="active">Active</option>
            <option value="revoked">Revoked</option>
          </select>
        </label>
        <label>
          <span>Expires</span>
          <input name="expiresAt" type="date" defaultValue={expiresAt} />
        </label>
      </div>
      <ScopeGrid role={role} selected={token.scopes} />
      <div className="token-meta">
        <span>Last used: {token.lastUsedAt ? new Date(token.lastUsedAt).toLocaleString() : "Never"}</span>
        {token.revokedAt ? <span>Revoked: {new Date(token.revokedAt).toLocaleString()}</span> : null}
      </div>
      <div className="config-actions">
        <button type="submit" disabled={pending && busyKey === `update-${token.id}`}><Save size={15} aria-hidden /> Save</button>
        <button
          className="secondary"
          disabled={pending && busyKey === `delete-${token.id}`}
          onClick={() => onDelete(token.id)}
          type="button"
        >
          <Trash2 size={15} aria-hidden /> Delete
        </button>
      </div>
    </form>
  );
}

function ScopeGrid({ role, selected }: { role: ApiTokenRole; selected: string[] }) {
  const allowed = new Set(allowedApiTokenScopesForRole(role));

  return (
    <fieldset className="scope-fieldset">
      <legend>Scopes</legend>
      <div className="scope-grid">
        {apiTokenScopes.map((scope) => {
          const disabled = !allowed.has(scope.id);
          return (
            <label className="checkbox-field" key={scope.id}>
              <input
                defaultChecked={!disabled && selected.includes(scope.id)}
                disabled={disabled}
                name="scopes"
                type="checkbox"
                value={scope.id}
              />
              <span>{scope.label}<small>{scope.detail}</small></span>
            </label>
          );
        })}
      </div>
    </fieldset>
  );
}
