"use client";

import { KeyRound, Send, ShieldCheck, UserPlus } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";
import { notify } from "@/components/toast-provider";

type MemberRow = {
  id: string;
  email: string;
  name: string;
  role: string;
  createdAt: string;
};

type InvitationRow = {
  id: string;
  email: string;
  role: string;
  status: string;
  createdAt: string;
  expiresAt?: string;
};

export function AdminAccessForms({
  members,
  invitations,
  twoFactorEnabled,
}: {
  members: MemberRow[];
  invitations: InvitationRow[];
  twoFactorEnabled: boolean;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [busyAction, setBusyAction] = useState("");
  const [totpURI, setTotpURI] = useState("");
  const [backupCodes, setBackupCodes] = useState<string[]>([]);

  function action(payload: Record<string, unknown>, key: string) {
    setBusyAction(key);
    startTransition(async () => {
      const res = await fetch("/api/soc/actions", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      const body = await res.json().catch(() => ({})) as { message?: string; error?: string };
      setBusyAction("");
      if (!res.ok) {
        notify(body.error ?? "Team action failed.", "error");
        return;
      }
      notify(body.message ?? "Team updated.", "success");
      router.refresh();
    });
  }

  function enableTwoFactor(formData: FormData) {
    setBusyAction("2fa-enable");
    startTransition(async () => {
      const res = await fetch("/api/auth/two-factor/enable", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          password: String(formData.get("password") ?? "") || undefined,
          issuer: "Tawny-SOC",
        }),
      });
      const body = await res.json().catch(() => ({})) as { totpURI?: string; backupCodes?: string[]; message?: string };
      setBusyAction("");
      if (!res.ok || !body.totpURI) {
        notify(body.message ?? "2FA setup failed.", "error");
        return;
      }
      setTotpURI(body.totpURI);
      setBackupCodes(body.backupCodes ?? []);
      notify("2FA setup started.", "success");
    });
  }

  function verifyTwoFactor(formData: FormData) {
    setBusyAction("2fa-verify");
    startTransition(async () => {
      const res = await fetch("/api/auth/two-factor/verify-totp", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ code: String(formData.get("code") ?? "") }),
      });
      setBusyAction("");
      if (!res.ok) {
        notify("2FA code verification failed.", "error");
        return;
      }
      notify("2FA enabled.", "success");
      router.refresh();
    });
  }

  function disableTwoFactor(formData: FormData) {
    setBusyAction("2fa-disable");
    startTransition(async () => {
      const res = await fetch("/api/auth/two-factor/disable", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ password: String(formData.get("password") ?? "") || undefined }),
      });
      setBusyAction("");
      if (!res.ok) {
        notify("2FA disable failed.", "error");
        return;
      }
      notify("2FA disabled.", "success");
      router.refresh();
    });
  }

  return (
    <div className="admin-stack">
      <div className="grid overview-grid">
        <form className="config-form" action={(formData) => action({
          action: "invite-user",
          email: formData.get("email"),
          role: formData.get("role"),
        }, "invite")}>
          <div className="config-form-heading">
            <div>
              <h3>Invite user</h3>
              <p>Create an invitation and send a magic link.</p>
            </div>
            <Send size={18} aria-hidden />
          </div>
          <label>
            <span>Email</span>
            <input name="email" type="email" required />
          </label>
          <RoleSelect />
          <div className="config-actions">
            <button type="submit" disabled={pending && busyAction === "invite"}><Send size={15} aria-hidden /> Send invite</button>
          </div>
        </form>

        <form className="config-form" action={(formData) => action({
          action: "add-user",
          email: formData.get("email"),
          role: formData.get("role"),
        }, "add")}>
          <div className="config-form-heading">
            <div>
              <h3>Add existing user</h3>
              <p>Add an account that already exists in this install.</p>
            </div>
            <UserPlus size={18} aria-hidden />
          </div>
          <label>
            <span>Email</span>
            <input name="email" type="email" required />
          </label>
          <RoleSelect />
          <div className="config-actions">
            <button type="submit" disabled={pending && busyAction === "add"}><UserPlus size={15} aria-hidden /> Add user</button>
          </div>
        </form>
      </div>

      <section className="panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Members</p>
            <h2>Tenant access</h2>
          </div>
          <UserPlus size={18} aria-hidden />
        </div>
        <div className="table-wrap">
          <table className="soc-table">
            <thead>
              <tr><th>Name</th><th>Email</th><th>Role</th><th>Created</th></tr>
            </thead>
            <tbody>
              {members.map((member) => (
                <tr key={member.id}>
                  <td>{member.name}</td>
                  <td>{member.email}</td>
                  <td>{member.role}</td>
                  <td>{new Date(member.createdAt).toLocaleDateString()}</td>
                </tr>
              ))}
              {!members.length ? <tr><td colSpan={4}>No members found for this tenant.</td></tr> : null}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Invitations</p>
            <h2>Pending access</h2>
          </div>
          <KeyRound size={18} aria-hidden />
        </div>
        <div className="table-wrap">
          <table className="soc-table">
            <thead>
              <tr><th>Email</th><th>Role</th><th>Status</th><th>Expires</th></tr>
            </thead>
            <tbody>
              {invitations.map((invite) => (
                <tr key={invite.id}>
                  <td>{invite.email}</td>
                  <td>{invite.role}</td>
                  <td>{invite.status}</td>
                  <td>{invite.expiresAt ? new Date(invite.expiresAt).toLocaleDateString() : "No expiry"}</td>
                </tr>
              ))}
              {!invitations.length ? <tr><td colSpan={4}>No invitations have been created.</td></tr> : null}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Multi-factor</p>
            <h2>Two-factor authentication</h2>
          </div>
          <span className={twoFactorEnabled ? "status status-healthy" : "status status-watch"}>
            {twoFactorEnabled ? "Enabled" : "Not enabled"}
          </span>
        </div>
        {twoFactorEnabled ? (
          <form className="config-form compact-form" action={disableTwoFactor}>
            <label>
              <span>Password</span>
              <input name="password" type="password" autoComplete="current-password" />
            </label>
            <div className="config-actions">
              <button type="submit" disabled={pending && busyAction === "2fa-disable"}><ShieldCheck size={15} aria-hidden /> Disable 2FA</button>
            </div>
          </form>
        ) : (
          <div className="grid overview-grid">
            <form className="config-form compact-form" action={enableTwoFactor}>
              <label>
                <span>Password</span>
                <input name="password" type="password" autoComplete="current-password" />
              </label>
              <div className="config-actions">
                <button type="submit" disabled={pending && busyAction === "2fa-enable"}><ShieldCheck size={15} aria-hidden /> Generate TOTP</button>
              </div>
            </form>
            <form className="config-form compact-form" action={verifyTwoFactor}>
              <label>
                <span>Authenticator code</span>
                <input name="code" inputMode="numeric" autoComplete="one-time-code" required />
              </label>
              <div className="config-actions">
                <button type="submit" disabled={!totpURI || (pending && busyAction === "2fa-verify")}><ShieldCheck size={15} aria-hidden /> Verify 2FA</button>
              </div>
            </form>
          </div>
        )}
        {totpURI ? (
          <div className="secret-output">
            <span>TOTP URI</span>
            <code>{totpURI}</code>
            {backupCodes.length ? (
              <>
                <span>Backup codes</span>
                <code>{backupCodes.join(" ")}</code>
              </>
            ) : null}
          </div>
        ) : null}
      </section>
    </div>
  );
}

function RoleSelect() {
  return (
    <label>
      <span>Role</span>
      <select name="role" defaultValue="member">
        <option value="member">Member</option>
        <option value="admin">Admin</option>
        <option value="owner">Owner</option>
      </select>
    </label>
  );
}
