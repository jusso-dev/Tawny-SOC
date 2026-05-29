export type SocRole = "viewer" | "member" | "analyst" | "responder" | "admin" | "owner";

export type SocPermission =
  | "soc.read"
  | "alert.assign"
  | "alert.dismiss"
  | "alert.suppress"
  | "incident.create"
  | "incident.assign"
  | "incident.transition"
  | "incident.task.create"
  | "incident.evidence.read"
  | "incident.evidence.add"
  | "playbook.run"
  | "integration.kelpie.sync"
  | "integration.manage"
  | "settings.manage"
  | "detection.manage"
  | "threat-intel.manage"
  | "threat-intel.test"
  | "compliance.report.read"
  | "compliance.report.export"
  | "retention.policy.manage"
  | "user.invite"
  | "user.manage"
  | "saved-search.manage"
  | "tenant.manage";

export type SocAction =
  | "assign-alert"
  | "dismiss-alert"
  | "suppress-alert"
  | "create-case"
  | "send-alert-kelpie"
  | "assign-incident"
  | "change-incident-state"
  | "add-task"
  | "run-playbook"
  | "sync-incident-kelpie"
  | "sync-comments"
  | "send-test-alert"
  | "sync-stale-cases"
  | "save-kelpie-config"
  | "save-integration-channel"
  | "test-integration-channel"
  | "add-threat-feed"
  | "test-threat-feed"
  | "save-soc-setting"
  | "invite-user"
  | "add-user"
  | "import-sigma"
  | "duplicate-rule"
  | "disable-rule"
  | "save-search";

export type SocPermissionPolicy = {
  dismissRole?: string;
  suppressRole?: string;
  kelpieRole?: string;
  integrationRole?: string;
  settingsRole?: string;
  userAdminRole?: string;
};

export type SocAuthorizationActor = {
  id: string;
  role?: string | null;
  tenantId?: string;
};

export class SocAuthorizationError extends Error {
  constructor(
    message: string,
    readonly permission: SocPermission,
    readonly role: SocRole,
  ) {
    super(message);
    this.name = "SocAuthorizationError";
  }
}

export const SOC_ROLE_ORDER: Record<SocRole, number> = {
  viewer: 0,
  member: 1,
  analyst: 2,
  responder: 3,
  admin: 4,
  owner: 5,
};

export const SOC_PERMISSION_MINIMUM_ROLES: Record<SocPermission, SocRole> = {
  "soc.read": "viewer",
  "alert.assign": "member",
  "alert.dismiss": "member",
  "alert.suppress": "admin",
  "incident.create": "member",
  "incident.assign": "member",
  "incident.transition": "member",
  "incident.task.create": "member",
  "incident.evidence.read": "viewer",
  "incident.evidence.add": "member",
  "playbook.run": "member",
  "integration.kelpie.sync": "admin",
  "integration.manage": "admin",
  "settings.manage": "admin",
  "detection.manage": "admin",
  "threat-intel.manage": "admin",
  "threat-intel.test": "member",
  "compliance.report.read": "viewer",
  "compliance.report.export": "admin",
  "retention.policy.manage": "admin",
  "user.invite": "admin",
  "user.manage": "owner",
  "saved-search.manage": "member",
  "tenant.manage": "owner",
};

export const SOC_PERMISSION_MATRIX = {
  viewer: permissionsForMinimumRole("viewer"),
  member: permissionsForMinimumRole("member"),
  analyst: permissionsForMinimumRole("analyst"),
  responder: permissionsForMinimumRole("responder"),
  admin: permissionsForMinimumRole("admin"),
  owner: permissionsForMinimumRole("owner"),
} as const satisfies Record<SocRole, readonly SocPermission[]>;

export const SOC_ACTION_PERMISSION_MAP = {
  "assign-alert": "alert.assign",
  "dismiss-alert": "alert.dismiss",
  "suppress-alert": "alert.suppress",
  "create-case": "incident.create",
  "send-alert-kelpie": "integration.kelpie.sync",
  "assign-incident": "incident.assign",
  "change-incident-state": "incident.transition",
  "add-task": "incident.task.create",
  "run-playbook": "playbook.run",
  "sync-incident-kelpie": "integration.kelpie.sync",
  "sync-comments": "integration.kelpie.sync",
  "send-test-alert": "integration.kelpie.sync",
  "sync-stale-cases": "integration.kelpie.sync",
  "save-kelpie-config": "integration.manage",
  "save-integration-channel": "integration.manage",
  "test-integration-channel": "integration.manage",
  "add-threat-feed": "threat-intel.manage",
  "test-threat-feed": "threat-intel.test",
  "save-soc-setting": "settings.manage",
  "invite-user": "user.invite",
  "add-user": "user.manage",
  "import-sigma": "detection.manage",
  "duplicate-rule": "detection.manage",
  "disable-rule": "detection.manage",
  "save-search": "saved-search.manage",
} as const satisfies Record<SocAction, SocPermission>;

export function normalizeSocRole(role: string | null | undefined, fallback: SocRole = "viewer"): SocRole {
  if (!role) return fallback;
  if (role in SOC_ROLE_ORDER) return role as SocRole;
  return fallback;
}

export function roleAtLeast(role: string | null | undefined, minimumRole: string | null | undefined): boolean {
  const normalizedRole = normalizeSocRole(role);
  const normalizedMinimum = normalizeSocRole(minimumRole, "owner");
  return SOC_ROLE_ORDER[normalizedRole] >= SOC_ROLE_ORDER[normalizedMinimum];
}

export function permissionForAction(action: SocAction): SocPermission {
  return SOC_ACTION_PERMISSION_MAP[action];
}

export function minimumRoleForPermission(permission: SocPermission, policy: SocPermissionPolicy = {}): SocRole {
  const baseRole = SOC_PERMISSION_MINIMUM_ROLES[permission];
  const configuredRole = configuredMinimumRole(permission, policy);
  return configuredRole ? normalizeSocRole(configuredRole, baseRole) : baseRole;
}

export function hasSocPermission(
  role: string | null | undefined,
  permission: SocPermission,
  policy: SocPermissionPolicy = {},
): boolean {
  return roleAtLeast(role, minimumRoleForPermission(permission, policy));
}

export function canPerformSocAction(
  role: string | null | undefined,
  action: SocAction,
  policy: SocPermissionPolicy = {},
): boolean {
  return hasSocPermission(role, permissionForAction(action), policy);
}

export function assertSocPermission(
  actor: SocAuthorizationActor,
  permission: SocPermission,
  policy: SocPermissionPolicy = {},
): void {
  const role = normalizeSocRole(actor.role);
  if (hasSocPermission(role, permission, policy)) return;
  throw new SocAuthorizationError(
    `Role ${role} is not permitted to perform ${permission}.`,
    permission,
    role,
  );
}

export function assertSocAction(
  actor: SocAuthorizationActor,
  action: SocAction,
  policy: SocPermissionPolicy = {},
): void {
  assertSocPermission(actor, permissionForAction(action), policy);
}

function permissionsForMinimumRole(role: SocRole): SocPermission[] {
  return Object.entries(SOC_PERMISSION_MINIMUM_ROLES)
    .filter(([, minimumRole]) => SOC_ROLE_ORDER[role] >= SOC_ROLE_ORDER[minimumRole])
    .map(([permission]) => permission as SocPermission);
}

function configuredMinimumRole(permission: SocPermission, policy: SocPermissionPolicy): string | undefined {
  if (permission === "alert.dismiss") return policy.dismissRole;
  if (permission === "alert.suppress") return policy.suppressRole;
  if (permission === "integration.kelpie.sync") return policy.kelpieRole;
  if (permission === "integration.manage") return policy.integrationRole;
  if (permission === "settings.manage" || permission === "retention.policy.manage") return policy.settingsRole;
  if (permission === "user.invite" || permission === "user.manage") return policy.userAdminRole;
  return undefined;
}
