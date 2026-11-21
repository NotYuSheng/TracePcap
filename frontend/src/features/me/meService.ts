import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';

/** A permission in the catalogue. Mirrors the backend PermissionAction enum. */
export type PermissionAction =
  | 'SEE_CAPTURES'
  | 'DOWNLOAD_REPORT'
  | 'READ_AUDIT_LOG'
  | 'UPLOAD_CAPTURES'
  | 'ASK_AI'
  | 'EXPORT_PACKETS'
  | 'LABEL_HOSTS'
  | 'OVERRIDE_ANSWERS'
  | 'HOST_OCCUPANCY'
  | 'NETWORK_MAP'
  | 'DETECTION_RULES_CAPTURE'
  | 'DETECTION_RULES_NETWORK'
  | 'DETECTION_RULES_GLOBAL'
  | 'NETWORK_CAPTURES'
  | 'NETWORK_CREATE'
  | 'NETWORK_SETTINGS'
  | 'NETWORK_DELETE'
  | 'KEEP_CAPTURES'
  | 'DELETE_OWN_CAPTURES'
  | 'DELETE_ANY_CAPTURES'
  | 'RETENTION'
  | 'ADDRESS_DEFAULTS'
  | 'ANALYSIS_POLICY'
  | 'LLM_CONNECTION'
  | 'CANCEL_OTHERS_AI_JOBS'
  | 'MANAGE_ROLES';

/** Mirrors PermissionDto: one permission, and whether the caller has it. */
export interface Permission {
  action: PermissionAction;
  label: string;
  description: string;
  group: string;
  /** The group's heading, e.g. "Detection rules". */
  groupLabel: string;
  /** The catalogue's suggested lowest built-in role: viewer, analyst, lead or admin. */
  suggestedRole: string;
  /** Everyone sees captures and only admin manages roles: no role's set can change these. */
  fixed: boolean;
  allowed: boolean;
  /** Why not, shown next to the greyed-out control. Null when allowed. */
  reason?: string | null;
}

/** Mirrors RoleDto: a role and what it may do. Who has it is set in Keycloak, by its key. */
export interface Role {
  /** The Keycloak client role (on the app's client) that gives this role. */
  key: string;
  label: string;
  description?: string | null;
  builtIn: boolean;
  /** The role for someone whose sign-in carries none of TracePcap's roles. */
  defaultRole: boolean;
  /** False for the admin role, which always has every permission. */
  editable: boolean;
  permissions: PermissionAction[];
}

/** A change to a role; omitted fields stay as they are. Name and description: custom roles only. */
export interface RoleChange {
  permissions?: PermissionAction[];
  defaultRole?: boolean;
  label?: string;
  description?: string;
}

/** Mirrors CreateRoleRequest. */
export interface NewRole {
  key: string;
  label: string;
  description?: string;
  /** A role whose permissions the new one starts with. */
  copyFrom?: string;
}

/** Mirrors MeDto. */
export interface Me {
  username: string;
  authEnabled: boolean;
  admin: boolean;
  canManagePermissions: boolean;
  /** The TracePcap roles that apply to the caller: from their sign-in, or the default role. */
  roles: string[];
  permissions: Permission[];
}

/** Mirrors AuditLogDto. */
export interface AuditLogEntry {
  id: number;
  at: string;
  actor: string;
  action: string;
  targetType: string;
  targetId?: string | null;
  before?: Record<string, unknown> | null;
  after?: Record<string, unknown> | null;
}

/** Mirrors PagedResponse. */
export interface Paged<T> {
  data: T[];
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
}

export const meService = {
  getMe: async (): Promise<Me> => (await apiClient.get<Me>(API_ENDPOINTS.ME)).data,
  getRoles: async (): Promise<Role[]> => (await apiClient.get<Role[]>(API_ENDPOINTS.ROLES)).data,
  /** Replaces what a role may do, and/or makes it the default role. Admin only. */
  updateRole: async (key: string, change: RoleChange): Promise<Role> =>
    (await apiClient.patch<Role>(API_ENDPOINTS.ROLE(key), change)).data,
  /** A custom role, named by the Keycloak client role that gives it. Admin only. */
  createRole: async (role: NewRole): Promise<Role> =>
    (await apiClient.post<Role>(API_ENDPOINTS.ROLES, role)).data,
  /** Deletes a custom role (not a built-in one, nor the default). Admin only. */
  deleteRole: async (key: string): Promise<void> => {
    await apiClient.delete(API_ENDPOINTS.ROLE(key));
  },
  getAuditLog: async (
    page: number,
    pageSize: number,
    search?: string,
    targetTypes?: string[]
  ): Promise<Paged<AuditLogEntry>> =>
    (
      await apiClient.get<Paged<AuditLogEntry>>(API_ENDPOINTS.AUDIT_LOG, {
        params: {
          page,
          pageSize,
          ...(search ? { search } : {}),
          ...(targetTypes?.length ? { targetTypes } : {}),
        },
        // targetTypes=a&targetTypes=b, as Spring reads a list.
        paramsSerializer: { indexes: null },
      })
    ).data,
};
