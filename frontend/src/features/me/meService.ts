import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';

/** A configurable action (#915). Mirrors the backend PermissionAction enum. */
export type PermissionAction =
  | 'DETECTION_RULES_GLOBAL'
  | 'DETECTION_RULES_NETWORK'
  | 'DETECTION_RULES_CAPTURE'
  | 'HOST_OCCUPANCY'
  | 'NETWORK_SETTINGS'
  | 'ANALYSIS_POLICY'
  | 'RETENTION';

export type PermissionLevel = 'ANALYST' | 'ADMIN';

/** Mirrors PermissionDto: one action as it applies to the caller. */
export interface Permission {
  action: PermissionAction;
  label: string;
  description: string;
  level: PermissionLevel;
  defaultLevel: PermissionLevel;
  allowed: boolean;
  /** Why not, shown next to the greyed-out control. Null when allowed. */
  reason?: string | null;
}

/** Mirrors MeDto. */
export interface Me {
  username: string;
  authEnabled: boolean;
  admin: boolean;
  canManagePermissions: boolean;
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
  setPermissionLevel: async (action: PermissionAction, level: PermissionLevel): Promise<Permission> =>
    (await apiClient.put<Permission>(API_ENDPOINTS.PERMISSION(action), { level })).data,
  getAuditLog: async (page: number, pageSize: number, search?: string): Promise<Paged<AuditLogEntry>> =>
    (
      await apiClient.get<Paged<AuditLogEntry>>(API_ENDPOINTS.AUDIT_LOG, {
        params: { page, pageSize, ...(search ? { search } : {}) },
      })
    ).data,
};
