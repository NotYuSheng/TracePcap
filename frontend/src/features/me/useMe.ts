import { useEffect, useState } from 'react';
import { meService, type Me, type Permission, type PermissionAction } from './meService';

// One request shared by every component that mounts at the same time. It's cleared once settled,
// so the next mount (e.g. reopening a modal) sees permission changes an admin made since.
let inflight: Promise<Me> | null = null;

function fetchMe(): Promise<Me> {
  if (!inflight) {
    inflight = meService.getMe().finally(() => {
      inflight = null;
    });
  }
  return inflight;
}

/** The caller's identity and permissions (#915), or null while loading or if the request failed. */
export function useMe(): Me | null {
  const [me, setMe] = useState<Me | null>(null);
  useEffect(() => {
    let active = true;
    fetchMe()
      .then(m => active && setMe(m))
      .catch(() => active && setMe(null));
    return () => {
      active = false;
    };
  }, []);
  return me;
}

export interface PermissionState {
  /**
   * False only when the server says the caller may not. While loading, or if /me failed, this is
   * true: the server enforces the permission on save anyway, so the UI shouldn't lock people out
   * because a read failed.
   */
  allowed: boolean;
  reason: string | null;
  permission: Permission | null;
}

/** Whether the caller may perform {@code action}, and why not. */
export function usePermission(action: PermissionAction): PermissionState {
  const me = useMe();
  const permission = me?.permissions.find(p => p.action === action) ?? null;
  return {
    allowed: permission ? permission.allowed : true,
    reason: permission && !permission.allowed ? (permission.reason ?? null) : null,
    permission,
  };
}
