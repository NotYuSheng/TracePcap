import type { NodeRole } from '../types/insights.types';

/**
 * Human-readable explanation of why a carried-forward label is stale (#369), e.g.
 * "Label may be stale — since the previous snapshot: new protocol (MQTT)."
 */
export function staleTooltip(role: NodeRole): string {
  const changes = (role.staleFields ?? []).join(', ');
  return changes
    ? `Label may be stale — since the previous snapshot: ${changes}.`
    : 'Label may no longer match this snapshot.';
}
