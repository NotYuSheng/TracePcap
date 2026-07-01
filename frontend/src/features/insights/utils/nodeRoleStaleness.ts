import { parseDateTime } from '@/utils/dateUtils';
import type { NodeRole } from '../types/insights.types';

/**
 * Human-readable explanation of why a confirmed label is stale (#369), e.g.
 * "Label set 1 Nov 2025. Since then: MAC changed, new protocol (MQTT)."
 */
export function staleTooltip(role: NodeRole): string {
  const changes = (role.staleFields ?? []).join(', ');
  let prefix = 'Label';
  if (role.labeledAt) {
    const ms = parseDateTime(role.labeledAt as unknown as string | number[]);
    if (ms) {
      prefix = `Label set ${new Date(ms).toLocaleDateString('en-GB', {
        day: 'numeric',
        month: 'short',
        year: 'numeric',
      })}`;
    }
  }
  return changes ? `${prefix}. Since then: ${changes}.` : `${prefix} may be out of date.`;
}
