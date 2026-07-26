import type { GraphNode } from '@/features/network/types';
import type { EntityType } from '@/features/notes/services/entityNotesService';

/**
 * Derives the {@link EntityDetailModal} identity props from a graph node, mirroring the mapping the
 * former NodeDetails did internally (#578): a pure-L2 node is a DEVICE keyed by MAC; everything else
 * is an IP keyed by its address.
 */
export function graphNodeEntity(node: GraphNode): {
  entityType: EntityType;
  entityKey: string;
  displayName: string;
} {
  const entityType: EntityType = node.data.isL2 ? 'DEVICE' : 'IP';
  const entityKey = node.data.isL2 ? (node.data.mac ?? node.data.ip) : node.data.ip;
  return { entityType, entityKey, displayName: entityKey };
}
