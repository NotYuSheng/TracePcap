import type { GraphNode, GraphEdge, NetworkGraphData } from '../types';

/**
 * Returns true when two nodes represent the same physical host.
 *
 * IP match is required. If both nodes have a MAC address, they must also
 * match — a MAC mismatch means the IP was reused (e.g. DHCP lease turnover)
 * and the nodes should NOT be merged.
 *
 * L2-only nodes (identified by MAC, no real IP) are matched by their MAC id
 * and never get the MAC-conflict split treatment.
 */
function isSameHost(a: GraphNode, b: GraphNode): boolean {
  if (a.data.isL2 || b.data.isL2) return a.id === b.id;
  const macA = a.data.mac?.toLowerCase();
  const macB = b.data.mac?.toLowerCase();
  if (macA && macB && macA !== macB) return false;
  return true;
}

function edgeKey(e: GraphEdge): string {
  const appOrProto = (e.data.appName ?? e.data.protocol).toLowerCase();
  return `${e.source}\0${e.target}\0${appOrProto}`;
}

/**
 * Merge N NetworkGraphData objects into a single unified graph for comparison.
 *
 * Nodes are matched by IP (node ID) with a MAC tiebreaker: if both nodes have
 * a MAC address and they differ, the IP is treated as reused (e.g. DHCP lease
 * turnover) and the nodes are kept separate rather than incorrectly merged.
 *
 * Edges are matched by the (source, target, appOrProtocol) triple — the same
 * dedup key used in NetworkGraph's deduplicateEdges function.
 *
 * Each resulting node/edge carries a `sources` array indicating which file(s)
 * it appears in, which drives the visual encoding in NetworkGraph.
 */
export function mergeGraphs(
  graphs: NetworkGraphData[],
  labels: string[]
): NetworkGraphData {
  const nodeMap = new Map<string, GraphNode>();
  const edgeMap = new Map<string, GraphEdge>();

  for (let i = 0; i < graphs.length; i++) {
    const graph = graphs[i];
    const label = labels[i];

    // ── Per-file node ID remap (for MAC-conflict splits within this file) ────
    // Maps this file's original node ID → the ID used in nodeMap.
    const nodeIdRemap = new Map<string, string>();

    // ── Nodes ────────────────────────────────────────────────────────────────
    for (const node of graph.nodes) {
      const existing = nodeMap.get(node.id);

      if (existing && isSameHost(existing, node)) {
        // Same host seen in a previous file — accumulate stats and add label
        nodeMap.set(node.id, {
          ...existing,
          data: {
            ...existing.data,
            packetsSent: existing.data.packetsSent + node.data.packetsSent,
            packetsReceived: existing.data.packetsReceived + node.data.packetsReceived,
            bytesSent: existing.data.bytesSent + node.data.bytesSent,
            bytesReceived: existing.data.bytesReceived + node.data.bytesReceived,
            totalBytes: existing.data.totalBytes + node.data.totalBytes,
            connections: existing.data.connections + node.data.connections,
            protocols: [...new Set([...existing.data.protocols, ...node.data.protocols])],
            isAnomaly: existing.data.isAnomaly || node.data.isAnomaly,
            sources: [...(existing.data.sources ?? []), label],
          },
        });
        nodeIdRemap.set(node.id, node.id);
      } else if (existing) {
        // Same IP but different MAC — IP was reused by a different host.
        const remappedId = `${node.id}~${label}`;
        nodeMap.set(remappedId, {
          ...node,
          id: remappedId,
          data: { ...node.data, sources: [label] },
        });
        nodeIdRemap.set(node.id, remappedId);
      } else {
        // First time we see this node
        nodeMap.set(node.id, {
          ...node,
          data: { ...node.data, sources: [label] },
        });
        nodeIdRemap.set(node.id, node.id);
      }
    }

    // ── Edges ────────────────────────────────────────────────────────────────
    for (const edge of graph.edges) {
      const remappedEdge: GraphEdge = {
        ...edge,
        source: nodeIdRemap.get(edge.source) ?? edge.source,
        target: nodeIdRemap.get(edge.target) ?? edge.target,
      };
      const key = edgeKey(remappedEdge);
      const existing = edgeMap.get(key);

      if (existing) {
        const totalPackets = existing.data.packetCount + remappedEdge.data.packetCount;
        const totalBytes = existing.data.totalBytes + remappedEdge.data.totalBytes;
        const raw = existing.data.appName ?? existing.data.protocol;
        const displayName = raw.charAt(0).toUpperCase() + raw.slice(1);
        edgeMap.set(key, {
          ...existing,
          id: `${existing.id}|${remappedEdge.id}`,
          label: `${displayName} (${totalPackets})`,
          data: {
            ...existing.data,
            packetCount: totalPackets,
            totalBytes,
            sources: [...(existing.data.sources ?? []), label],
          },
        });
      } else {
        edgeMap.set(key, {
          ...remappedEdge,
          data: { ...remappedEdge.data, sources: [label] },
        });
      }
    }
  }

  const mergedNodes = [...nodeMap.values()];
  const mergedEdges = [...edgeMap.values()];

  const protocolBreakdown: Record<string, number> = {};
  for (const edge of mergedEdges) {
    const proto = edge.data.protocol;
    protocolBreakdown[proto] = (protocolBreakdown[proto] ?? 0) + edge.data.packetCount;
  }

  const totalPackets = graphs.reduce((s, g) => s + g.stats.totalPackets, 0);
  const totalBytes = graphs.reduce((s, g) => s + g.stats.totalBytes, 0);

  return {
    nodes: mergedNodes,
    edges: mergedEdges,
    stats: {
      totalNodes: mergedNodes.length,
      totalEdges: mergedEdges.length,
      totalPackets,
      totalBytes,
      protocolBreakdown,
    },
  };
}
