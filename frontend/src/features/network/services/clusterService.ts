import type { GraphNode, GraphEdge, NodeData } from '@/features/network/types';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const NEVER_CLUSTER_PREFIXES = ['127.', '169.254.', '224.', '239.', 'ff0', 'fe80'];

function isNeverClustered(ip: string): boolean {
  return NEVER_CLUSTER_PREFIXES.some(p => ip.startsWith(p));
}

/** Returns the /24 candidate key for an IPv4 address. */
function slash24Key(ip: string): string {
  const parts = ip.split('.');
  return `cluster:${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

/** Returns the /16 fallback key for an IPv4 address. */
function slash16Key(ip: string): string {
  const parts = ip.split('.');
  return `cluster:${parts[0]}.${parts[1]}.0.0/16`;
}

/**
 * Computes the effective cluster key for every node using a two-pass strategy:
 *
 * Pass 1 — group all eligible IPv4 nodes by /24.
 * Pass 2 — any /24 group with only 1 member is "promoted" to /16, so scattered
 *           IPs (e.g. 250 unique /24s) still get grouped rather than left as
 *           individual nodes.  /16 groups with only 1 member pass through unchanged.
 *
 * IPv6 nodes always group by their first 4 colon-delimited groups (/64-ish).
 * L2/loopback/multicast nodes return null (never clustered).
 */
function buildClusterKeyMap(nodes: GraphNode[]): Map<string, string> {
  const keyMap = new Map<string, string>(); // nodeId → final clusterId

  // ── IPv6 and ineligible nodes ──
  const eligible: GraphNode[] = [];
  for (const node of nodes) {
    if (node.data.isL2) continue;
    const ip = node.data.ip;
    if (!ip || isNeverClustered(ip)) continue;

    if (ip.includes(':')) {
      const groups = ip.split(':');
      keyMap.set(node.id, `cluster:${groups.slice(0, 4).join(':')}::/64`);
      continue;
    }

    const parts = ip.split('.');
    if (parts.length !== 4) continue;
    eligible.push(node);
  }

  // ── Pass 1: count /24 members ──
  const slash24Count = new Map<string, number>();
  for (const node of eligible) {
    const k = slash24Key(node.data.ip);
    slash24Count.set(k, (slash24Count.get(k) ?? 0) + 1);
  }

  // ── Pass 2: assign final key (/24 if ≥2 members, else /16) ──
  for (const node of eligible) {
    const k24 = slash24Key(node.data.ip);
    if ((slash24Count.get(k24) ?? 0) >= 2) {
      keyMap.set(node.id, k24);
    } else {
      // Promote to /16 — scattered IPs in the same /16 will group together
      keyMap.set(node.id, slash16Key(node.data.ip));
    }
  }

  return keyMap;
}

function subnetLabel(clusterId: string): string {
  const inner = clusterId.replace(/^cluster:/, '');
  if (inner.endsWith('/24')) return inner.replace(/\.0\/24$/, '.x');
  if (inner.endsWith('/16')) return inner.replace(/\.0\.0\/16$/, '.x.x');
  // IPv6
  return inner.replace(/:\/64$/, ':…');
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

export function applySubnetClustering(
  nodes: GraphNode[],
  edges: GraphEdge[],
  expandedClusters: Set<string>
): { nodes: GraphNode[]; edges: GraphEdge[] } {
  // ── Step 1: assign each node to a cluster key ────────────────────────────
  const nodeToCluster = buildClusterKeyMap(nodes); // nodeId → clusterId
  const clusterToMembers = new Map<string, GraphNode[]>(); // clusterId → members

  for (const node of nodes) {
    const key = nodeToCluster.get(node.id);
    if (!key) continue; // never clustered — L2, loopback, etc.
    const members = clusterToMembers.get(key) ?? [];
    members.push(node);
    clusterToMembers.set(key, members);
  }

  // ── Step 2: decide which clusters are active (collapsed) ─────────────────
  // A cluster is active when it has 2+ members AND is not expanded
  const activeClusters = new Set<string>();
  for (const [id, members] of clusterToMembers) {
    if (members.length >= 2 && !expandedClusters.has(id)) {
      activeClusters.add(id);
    }
  }

  // For non-active clusters, their members pass through individually
  // Build a set of node IDs that are inside active clusters
  const clusteredNodeIds = new Set<string>();
  for (const [clusterId, members] of clusterToMembers) {
    if (activeClusters.has(clusterId)) {
      members.forEach(n => clusteredNodeIds.add(n.id));
    }
  }

  // ── Step 3: build output nodes ───────────────────────────────────────────
  const outputNodes: GraphNode[] = [];

  // Pass-through: unclustered nodes and members of expanded/single clusters
  for (const node of nodes) {
    if (!clusteredNodeIds.has(node.id)) {
      outputNodes.push(node);
    }
  }

  // Collect intra-cluster edge protocols for dominant protocol calculation
  const clusterIntraProtocols = new Map<string, Map<string, number>>(); // clusterId → proto → count

  for (const edge of edges) {
    const sc = nodeToCluster.get(edge.source);
    const tc = nodeToCluster.get(edge.target);
    if (sc && tc && sc === tc && activeClusters.has(sc)) {
      const protoMap = clusterIntraProtocols.get(sc) ?? new Map<string, number>();
      const proto = edge.data.appName ?? edge.data.protocol;
      protoMap.set(proto, (protoMap.get(proto) ?? 0) + edge.data.packetCount);
      clusterIntraProtocols.set(sc, protoMap);
    }
  }

  // Synthetic cluster nodes
  for (const clusterId of activeClusters) {
    const members = clusterToMembers.get(clusterId)!;

    let totalBytes = 0;
    let totalConnections = 0;
    const roleBreakdown = { client: 0, server: 0, both: 0, unknown: 0 };
    let hasAnomaly = false;
    const allSources = new Set<string>();

    for (const m of members) {
      totalBytes += m.data.totalBytes;
      totalConnections += m.data.connections;
      roleBreakdown[m.data.role as keyof typeof roleBreakdown] =
        (roleBreakdown[m.data.role as keyof typeof roleBreakdown] ?? 0) + 1;
      if (m.data.isAnomaly) hasAnomaly = true;
      m.data.sources?.forEach(s => allSources.add(s));
    }

    // Top 3 dominant protocols from intra-cluster edges
    const protoMap = clusterIntraProtocols.get(clusterId);
    const dominantProtocols = protoMap
      ? [...protoMap.entries()]
          .sort((a, b) => b[1] - a[1])
          .slice(0, 3)
          .map(([p]) => p)
      : [];

    const label = subnetLabel(clusterId);
    const statsText = `${members.length} nodes · ${formatBytes(totalBytes)}`;

    const clusterData: NodeData = {
      ip: clusterId, // synthetic — not a real IP
      packetsSent: 0,
      packetsReceived: 0,
      bytesSent: 0,
      bytesReceived: 0,
      totalBytes,
      role: 'unknown',
      protocols: dominantProtocols,
      connections: totalConnections,
      isAnomaly: hasAnomaly,
      nodeType: 'unknown',
      nodeTypeEvidence: { dominantPort: null, connectionCount: 0, distinctPeers: 0 },
      sources: allSources.size > 0 ? [...allSources] : undefined,
      // Cluster-specific
      isCluster: true,
      clusterId,
      memberCount: members.length,
      memberIds: members.map(m => m.id),
      roleBreakdown,
      dominantProtocols,
      // Reuse hostname as stats display text
      hostname: statsText,
    };

    outputNodes.push({ id: clusterId, label, data: clusterData });
  }

  // ── Step 4: remap and aggregate edges ────────────────────────────────────
  // resolvedId: if node is in active cluster → clusterId, else node.id
  const resolve = (nodeId: string): string => {
    const cid = nodeToCluster.get(nodeId);
    return cid && activeClusters.has(cid) ? cid : nodeId;
  };

  // Aggregate by (resolvedSource, resolvedTarget, protocol)
  const edgeAgg = new Map<
    string,
    { edge: GraphEdge; packetCount: number; totalBytes: number }
  >();

  for (const edge of edges) {
    const rs = resolve(edge.source);
    const rt = resolve(edge.target);

    // Drop intra-cluster edges
    if (rs === rt) continue;

    const proto = (edge.data.appName ?? edge.data.protocol).toLowerCase();
    const key = `${rs}\0${rt}\0${proto}`;

    const existing = edgeAgg.get(key);
    if (existing) {
      existing.packetCount += edge.data.packetCount;
      existing.totalBytes += edge.data.totalBytes;
    } else {
      edgeAgg.set(key, {
        edge: { ...edge, id: key, source: rs, target: rt },
        packetCount: edge.data.packetCount,
        totalBytes: edge.data.totalBytes,
      });
    }
  }

  const outputEdges: GraphEdge[] = [...edgeAgg.values()].map(({ edge, packetCount, totalBytes }) => {
    const raw = edge.data.appName ?? edge.data.protocol;
    const displayName = raw.charAt(0).toUpperCase() + raw.slice(1);
    return {
      ...edge,
      label: `${displayName} (${packetCount.toLocaleString()})`,
      data: { ...edge.data, packetCount, totalBytes },
    };
  });

  return { nodes: outputNodes, edges: outputEdges };
}
