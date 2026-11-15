import { useMemo, useState } from 'react';
import { Button } from '@govtechsg/sgds-react';
import { SideDrawer } from '@components/common/SideDrawer';
import type { ClusterGraphResponse } from '@/features/cluster/services/clusterApi';
import { getProtocolColor } from '@/features/network/constants';
import { formatBytes } from '@/utils/formatters';
import { SourceTag } from './SourceTag';
import { flowLayout, groupNames } from './layouts';

/** Bands drawn; the rest are one click away in the full list. */
const SHOWN = 8;
const W = 800;
const H = 250;
const TOP = 18;
const COL = 230;
const NODE_W = 12;

function clip(s: string, n: number) {
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}

/**
 * The largest flows between organisations: senders on the left, receivers on the right, each band
 * as thick as the bytes between the two. Traffic within one organisation isn't a flow between two,
 * so it shows in that organisation's own numbers instead.
 */
export function FlowsCard({ byOrg }: { byOrg: ClusterGraphResponse | null }) {
  const [showAll, setShowAll] = useState(false);
  const names = useMemo(() => groupNames(byOrg?.clusters ?? []), [byOrg]);
  const edges = useMemo(
    () => [...(byOrg?.edges ?? [])].sort((a, b) => b.totalBytes - a.totalBytes),
    [byOrg]
  );
  const top = edges.slice(0, SHOWN);
  const layout = useMemo(
    () =>
      flowLayout(
        top.map(e => ({ from: e.sourceId, to: e.targetId, value: e.totalBytes })),
        H,
        8,
        TOP
      ),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [byOrg]
  );
  if (!byOrg || edges.length === 0) return null;
  const protocolOf = new Map(top.map(e => [`${e.sourceId}→${e.targetId}`, e.dominantProtocol ?? '']));
  const shownBytes = top.reduce((s, e) => s + e.totalBytes, 0);
  const legend = [...new Set(top.map(e => e.dominantProtocol).filter(Boolean))] as string[];
  const xl = COL;
  const xr = W - COL;
  const xm = (xl + NODE_W + xr) / 2;

  return (
    <section className="ov-card" aria-labelledby="ov-flows">
      <div className="ov-head">
        <h2 id="ov-flows">Flows between organisations</h2>
        <SourceTag id="src-flows" source="tshark and GeoIP" title="How the flows are worked out">
          <p className="mb-0">
            Every conversation between hosts in two different organisations adds its bytes to the
            flow between them. The band's colour is the protocol that carried most of it.
          </p>
        </SourceTag>
        {edges.length > SHOWN && (
          <Button variant="link" size="sm" className="p-0 ms-auto" onClick={() => setShowAll(true)}>
            All {edges.length.toLocaleString()} flows
          </Button>
        )}
      </div>
      <p className="small text-muted mb-1">
        {top.length < edges.length ? `The ${top.length} largest` : `All ${top.length}`},{' '}
        {formatBytes(shownBytes)} together.
      </p>
      <svg
        className="ov-flows"
        viewBox={`0 0 ${W} ${H + TOP + 8}`}
        width="100%"
        role="img"
        aria-label={top
          .map(e => `${names.get(e.sourceId)} to ${names.get(e.targetId)}: ${formatBytes(e.totalBytes)}`)
          .join('; ')}
      >
        <text x={xl + NODE_W / 2} y={11} textAnchor="middle" className="ov-flows-col">FROM</text>
        <text x={xr + NODE_W / 2} y={11} textAnchor="middle" className="ov-flows-col">TO</text>
        {layout.bands.map(b => (
          <path
            key={`${b.from}→${b.to}`}
            className="ov-flow-band"
            fill={getProtocolColor(protocolOf.get(`${b.from}→${b.to}`) ?? '')}
            d={`M${xl + NODE_W},${b.y0} C${xm},${b.y0} ${xm},${b.y1} ${xr},${b.y1} L${xr},${b.y1 + b.h1} C${xm},${b.y1 + b.h1} ${xm},${b.y0 + b.h0} ${xl + NODE_W},${b.y0 + b.h0} Z`}
          >
            <title>{`${names.get(b.from)} → ${names.get(b.to)}: ${formatBytes(b.value)}`}</title>
          </path>
        ))}
        {layout.left.map(n => (
          <g key={`l-${n.id}`}>
            <rect x={xl} y={n.y} width={NODE_W} height={Math.max(2, n.h)} rx={2} className="ov-flow-node" />
            <text x={xl - 7} y={n.y + Math.max(2, n.h) / 2 + 4} textAnchor="end" className="ov-flows-name">
              {clip(names.get(n.id) ?? n.id, 30)}
            </text>
          </g>
        ))}
        {layout.right.map(n => (
          <g key={`r-${n.id}`}>
            <rect x={xr} y={n.y} width={NODE_W} height={Math.max(2, n.h)} rx={2} className="ov-flow-node" />
            <text x={xr + NODE_W + 7} y={n.y + Math.max(2, n.h) / 2 + 4} className="ov-flows-name">
              {clip(names.get(n.id) ?? n.id, 30)}
            </text>
          </g>
        ))}
      </svg>
      <div className="ov-legend small text-muted">
        {legend.map(p => (
          <span key={p}>
            <i style={{ background: getProtocolColor(p) }} /> {p}
          </span>
        ))}
      </div>

      <SideDrawer
        show={showAll}
        onHide={() => setShowAll(false)}
        title="Flows between organisations"
        titleId="ov-flows-all"
        badge={edges.length}
      >
        <table className="ov-group-table">
          <thead>
            <tr>
              <th scope="col">From</th>
              <th scope="col">To</th>
              <th scope="col" className="text-end">Traffic</th>
              <th scope="col" className="text-end">Conv.</th>
            </tr>
          </thead>
          <tbody>
            {edges.map(e => (
              <tr key={`${e.sourceId}→${e.targetId}`}>
                <td>{names.get(e.sourceId) ?? e.sourceId}</td>
                <td>
                  {names.get(e.targetId) ?? e.targetId}
                  {e.dominantProtocol && <span className="ov-chip">{e.dominantProtocol}</span>}
                </td>
                <td className="text-end text-nowrap">{formatBytes(e.totalBytes)}</td>
                <td className="text-end">{e.conversationCount.toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </SideDrawer>
    </section>
  );
}
