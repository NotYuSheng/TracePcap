import { useEffect, useMemo, useState } from 'react';
import { Button, ButtonGroup, Form } from '@govtechsg/sgds-react';
import { SideDrawer } from '@components/common/SideDrawer';
import { HostDetailModal } from '@components/common/EntityDetailModal/HostDetailModal';
import { Spinner } from '@components/common/Spinner/Spinner';
import {
  clusterApi,
  type ClusterEdge,
  type ClusterGraphResponse,
  type ClusterNode,
} from '@/features/cluster/services/clusterApi';
import { formatBytes } from '@/utils/formatters';
import { CountryMapView } from './CountryMapView';
import { SourceTag } from './SourceTag';
import { groupName, groupNames, hosts as hostsText, squarify } from './layouts';

type View = 'asn' | 'country' | 'map';

const VIEW_LABEL: Record<View, string> = { asn: 'Organisation', country: 'Country', map: 'Map' };
/** Tiles drawn one each; the rest fold into one "smaller" tile, so the tail stays readable. */
const TILES = 16;
const TW = 800;
const TH = 340;

function groupMeta(c: ClusterNode): string {
  if (c.id === 'cluster:internal') return 'Your private address ranges';
  if (c.id === 'cluster:unknown') return 'No organisation or country in the GeoIP data';
  const asn = c.id.startsWith('asn:') ? c.id.slice(4) : null;
  const cc = c.id.startsWith('country:') ? c.id.slice(8) : null;
  return [asn, cc, c.dominantProtocols.slice(0, 3).join(', ')].filter(Boolean).join(' · ');
}

function tone(id: string): string {
  if (id === 'cluster:internal') return 'ov-tile-internal';
  if (id === 'cluster:unknown' || id === 'other') return 'ov-tile-unknown';
  return 'ov-tile-outside';
}

interface Props {
  fileId: string;
  networkId?: string;
  /** The organisation grouping, loaded once by the Overview and shared with the flows card. */
  byOrg: ClusterGraphResponse | null;
}

/**
 * Where the capture's traffic goes: its hosts grouped by organisation (ASN) or country, as tiles
 * sized by traffic, or the world map. Clicking a group opens its hosts and who it talks to.
 */
export function TrafficWhereCard({ fileId, networkId, byOrg }: Props) {
  const [view, setView] = useState<View>('asn');
  const [byCountry, setByCountry] = useState<ClusterGraphResponse | null>(null);
  const [picked, setPicked] = useState<ClusterNode | null>(null);

  // Country is fetched the first time it is asked for.
  useEffect(() => {
    if (view === 'asn' || byCountry) return;
    let alive = true;
    clusterApi
      .getClusters(fileId, 'country', {}, networkId)
      .then(r => alive && setByCountry(r))
      .catch(() => alive && setByCountry({ groupType: 'country', clusters: [], edges: [], hiddenClusters: 0 }));
    return () => {
      alive = false;
    };
  }, [view, byCountry, fileId, networkId]);

  const data = view === 'asn' ? byOrg : byCountry;
  const groups = useMemo(
    () => [...(data?.clusters ?? [])].sort((a, b) => b.totalBytes - a.totalBytes),
    [data]
  );
  const total = groups.length + (data?.hiddenClusters ?? 0);
  const names = useMemo(() => groupNames(groups), [groups]);
  const noun = view === 'asn' ? 'organisations' : 'countries';

  const tiles = useMemo(() => {
    const shown = groups.slice(0, TILES).map(c => ({ value: c.totalBytes, item: c as ClusterNode | null }));
    const rest = groups.slice(TILES);
    const restBytes = rest.reduce((s, c) => s + c.totalBytes, 0);
    if (restBytes > 0) shown.push({ value: restBytes, item: null });
    return squarify(shown, TW, TH).map(t => ({
      ...t,
      restCount: t.item ? 0 : rest.length,
      restHosts: t.item ? 0 : rest.reduce((s, c) => s + c.hostCount, 0),
    }));
  }, [groups]);

  return (
    <section className="ov-card" aria-labelledby="ov-where">
      <div className="ov-head">
        <h2 id="ov-where">Where the traffic goes</h2>
        <SourceTag id="src-where" source="GeoIP" title="How the traffic is grouped">
          <p className="mb-2">
            Each host is put in its organisation (the network's ASN) or its country, from the GeoIP
            data: ipinfo.io when the internet is reachable, the bundled DB-IP database when not.
            Private addresses are your networks.
          </p>
          <p className="mb-0">
            A tile is as big as the traffic its hosts sent and received. Click one for its hosts and
            the groups it talks to.
          </p>
        </SourceTag>
        <ButtonGroup size="sm" className="ms-auto" aria-label="Group by">
          {(Object.keys(VIEW_LABEL) as View[]).map(v => (
            <Button
              key={v}
              variant={view === v ? 'primary' : 'outline-primary'}
              aria-pressed={view === v}
              onClick={() => setView(v)}
            >
              {VIEW_LABEL[v]}
            </Button>
          ))}
        </ButtonGroup>
      </div>

      {!data ? (
        <div className="ov-where-loading">
          <Spinner animation="border" size="sm" /> Loading…
        </div>
      ) : groups.length === 0 ? (
        <p className="small text-muted mb-0">No hosts to group.</p>
      ) : view === 'map' ? (
        <div className="ov-where-map">
          <CountryMapView
            data={data}
            colorMode="traffic"
            selectedClusterId={picked?.id ?? null}
            onSelectCluster={c => setPicked(c)}
            fileId={fileId}
          />
        </div>
      ) : (
        <>
          <p className="small text-muted mb-2">
            {total.toLocaleString()} {noun}, sized by traffic.
          </p>
          <svg
            className="ov-treemap"
            viewBox={`0 0 ${TW} ${TH}`}
            width="100%"
            role="group"
            aria-label={`${noun}, sized by traffic`}
          >
            {tiles.map((t, i) => {
              const c = t.item;
              const name = c ? (names.get(c.id) ?? groupName(c.label)) : `${t.restCount} smaller ${noun}`;
              const hosts = c ? c.hostCount : t.restHosts;
              const fit = Math.max(4, Math.floor(t.w / 7.4));
              const label = name.length > fit ? `${name.slice(0, fit - 1)}…` : name;
              const open = () => c && setPicked(c);
              return (
                <g
                  key={c?.id ?? `rest-${i}`}
                  className={`ov-tile ${tone(c?.id ?? 'other')}${c ? ' ov-tile-pick' : ''}`}
                  role={c ? 'button' : undefined}
                  tabIndex={c ? 0 : undefined}
                  aria-label={`${name}: ${formatBytes(t.value)}, ${hostsText(hosts)}`}
                  onClick={open}
                  onKeyDown={e => {
                    if (c && (e.key === 'Enter' || e.key === ' ')) {
                      e.preventDefault();
                      open();
                    }
                  }}
                >
                  <rect x={t.x + 1} y={t.y + 1} width={Math.max(0, t.w - 2)} height={Math.max(0, t.h - 2)} rx={6} />
                  {t.w > 64 && t.h > 30 && (
                    <text x={t.x + 9} y={t.y + 19} className="ov-tile-name" fontSize={t.w > 150 ? 12.5 : 11}>
                      {label}
                    </text>
                  )}
                  {t.w > 64 && t.h > 48 && (
                    <text x={t.x + 9} y={t.y + 35} className="ov-tile-meta" fontSize={11}>
                      {formatBytes(t.value)} · {hostsText(hosts)}
                    </text>
                  )}
                </g>
              );
            })}
          </svg>
          <div className="ov-legend small text-muted">
            <span><i className="ov-tile-internal" /> your networks</span>
            <span><i className="ov-tile-outside" /> outside</span>
            <span><i className="ov-tile-unknown" /> unknown or smaller</span>
          </div>
        </>
      )}

      <GroupDrawer
        fileId={fileId}
        group={picked}
        edges={data?.edges ?? []}
        groups={data?.clusters ?? []}
        onHide={() => setPicked(null)}
      />
    </section>
  );
}

const MEMBERS_SHOWN = 10;

/** One group: its numbers, its hosts (each opens its identity card) and the groups it talks to. */
function GroupDrawer({
  fileId,
  group,
  edges,
  groups,
  onHide,
}: {
  fileId: string;
  group: ClusterNode | null;
  edges: ClusterEdge[];
  groups: ClusterNode[];
  onHide: () => void;
}) {
  const [query, setQuery] = useState('');
  const [all, setAll] = useState(false);
  const [host, setHost] = useState<string | null>(null);
  const [shownFor, setShownFor] = useState<string | null>(null);
  // A new group starts with the search cleared and the list folded.
  if (group && group.id !== shownFor) {
    setShownFor(group.id);
    setQuery('');
    setAll(false);
  }

  const names = useMemo(() => groupNames(groups), [groups]);
  const members = useMemo(
    () =>
      group
        ? Object.entries(group.ipBytes ?? {})
            .sort((a, b) => b[1] - a[1])
            .map(([ip, bytes]) => ({
              ip,
              bytes,
              conversations: group.ipConversations?.[ip] ?? 0,
              risks: group.ipRisks?.[ip] ?? 0,
            }))
        : [],
    [group]
  );
  const peers = useMemo(() => {
    if (!group) return [];
    return edges
      .filter(e => e.sourceId === group.id || e.targetId === group.id)
      .map(e => ({
        id: e.sourceId === group.id ? e.targetId : e.sourceId,
        bytes: e.totalBytes,
        conversations: e.conversationCount,
        protocol: e.dominantProtocol,
      }))
      .sort((a, b) => b.bytes - a.bytes);
  }, [group, edges]);

  const q = query.trim().toLowerCase();
  const matching = q ? members.filter(m => m.ip.toLowerCase().includes(q)) : members;
  const shown = all || q ? matching : matching.slice(0, MEMBERS_SHOWN);
  const maxMember = Math.max(1, ...members.map(m => m.bytes));
  const maxPeer = Math.max(1, ...peers.map(p => p.bytes));

  return (
    <>
      <SideDrawer
        show={!!group && !host}
        onHide={onHide}
        title={group ? (groupNames(groups).get(group.id) ?? groupName(group.label)) : ''}
        titleId="ov-group-title"
      >
        {group && (
          <div className="ov-group">
            <p className="small text-muted mb-3">{groupMeta(group)}</p>
            <div className="ov-group-stats">
              <div><b>{group.hostCount.toLocaleString()}</b><span>hosts</span></div>
              <div><b>{formatBytes(group.totalBytes)}</b><span>traffic</span></div>
              <div><b>{group.conversationCount.toLocaleString()}</b><span>conversations</span></div>
              <div><b>{group.riskCount.toLocaleString()}</b><span>risks</span></div>
            </div>

            <h3 className="ov-group-h">Hosts</h3>
            {members.length > MEMBERS_SHOWN && (
              <Form.Control
                type="search"
                size="sm"
                placeholder="Search addresses"
                aria-label="Search this group's hosts"
                value={query}
                onChange={e => setQuery(e.target.value)}
                className="mb-2"
              />
            )}
            <table className="ov-group-table">
              <thead>
                <tr>
                  <th scope="col">Address</th>
                  <th scope="col">Traffic</th>
                  <th scope="col" className="text-end">Conv.</th>
                </tr>
              </thead>
              <tbody>
                {shown.map(m => (
                  <tr key={m.ip}>
                    <td>
                      <button type="button" className="btn btn-link p-0 font-monospace ov-group-ip" onClick={() => setHost(m.ip)}>
                        {m.ip}
                      </button>
                      {m.risks > 0 && <span className="badge bg-danger ms-1">{m.risks}</span>}
                    </td>
                    <td>
                      <span className="ov-bar" aria-hidden="true">
                        <span style={{ width: `${Math.max(2, (m.bytes / maxMember) * 100)}%` }} />
                      </span>
                      <span className="ov-group-num">{formatBytes(m.bytes)}</span>
                    </td>
                    <td className="text-end">{m.conversations.toLocaleString()}</td>
                  </tr>
                ))}
                {shown.length === 0 && (
                  <tr>
                    <td colSpan={3} className="text-muted small">No address matches “{query}”.</td>
                  </tr>
                )}
              </tbody>
            </table>
            {!q && members.length > MEMBERS_SHOWN && (
              <Button variant="link" size="sm" className="p-0" onClick={() => setAll(a => !a)}>
                {all ? 'Show fewer' : `Show all ${members.length.toLocaleString()} hosts`}
              </Button>
            )}

            <h3 className="ov-group-h">Talks to</h3>
            {peers.length === 0 ? (
              <p className="small text-muted">No traffic with the other groups.</p>
            ) : (
              <ul className="ov-group-peers">
                {peers.slice(0, 8).map(p => (
                  <li key={p.id}>
                    <span className="ov-group-peer">
                      {names.get(p.id) ?? p.id}
                      {p.protocol && <span className="ov-chip">{p.protocol}</span>}
                    </span>
                    <span className="ov-bar" aria-hidden="true">
                      <span style={{ width: `${Math.max(3, (p.bytes / maxPeer) * 100)}%` }} />
                    </span>
                    <span className="ov-group-num">{formatBytes(p.bytes)}</span>
                  </li>
                ))}
              </ul>
            )}
            {peers.length > 8 && (
              <p className="small text-muted mb-0">and {peers.length - 8} more groups</p>
            )}
          </div>
        )}
      </SideDrawer>
      {host && <HostDetailModal fileId={fileId} ip={host} onClose={() => setHost(null)} />}
    </>
  );
}
