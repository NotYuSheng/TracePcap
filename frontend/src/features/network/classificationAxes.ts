import type { NodeData, NodeType } from './types';
import { NODE_TYPE_CONFIG } from './constants';
import { deviceTypeLabel } from '@/utils/deviceType';

/**
 * Single source of truth for TracePcap's three evidence axes (#499).
 *
 * The model is facts → votes → verdict:
 *   - The three axes are *raw measured facts* about a host, each answering an independent question:
 *       Hardware  — physical fingerprint (MAC OUI manufacturer, observed TTL)
 *       Service   — what it does on the wire (detected service roles, nDPI-identified apps)
 *       Behaviour — how it acted (who opened the connections, measured per #496)
 *   - The backend's classification signals read those same facts and *vote* on device-type
 *     candidates with weights (the ScoreBoard; e.g. 'Mobile app "WhatsApp" → +20' toward MOBILE).
 *   - Identity is the adjudicated *verdict* of that vote. Scores and confidence belong to Identity
 *     and its candidates alone — the AdjudicationPanel's "Why" block renders the per-candidate
 *     score + reasons breakdown; the axes never show scores.
 *
 * Earlier versions blurred this: the Hardware axis echoed the verdict's deviceType back as if it
 * were independent evidence, and vote reasons were keyword-routed into axis buckets, printing the
 * same fact in two places with scores attached to neither type. Axes now show only facts
 * (axisFacts); the vote breakdown lives in the Identity panel.
 */

export type AxisKey = 'behaviour' | 'service' | 'hardware';

export interface AxisMeta {
  key: AxisKey;
  /** Column label, e.g. "Hardware". */
  label: string;
  /** One-line answer this axis gives — shown in the row's info tooltip, not inline. */
  caption: string;
  /** How this evidence is derived — the per-row info-circle text (#499). */
  derivation: string;
}

/** Static per-axis metadata — used by the NodeDetails evidence rows. */
export const AXIS_META: Record<AxisKey, AxisMeta> = {
  hardware: {
    key: 'hardware',
    label: 'Hardware',
    caption: 'physical fingerprint',
    derivation:
      "Physical fingerprint facts — the manufacturer registered for the MAC's OUI prefix, and the observed IP TTL. These feed the Identity vote; the resulting device type is the Identity verdict above, not this row.",
  },
  service: {
    key: 'service',
    label: 'Ports / Service',
    caption: 'what it does on the wire',
    derivation:
      'What the host was observed doing on the wire — a service role (DNS/Web/API) when the backend confirms it actually served one, or the application(s) nDPI identified in its traffic when no service was detected.',
  },
  behaviour: {
    key: 'behaviour',
    label: 'Behaviour',
    caption: 'how it acted in this capture',
    derivation:
      'How the host acted in this capture — measured from who opened each connection (the initiator is the client, the responder is the server).',
  },
};

/** Node types that carry no exposed-service meaning — they mean "just an endpoint". */
const SERVICE_GENERIC: ReadonlySet<NodeType> = new Set(['client', 'unknown', 'l2-device']);

/**
 * Coarse "kind" a specific classification collapses to, for conflict detection. Two axes conflict
 * when they both name a *known* kind and the kinds differ (e.g. Hardware=server vs Service=router).
 */
type Kind = 'router' | 'server' | 'endpoint';

const DEVICE_KIND: Record<string, Kind> = {
  ROUTER: 'router',
  SERVER: 'server',
  DNS_SERVER: 'server',
  WEB_SERVER: 'server',
  API_SERVER: 'server',
  IOT: 'endpoint',
  MOBILE: 'endpoint',
  LAPTOP_DESKTOP: 'endpoint',
};

/** The service (nodeType) kind — every *-server maps to 'server', router to 'router'. */
function serviceKind(nodeType: NodeType): Kind | null {
  if (SERVICE_GENERIC.has(nodeType)) return null;
  if (nodeType === 'router') return 'router';
  return 'server'; // dns-server, web-server, ssh-server, … all expose a service
}

/** The axes in display order — used by the NodeDetails evidence rows. */
export const AXIS_ORDER: readonly AxisKey[] = ['hardware', 'service', 'behaviour'];

/**
 * The measured FACTS an axis rests on (#499) — plain observations, no scores. Scored reasoning
 * (which fact voted how much toward which device type) is the Identity panel's "Why" block, fed by
 * `identityCandidates`; this function must never read those candidates, or the verdict's reasoning
 * would masquerade as independent evidence again.
 */
export function axisFacts(node: NodeData, axis: AxisKey): string[] {
  if (axis === 'hardware') {
    const facts: string[] = [];
    if (node.manufacturer) facts.push(`MAC OUI manufacturer: ${node.manufacturer}`);
    if (node.ttl != null) facts.push(`Observed TTL: ${node.ttl}`);
    return facts;
  }

  if (axis === 'service') {
    const roles = node.serviceRoles ?? [];
    if (roles.length > 0) {
      return roles.map(role => `Observed serving ${role.toUpperCase()} (confirmed from its responses)`);
    }
    return (node.nodeTypeEvidence?.ndpiApps ?? []).map(app => `App identified in its traffic: ${app}`);
  }

  // behaviour — the counts behind the role, from the same measured who-opened-it pass (#496).
  const opened = node.initiatedConversations ?? 0;
  const answered = node.answeredConversations ?? 0;
  if (opened > 0 || answered > 0) {
    const facts: string[] = [];
    if (opened > 0) facts.push(`Opened ${opened} connection${opened === 1 ? '' : 's'}`);
    if (answered > 0) facts.push(`Answered ${answered} connection${answered === 1 ? '' : 's'} opened by peers`);
    else if (opened > 0) facts.push('Never seen answering a connection');
    return facts;
  }

  // Direction was never measured (UDP/ICMP/ARP-only, or a mid-flow capture) → the initiator gate
  // above yields nothing. Fall back to the raw fan-out the router signal actually weighs, so a
  // high-peer host still shows the evidence behind its verdict instead of a blank axis.
  const convs = node.conversationCount ?? 0;
  const peers = node.peerCount ?? 0;
  if (convs > 0 || peers > 0) {
    const facts: string[] = [];
    if (convs > 0) facts.push(`${convs} conversation${convs === 1 ? '' : 's'}`);
    if (peers > 0) facts.push(`${peers} distinct peer${peers === 1 ? '' : 's'} (fan-out)`);
    facts.push('who opened each flow was not measured');
    return facts;
  }
  return [];
}

/**
 * Whether the observed service evidence contradicts the Identity verdict (#499). Both sides are
 * collapsed to a coarse kind (router / server / endpoint); a conflict exists when both name a kind
 * and the kinds differ — e.g. a host that demonstrably served HTTP while the verdict calls it an
 * IoT endpoint (the stray-TLS case), or the inverse. When either side is silent — no exposed
 * service, or an unknown verdict — there is nothing to contradict.
 */
export function detectAxisConflict(node: NodeData): { conflict: boolean; detail?: string } {
  const dt = node.deviceType;
  const svcKind = serviceKind(node.nodeType);
  const verdictKind = dt ? DEVICE_KIND[dt] : undefined;
  if (!svcKind || !verdictKind || svcKind === verdictKind) return { conflict: false };

  return {
    conflict: true,
    detail: `The observed service (${NODE_TYPE_CONFIG[node.nodeType].label}) contradicts the Identity verdict (${deviceTypeLabel(dt!)}).`,
  };
}

