import type { GraphNode } from '../types';
import type { NetworkSegment } from '@/features/networkSegments/networkSegmentService';
import type { CustomPrivateRange } from '@/features/cluster/types/customPrivateRange.types';
import { ipInCidr, isPrivateIp } from '@/utils/ipClassification';
import { deviceTypeLabel, nodeIdentityKey } from '@/utils/deviceType';
import type { DeviceType } from '@/types';

/**
 * The "Network map" layout: devices grouped the way an analyst would draw them by hand — nested
 * boxes, every level shown.
 *
 *   Your networks ▸ network (DHCP / VLAN segment) ▸ subnet ▸ device family ▸ devices
 *   Internet      ▸ domain (from the hostname)                         ▸ hosts
 *   Broadcast and multicast                                            ▸ addresses
 *
 * Pure: building the tree and laying it out take nodes and return data, so both are testable and
 * the graph only has to place nodes and draw the boxes.
 */

export type GroupKind = 'local' | 'internet' | 'special' | 'network' | 'subnet' | 'type' | 'domain' | 'user';

export interface GroupNode {
  id: string;
  kind: GroupKind;
  label: string;
  detail?: string;
  /** Depth: 1 for the outermost boxes. */
  level: number;
  children: GroupNode[];
  /** Devices directly in this group (only on the innermost groups). */
  nodeIds: string[];
  /** Index of the network among its siblings, so each network gets its own colour. */
  tone?: number;
  /** Devices the analyst moved into this group. */
  movedIds?: string[];
  /** The automatic name, when the analyst renamed the group. */
  autoLabel?: string;
  /** The analyst's note on the group. */
  note?: string;
}

export interface GroupBox {
  id: string;
  kind: GroupKind;
  label: string;
  detail?: string;
  level: number;
  tone?: number;
  /** Members, deep: every device in the box. */
  count: number;
  /** An innermost box: it holds devices, and a device can be moved into it. */
  leaf: boolean;
  /** Devices the analyst moved into this box. */
  moved: number;
  /** The analyst's note, drawn under the name. */
  note?: string;
  /** This box's header band (layout units): taller when it carries a note. */
  header: number;
  memberIds: string[];
  /** Layout units, y pointing down. */
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface GroupedLayout {
  positions: Map<string, { x: number; y: number }>;
  boxes: GroupBox[];
  /** Header band height per level, in layout units (where the box's name sits). */
  headerFor: (level: number) => number;
}

interface Options {
  segments?: NetworkSegment[];
  customRanges?: CustomPrivateRange[];
  /** Names clients looked these addresses up by (forward DNS): the domain when a host has no hostname. */
  dnsNames?: Map<string, string>;
  /** The analyst's moves (#649): device → the group they put it in. Applied over the automatic grouping. */
  placements?: Record<string, string>;
  /** The analyst's own groups, each inside a group of the map. */
  userGroups?: { id: string; name: string; parentId: string }[];
  /** Group id → the name the analyst gave it. */
  names?: Record<string, string>;
  /** Group id → the analyst's note. */
  notes?: Record<string, string>;
}

/**
 * Address → the name clients looked it up by, from the DNS query logs. Where several names
 * resolved to one address (a CDN, a shared front end), the most-queried one wins.
 */
export function dnsNamesByIp(
  logs: { entries: { queryName: string; resolvedIps: string[]; queryCount: number }[] }[],
): Map<string, string> {
  const best = new Map<string, { name: string; count: number }>();
  for (const log of logs) {
    for (const e of log.entries) {
      for (const ip of e.resolvedIps) {
        const cur = best.get(ip);
        if (!cur || e.queryCount > cur.count) best.set(ip, { name: e.queryName.replace(/\.$/, ''), count: e.queryCount });
      }
    }
  }
  return new Map([...best].map(([ip, v]) => [ip, v.name]));
}

/** The address part of a node id: `10.0.0.73@1700…` / `192.168.1.10~vlan:20` → the address. */
function addressOf(id: string): string {
  return id.split(/[@~]/)[0];
}

function isSpecial(ip: string): boolean {
  if (ip === '0.0.0.0' || ip === '255.255.255.255' || ip === '::') return true;
  const first = Number(ip.split('.')[0]);
  if (!ip.includes(':') && first >= 224 && first <= 239) return true;
  return /^ff[0-9a-f]{2}:/i.test(ip);
}

/** `192.168.1.0/24` for IPv4, the /64 for IPv6. */
export function subnetOf(ip: string): string {
  if (ip.includes(':')) {
    const parts = ip.split(':').filter(Boolean);
    return `${parts.slice(0, 4).join(':')}::/64`;
  }
  const p = ip.split('.');
  return p.length === 4 ? `${p[0]}.${p[1]}.${p[2]}.0/24` : ip;
}

/** `cdn.example.co.uk` → `example.co.uk`; `www.google.com` → `google.com`. */
export function domainOf(hostname: string): string {
  const parts = hostname.toLowerCase().replace(/\.$/, '').split('.');
  if (parts.length <= 2) return parts.join('.');
  // A two-letter country code under a short second level (co.uk, com.au, ac.jp…) keeps three.
  const tld = parts[parts.length - 1];
  const sld = parts[parts.length - 2];
  const keep = tld.length === 2 && sld.length <= 3 ? 3 : 2;
  return parts.slice(-keep).join('.');
}

/**
 * The device-type level groups by family, not by exact classification: a DNS server and a web
 * server are both servers. The exact type stays on each device's own label.
 */
const FAMILIES: Record<string, string> = {
  SERVER: 'Servers',
  DNS_SERVER: 'Servers',
  WEB_SERVER: 'Servers',
  API_SERVER: 'Servers',
  ROUTER: 'Routers',
  LAPTOP_DESKTOP: 'Laptops and desktops',
  MOBILE: 'Phones and tablets',
  IOT: 'IoT devices',
  L2_DEVICE: 'Layer-2 devices',
  VIRTUAL_ADDRESS: 'Virtual addresses',
  UNKNOWN: 'Unclassified',
};

export function familyOf(node: GraphNode): string {
  const key = nodeIdentityKey(node.data);
  const family = FAMILIES[key];
  if (family) return family;
  const label = deviceTypeLabel(key as DeviceType);
  // A custom classification value (#926) is its own group: PRINTER_A3 → Printer a3.
  return /^[A-Z0-9_]+$/.test(label) ? label.charAt(0) + label.slice(1).toLowerCase().replace(/_/g, ' ') : label;
}

function segmentDetail(s: NetworkSegment): string {
  const parts: string[] = [];
  if (s.cidr) parts.push(s.cidr);
  if (s.routers.length) parts.push(`gateway ${s.routers.join(', ')}`);
  if (s.serverIds.length) parts.push(`DHCP ${s.serverIds.join(', ')}`);
  return parts.join(' · ');
}

/**
 * Which network a node belongs to: its device key names it; else, among the networks whose range
 * holds its address, the one that leased to its MAC, then the one whose gateway or DHCP server it
 * is, then the only one that leased its address, then the only one whose range holds it. The range check matters for a router that serves
 * several VLANs with one MAC: each interface goes to its own network.
 */
function segmentFor(node: GraphNode, segments: NetworkSegment[]): NetworkSegment | undefined {
  const tilde = node.id.indexOf('~');
  if (tilde !== -1) {
    const key = node.id.slice(tilde + 1).split('@')[0];
    const s = segments.find(x => x.key === key);
    if (s) return s;
  }
  const ip = addressOf(node.id);
  const inRange = segments.filter(x => !x.cidr || ipInCidr(ip, x.cidr));
  const mac = node.data.mac?.toLowerCase();
  if (mac) {
    const s = inRange.find(x => x.clients.some(c => c.mac.toLowerCase() === mac));
    if (s) return s;
  }
  const infra = inRange.filter(x => x.routers.includes(ip) || x.serverIds.includes(ip));
  if (infra.length === 1) return infra[0];
  const holders = inRange.filter(x => x.clients.some(c => c.ip === ip));
  if (holders.length === 1) return holders[0];
  // A statically addressed host (a server, a printer) leased nothing, but sits in its network's
  // range: it belongs there when exactly one network has that range (with overlaps, it's unknown).
  const ranged = segments.filter(x => x.cidr && ipInCidr(ip, x.cidr));
  return holders.length === 0 && ranged.length === 1 ? ranged[0] : undefined;
}

function bucket<T>(items: T[], keyOf: (t: T) => string): Map<string, T[]> {
  const m = new Map<string, T[]>();
  for (const it of items) {
    const k = keyOf(it);
    const arr = m.get(k);
    if (arr) arr.push(it);
    else m.set(k, [it]);
  }
  return m;
}

const byLabel = (a: GroupNode, b: GroupNode) => a.label.localeCompare(b.label, undefined, { numeric: true });

/** The group tree for a set of nodes. Empty groups are never made. */
export function buildGroupTree(
  nodes: GraphNode[],
  { segments = [], customRanges = [], dnsNames, placements, userGroups = [], names = {}, notes = {} }: Options = {},
): GroupNode[] {
  let tops = automaticTree(nodes, { segments, customRanges, dnsNames });
  if (userGroups.length) addUserGroups(tops, userGroups);
  if (placements && Object.keys(placements).length) tops = applyPlacements(tops, placements);
  if (Object.keys(names).length || Object.keys(notes).length) nameAndNote(tops, names, notes);
  return tops;
}

/** Every group, by id, at any depth. */
export function allGroups(tops: GroupNode[]): Map<string, GroupNode> {
  const out = new Map<string, GroupNode>();
  const walk = (g: GroupNode) => {
    out.set(g.id, g);
    g.children.forEach(walk);
  };
  tops.forEach(walk);
  return out;
}

/** Puts each of the analyst's groups inside its parent, when the parent is on the map and holds groups, not devices. */
function addUserGroups(tops: GroupNode[], userGroups: { id: string; name: string; parentId: string }[]): void {
  const groups = allGroups(tops);
  for (const u of userGroups) {
    const parent = groups.get(u.parentId);
    if (!parent || parent.children.length === 0 || groups.has(u.id)) continue;
    const g: GroupNode = { id: u.id, kind: 'user', label: u.name, level: parent.level + 1, children: [], nodeIds: [], tone: parent.tone };
    parent.children.push(g);
    groups.set(g.id, g);
  }
}

function nameAndNote(tops: GroupNode[], names: Record<string, string>, notes: Record<string, string>): void {
  allGroups(tops).forEach(g => {
    const name = names[g.id]?.trim();
    if (name && name !== g.label) {
      g.autoLabel = g.label;
      g.label = name;
    }
    const note = notes[g.id]?.trim();
    if (note) g.note = note;
  });
}

/** Every innermost group (the ones that hold devices), by id. */
export function leafGroups(tops: GroupNode[]): Map<string, GroupNode> {
  const out = new Map<string, GroupNode>();
  const walk = (g: GroupNode) => (g.children.length ? g.children.forEach(walk) : out.set(g.id, g));
  tops.forEach(walk);
  return out;
}

/**
 * Moves each placed device into the group it was put in. A placement whose device or group is no
 * longer on the map (filtered away, regrouped after re-analysis) is skipped, so the device stays in
 * its automatic group. Groups a move empties are dropped.
 */
export function applyPlacements(tops: GroupNode[], placements: Record<string, string>): GroupNode[] {
  const leaves = leafGroups(tops);
  const home = new Map<string, GroupNode>();
  leaves.forEach(g => g.nodeIds.forEach(id => home.set(id, g)));
  for (const [nodeId, groupId] of Object.entries(placements)) {
    const from = home.get(nodeId);
    const to = leaves.get(groupId);
    if (!from || !to || from === to) continue;
    from.nodeIds = from.nodeIds.filter(id => id !== nodeId);
    to.nodeIds = [...to.nodeIds, nodeId];
    to.movedIds = [...(to.movedIds ?? []), nodeId];
    home.set(nodeId, to);
  }
  const prune = (gs: GroupNode[]): GroupNode[] =>
    gs
      .map(g => ({ ...g, children: prune(g.children) }))
      .filter(g => g.nodeIds.length > 0 || g.children.length > 0 || g.kind === 'user');
  return prune(tops);
}

function automaticTree(
  nodes: GraphNode[],
  { segments = [], customRanges = [], dnsNames }: Options = {},
): GroupNode[] {
  const local: GraphNode[] = [];
  const internet: GraphNode[] = [];
  const special: GraphNode[] = [];
  for (const n of nodes) {
    const ip = addressOf(n.id);
    if (n.data.isL2 || isPrivateIp(ip, customRanges)) local.push(n);
    else if (isSpecial(ip)) special.push(n);
    else internet.push(n);
  }

  const tops: GroupNode[] = [];

  if (local.length) {
    const bySeg = bucket(local, n => segmentFor(n, segments)?.key ?? '');
    const networks: GroupNode[] = [];
    for (const [segKey, members] of bySeg) {
      const seg = segments.find(s => s.key === segKey);
      const subnets = bucket(members, n => (n.data.isL2 ? 'No IP address' : subnetOf(addressOf(n.id))));
      const subnetGroups: GroupNode[] = [];
      for (const [subnet, inSubnet] of subnets) {
        const types = bucket(inSubnet, familyOf);
        const typeGroups: GroupNode[] = [...types].map(([t, ms]) => ({
          id: `type:${segKey}:${subnet}:${t}`,
          kind: 'type' as const,
          label: t,
          level: 4,
          children: [],
          nodeIds: ms.map(m => m.id),
        }));
        subnetGroups.push({
          id: `subnet:${segKey}:${subnet}`,
          kind: 'subnet',
          label: subnet,
          level: 3,
          children: typeGroups.sort(byLabel),
          nodeIds: [],
        });
      }
      networks.push({
        id: `network:${segKey || 'other'}`,
        kind: 'network',
        label: seg ? seg.label : segments.length ? 'Other local addresses' : 'Local network',
        detail: seg ? segmentDetail(seg) : undefined,
        level: 2,
        children: subnetGroups.sort(byLabel),
        nodeIds: [],
      });
    }
    // Real networks first, the catch-all last; each network its own colour.
    networks.sort((a, b) => Number(a.id === 'network:other') - Number(b.id === 'network:other') || byLabel(a, b));
    networks.forEach((g, i) => (g.tone = i));
    tops.push({ id: 'local', kind: 'local', label: 'Your networks', level: 1, children: networks, nodeIds: [] });
  }

  if (internet.length) {
    const byDomain = bucket(internet, n => {
      const name = n.data.hostname ?? dnsNames?.get(addressOf(n.id));
      return name ? domainOf(name) : '';
    });
    const domains: GroupNode[] = [...byDomain].map(([d, ms]) => ({
      id: `domain:${d || 'none'}`,
      kind: 'domain' as const,
      label: d || 'No hostname',
      level: 2,
      children: [],
      nodeIds: ms.map(m => m.id),
    }));
    domains.sort((a, b) => Number(a.label === 'No hostname') - Number(b.label === 'No hostname') || byLabel(a, b));
    tops.push({ id: 'internet', kind: 'internet', label: 'Internet', level: 1, children: domains, nodeIds: [] });
  }

  if (special.length) {
    tops.push({
      id: 'special',
      kind: 'special',
      label: 'Broadcast and multicast',
      level: 1,
      children: [],
      nodeIds: special.map(n => n.id),
    });
  }

  return tops;
}

// ── Layout ───────────────────────────────────────────────────────────────────────────────────

/** A device's cell: wide, as node labels run several lines of text. Labels are fitted to it. */
export const CELL_W = 240;
export const CELL_H = 170;
const PAD = 20;
/** Where a node sits in its cell, from the top: room above for the node, below for its label. */
export const NODE_TOP = 34;
/** Room for a box's name on one line, by level (layout units). */
const minWidthFor = (g: GroupNode) => (g.level === 1 ? 600 : g.level === 2 ? 360 : 0);
const GAP = 28;
const TOP_GAP = 120;
const headerFor = (level: number) => (level === 1 ? 60 : level === 2 ? 68 : 40);

interface Sized {
  group: GroupNode;
  w: number;
  h: number;
  /** Child offsets inside this box, relative to its top-left. */
  place: { child: Sized; x: number; y: number }[];
  /** Device offsets (innermost groups). */
  cells: { id: string; x: number; y: number }[];
}

/** Shelf packing: children left to right, wrapping at a width that keeps the result roughly square. */
function pack(children: { w: number; h: number }[], gap: number): { xs: number[]; ys: number[]; w: number; h: number } {
  const area = children.reduce((s, c) => s + (c.w + gap) * (c.h + gap), 0);
  const widest = Math.max(...children.map(c => c.w));
  const target = Math.max(widest, Math.sqrt(area) * 1.4);
  const xs: number[] = [];
  const ys: number[] = [];
  let x = 0;
  let y = 0;
  let rowH = 0;
  let w = 0;
  for (const c of children) {
    if (x > 0 && x + c.w > target) {
      x = 0;
      y += rowH + gap;
      rowH = 0;
    }
    xs.push(x);
    ys.push(y);
    x += c.w + gap;
    rowH = Math.max(rowH, c.h);
    w = Math.max(w, x - gap);
  }
  return { xs, ys, w, h: y + rowH };
}

/** A group's header band: room for its name, and its note when it has one. */
const headerOf = (g: GroupNode) => headerFor(g.level) + (g.note ? 22 : 0);
/** An empty group of the analyst's still needs room to drop devices into. */
const EMPTY_H = 90;

function size(group: GroupNode): Sized {
  const header = headerOf(group);
  if (group.children.length === 0) {
    const n = group.nodeIds.length;
    if (n === 0) {
      return { group, w: Math.max(CELL_W + PAD * 2, minWidthFor(group), 280), h: header + EMPTY_H, place: [], cells: [] };
    }
    const cols = Math.max(1, Math.ceil(Math.sqrt(n * 1.5)));
    const rows = Math.ceil(n / cols);
    // A node's label hangs below it, so the node sits near the top of its cell.
    const w = Math.max(cols * CELL_W + PAD * 2, minWidthFor(group));
    const offset = (w - cols * CELL_W) / 2;
    const cells = group.nodeIds.map((id, i) => ({
      id,
      x: offset + (i % cols) * CELL_W + CELL_W / 2,
      y: header + Math.floor(i / cols) * CELL_H + NODE_TOP,
    }));
    return { group, w, h: header + rows * CELL_H + PAD, place: [], cells };
  }
  // Biggest first, so the packing fills well; ties keep the tree's order.
  const kids = group.children.map(size);
  const order = kids.map((k, i) => ({ k, i })).sort((a, b) => b.k.w * b.k.h - a.k.w * a.k.h || a.i - b.i);
  const p = pack(order.map(o => o.k), GAP);
  const place = order.map((o, i) => ({ child: o.k, x: PAD + p.xs[i], y: header + p.ys[i] }));
  // Keep the children in their tree order for drawing.
  place.sort((a, b) => kids.indexOf(a.child) - kids.indexOf(b.child));
  return { group, w: Math.max(p.w + PAD * 2, minWidthFor(group)), h: header + p.h + PAD, place, cells: [] };
}

function memberIdsOf(g: GroupNode): string[] {
  return [...g.nodeIds, ...g.children.flatMap(memberIdsOf)];
}

/** Places every device and box. Units are arbitrary (the graph frames them); y points down. */
export function layoutGroups(tops: GroupNode[]): GroupedLayout {
  const positions = new Map<string, { x: number; y: number }>();
  const boxes: GroupBox[] = [];
  if (tops.length === 0) return { positions, boxes, headerFor };

  const sized = tops.map(size);
  const p = pack(sized, TOP_GAP);

  const emit = (s: Sized, x: number, y: number, tone?: number) => {
    const t = s.group.tone ?? tone;
    const memberIds = memberIdsOf(s.group);
    boxes.push({
      id: s.group.id,
      kind: s.group.kind,
      label: s.group.label,
      detail: s.group.detail,
      level: s.group.level,
      tone: t,
      count: memberIds.length,
      leaf: s.group.children.length === 0,
      moved: s.group.movedIds?.length ?? 0,
      note: s.group.note,
      header: headerOf(s.group),
      memberIds,
      x,
      y,
      w: s.w,
      h: s.h,
    });
    for (const c of s.cells) positions.set(c.id, { x: x + c.x, y: y + c.y });
    for (const c of s.place) emit(c.child, x + c.x, y + c.y, t);
  };
  sized.forEach((s, i) => emit(s, p.xs[i], p.ys[i]));
  return { positions, boxes, headerFor };
}
