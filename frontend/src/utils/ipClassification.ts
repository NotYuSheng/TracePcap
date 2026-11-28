import type { CustomPrivateRange } from '@/features/cluster/types/customPrivateRange.types';

/**
 * Single source of truth for "is this address internal?" — previously copied (and already drifting)
 * across ConversationDetail, IpDriftPanel and HostIdentitySection.
 *
 * Two layers, matching how the app classifies elsewhere:
 *   - {@link isRfc1918} — the plain heuristic (RFC 1918 / loopback / link-local / IPv6 ULA + loopback).
 *   - {@link isPrivateIp} — the heuristic, but a user's custom range override wins in either direction.
 */

/**
 * RFC 1918 / loopback / link-local / IPv6 ULA (fc00::/7) + link-local (fe80::/10) + loopback (::1).
 *
 * Kept in step with the backend's IpLocality (#733 finding 3). The link-local alternative was
 * `fe80:`, which is one hextet of a /10 — so feb0::1 read as public here and internal on the
 * server, and the same host was classified differently depending on which side answered.
 */
export function isRfc1918(ip: string): boolean {
  if (!ip) return false; // callers pass node data, which can lack an address
  // An IPv4-mapped address (::ffff:10.0.0.1) is its IPv4 address, as parseIp reads it (#1357).
  if (ip.includes(':')) {
    const b = parseIp(ip);
    if (b && b.length === 4) ip = formatIp(b);
  }
  return /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|f[cd][0-9a-f]{2}:|fe[89ab][0-9a-f]:|::1$)/i.test(ip);
}

/**
 * The bytes of an address literal: 4 for IPv4, 16 for IPv6 (compressed or not, with an IPv4 tail),
 * or null for anything else (a MAC, a name, a CIDR). A scope id (`fe80::1%eth0`) is dropped, and an
 * IPv4-mapped address (`::ffff:10.0.0.1`) reads as its IPv4 address. The backend's
 * `Cidr.addressBytes`.
 */
export function parseIp(ip: string | null | undefined): number[] | null {
  if (!ip) return null;
  let a = ip.trim();
  const zone = a.indexOf('%');
  if (zone >= 0) a = a.slice(0, zone);
  if (!a.includes(':')) return parseV4(a);
  if (!/^[0-9a-f:.]+$/i.test(a)) return null;
  const halves = a.split('::');
  if (halves.length > 2) return null;
  // An IPv4 tail is allowed only as the last group of the whole address.
  const groups = (part: string, last: boolean): number[] | null => {
    if (part === '') return [];
    const out: number[] = [];
    const parts = part.split(':');
    for (let i = 0; i < parts.length; i++) {
      const p = parts[i];
      if (last && i === parts.length - 1 && p.includes('.')) {
        const v4 = parseV4(p);
        if (!v4) return null;
        out.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
      } else if (/^[0-9a-f]{1,4}$/i.test(p)) {
        out.push(parseInt(p, 16));
      } else {
        return null;
      }
    }
    return out;
  };
  const head = groups(halves[0], halves.length === 1);
  const tail = halves.length === 2 ? groups(halves[1], true) : [];
  if (!head || !tail) return null;
  if (halves.length === 1 ? head.length !== 8 : head.length + tail.length > 7) return null;
  const all = [...head, ...new Array(8 - head.length - tail.length).fill(0), ...tail];
  const bytes = all.flatMap(g => [g >> 8, g & 0xff]);
  const mapped = bytes.slice(0, 10).every(b => b === 0) && bytes[10] === 0xff && bytes[11] === 0xff;
  return mapped ? bytes.slice(12) : bytes;
}

function parseV4(a: string): number[] | null {
  const parts = a.split('.');
  if (parts.length !== 4 || parts.some(p => !/^\d{1,3}$/.test(p) || Number(p) > 255)) return null;
  return parts.map(Number);
}

/** `10.0.0.1`, or IPv6 in RFC 5952 form (`fd00::1`). The backend's `Cidr.formatAddress`. */
export function formatIp(bytes: number[]): string {
  if (bytes.length === 4) return bytes.join('.');
  // RFC 5952 §5: an IPv4-mapped address keeps its dotted tail. The backend's Cidr.formatAddress.
  if (bytes.slice(0, 10).every(b => b === 0) && bytes[10] === 0xff && bytes[11] === 0xff) {
    return `::ffff:${bytes.slice(12).join('.')}`;
  }
  const g: number[] = [];
  for (let i = 0; i < 16; i += 2) g.push((bytes[i] << 8) | bytes[i + 1]);
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (g[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && g[j] === 0) j++;
    if (j - i > bestLen) { bestStart = i; bestLen = j - i; }
    i = j;
  }
  const hex = (xs: number[]) => xs.map(x => x.toString(16)).join(':');
  if (bestLen < 2) return hex(g);
  return `${hex(g.slice(0, bestStart))}::${hex(g.slice(bestStart + bestLen))}`;
}

function mask(bytes: number[], prefix: number): number[] {
  return bytes.map((b, i) => b & (0xff << (8 - Math.max(0, Math.min(8, prefix - i * 8)))) & 0xff);
}

function parseCidrBlock(cidr: string): { net: number[]; prefix: number } | null {
  const [base, bits, extra] = cidr.trim().split('/');
  if (extra !== undefined) return null;
  const net = parseIp(base);
  if (!net) return null;
  const max = net.length * 8;
  if (bits === undefined) return { net, prefix: max };
  if (!/^\d{1,3}$/.test(bits.trim()) || Number(bits) > max) return null;
  return { net: mask(net, Number(bits)), prefix: Number(bits) };
}

/**
 * Whether an address falls inside a CIDR, IPv4 or IPv6. One family is never inside the other; a
 * bare address is a single host. The backend's `CidrBlock.contains`.
 */
export function ipInCidr(ip: string, cidr: string): boolean {
  const addr = parseIp(ip);
  const block = cidr ? parseCidrBlock(cidr) : null;
  if (!addr || !block || addr.length !== block.net.length) return false;
  const m = mask(addr, block.prefix);
  return m.every((b, i) => b === block.net[i]);
}

/** The network an address is on at a prefix: `10.1.2.0/24`, `2001:db8:1:2::/64`. Null if not an address. */
export function networkOf(ip: string, prefix: number): string | null {
  const addr = parseIp(ip);
  if (!addr) return null;
  const p = Math.min(prefix, addr.length * 8);
  return `${formatIp(mask(addr, p))}/${p}`;
}

/** Sort order for addresses: IPv4 by value, then IPv6 by value, then anything else as text. */
export function compareIps(a: string, b: string): number {
  const x = parseIp(a);
  const y = parseIp(b);
  if (!x || !y) return x ? -1 : y ? 1 : a.localeCompare(b);
  if (x.length !== y.length) return x.length - y.length;
  for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return x[i] - y[i];
  return 0;
}

/**
 * Whether an address is internal. A user's custom range override wins over the RFC 1918 heuristic in
 * either direction — the first matching range takes precedence (ranges arrive most-recent-first).
 * Omit {@code customRanges} (or pass an empty list) for callers with no override context, which then
 * get the plain heuristic.
 */
export function isPrivateIp(ip: string, customRanges: CustomPrivateRange[] = []): boolean {
  const match = customRanges.find(r => ipInCidr(ip, r.cidr));
  if (match) return match.classification !== 'PUBLIC';
  return isRfc1918(ip);
}

/** IPv6 link-local (fe80::/10): on every link, so the same address on two links is two machines. */
export function isLinkLocal(ip: string | null | undefined): boolean {
  const b = parseIp(ip);
  return b != null && b.length === 16 && b[0] === 0xfe && (b[1] & 0xc0) === 0x80;
}

/**
 * The unspecified address, `0.0.0.0` or `::`: what a client sends from before it has an address (a
 * DHCP request). The backend's `IpLocality.isUnspecified`.
 */
export function isUnspecified(ip: string | null | undefined): boolean {
  if (!ip) return false;
  const a = ip.trim();
  return a === '0.0.0.0' || a === '::';
}

/**
 * Whether one machine can hold the address. False for the unspecified address, IPv4 broadcast,
 * multicast and reserved space (224.0.0.0 and up), IPv6 multicast (`ff00::/8`) and the broadcast
 * MAC. Anything it can't parse counts as a host. The backend's `IpLocality.isHostAddress`.
 */
export function isHostAddress(ip: string | null | undefined): boolean {
  if (!ip) return false;
  const a = ip.trim().toLowerCase();
  if (!a || a === 'ff:ff:ff:ff:ff:ff' || isUnspecified(a)) return false;
  if (!a.includes(':')) {
    const parts = a.split('.');
    // Unparseable (not four octets of 0–255) counts as a host, as the backend's toLong does.
    if (parts.length !== 4 || parts.some(p => !/^\d{1,3}$/.test(p) || Number(p) > 255)) return true;
    return Number(parts[0]) < 224;
  }
  const first = a.slice(0, a.indexOf(':'));
  if (/^[0-9a-f]{1,4}$/.test(first)) return parseInt(first, 16) < 0xff00;
  return true;
}
