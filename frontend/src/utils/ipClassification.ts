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
  return /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|f[cd][0-9a-f]{2}:|fe[89ab][0-9a-f]:|::1$)/i.test(ip);
}

/** IPv4 dotted-quad → uint32. IPv4 only; callers guard IPv6 before calling. */
export function ipToInt(ip: string): number {
  const parts = ip.split('.').map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

/** Whether an IPv4 address falls inside an IPv4 CIDR. IPv6 on either side never matches. */
export function ipInCidr(ip: string, cidr: string): boolean {
  // ipToInt is IPv4-only; a colon means IPv6, which would otherwise both parse to 0 and spuriously
  // match. Bail so IPv6 never matches an IPv4 CIDR (or vice versa).
  if (ip.includes(':') || cidr.includes(':')) return false;
  try {
    const [base, bits] = cidr.split('/');
    const mask = bits ? (0xffffffff << (32 - parseInt(bits))) >>> 0 : 0xffffffff;
    return (ipToInt(ip) & mask) === (ipToInt(base) & mask);
  } catch {
    return false;
  }
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
