import { ipInCidr, isLinkLocal, parseIp } from '@/utils/ipClassification';
import type { NetworkSegment } from './networkSegmentService';

/** A network's ranges: its IPv4 range, then its IPv6 prefixes (#1357). */
export function segmentRanges(s: NetworkSegment): string[] {
  return [...(s.cidr ? [s.cidr] : []), ...(s.prefixes ?? [])];
}

/** Whether one of the network's ranges holds the address. */
export function segmentHolds(s: NetworkSegment, ip: string): boolean {
  return segmentRanges(s).some(r => ipInCidr(ip, r));
}

/**
 * Whether the address could be on this network: a range of its family holds it, or the network has
 * no range of that family to say otherwise. An IPv6 link-local address is on every link, so it never
 * rules a network out.
 */
export function segmentAdmits(s: NetworkSegment, ip: string): boolean {
  const bytes = parseIp(ip);
  if (!bytes || isLinkLocal(ip)) return true;
  const same = segmentRanges(s).filter(r => parseIp(r.split('/')[0])?.length === bytes.length);
  return same.length === 0 || same.some(r => ipInCidr(ip, r));
}
