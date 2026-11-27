import type { ChangeEvent } from '@/features/monitor/types/monitor.types';

/** Human label for a security-drift signalKind payload value. */
function securityKindLabel(kind: unknown): string {
  switch (kind) {
    case 'ids':       return 'IDS alert';
    case 'signature': return 'Custom signature';
    case 'risk':      return 'Flow risk';
    case 'fileType':  return 'File type';
    default:          return 'Security signal';
  }
}

export function describeEvent(event: ChangeEvent): string {
  const nv = event.newValue ?? {};
  const ov = event.oldValue ?? {};

  switch (event.changeType) {
    case 'MAC_ADDED': {
      const parts = [nv['manufacturer'], nv['deviceType']].filter(Boolean);
      const parens = parts.length ? ` (${parts.join(', ')})` : '';
      return `New device: ${event.entityKey}${parens}${nv['ip'] ? ` at ${nv['ip']}` : ''}`;
    }
    case 'IP_MAC_DRIFT':
      if (ov['mac'] && nv['mac'] && ov['mac'] !== nv['mac']) {
        // IP→MAC change: same IP, different MAC (possible ARP spoofing)
        return `Potential ARP spoof: ${event.entityKey} — MAC changed from ${ov['mac']} to ${nv['mac']}`;
      }
      // MAC→IP change: same MAC, different IP (DHCP reassignment)
      return `IP reassignment: ${event.entityKey} — IP changed from ${ov['ip'] ?? '?'} to ${nv['ip'] ?? '?'}`;
    case 'ASN_CHANGE':
      return `New ISP/ASN seen: ${nv['asn']}${nv['org'] ? ` — ${nv['org']}` : ''}${nv['country'] ? ` (${nv['country']})` : ''}`;
    case 'GATEWAY_CHANGE': {
      const fmtGw = (ip: unknown, org: unknown) => `${ip ?? '?'}${org ? ` (${org})` : ''}`;
      return `Gateway changed: ${fmtGw(ov['ip'], ov['org'])} → ${fmtGw(nv['ip'], nv['org'])}`;
    }
    case 'APP_ADDED':
      return `New application: ${event.entityKey}`;
    case 'PROTOCOL_ADDED':
      return `New protocol: ${event.entityKey}`;
    case 'VPN_DRIFT':
      if (nv['riskType']) return `VPN detected: ${nv['riskType']}`;
      return `VPN signal gone: ${ov['riskType'] ?? event.entityKey}`;
    case 'SECURITY_ALERT_ADDED':
      return `${securityKindLabel(nv['signalKind'])} appeared: ${event.entityKey}`;
    case 'SECURITY_ALERT_REMOVED':
      return `${securityKindLabel(ov['signalKind'])} cleared: ${event.entityKey}`;
    case 'BASELINE_MISSING': {
      const what = nv['entryType'] === 'GATEWAY' ? 'gateway' : 'device';
      return `Baselined ${what} not seen: ${event.entityKey}${nv['expected'] ? ` (expected at ${nv['expected']})` : ''}`;
    }
    case 'BASELINE_MISMATCH':
      return `Baseline mismatch: ${event.entityKey} — declared ${nv['expected'] ?? '?'}, observed ${nv['observed'] ?? '?'}`;
    case 'LABEL_STALE': {
      const changes = Array.isArray(nv['changes']) ? (nv['changes'] as string[]).join(', ') : '';
      const label = nv['roleLabel'] ? ` (${nv['roleLabel']})` : '';
      return `Label may be stale: ${event.entityKey}${label}${changes ? ` — ${changes}` : ''}`;
    }
    default:
      return event.entityKey;
  }
}

/** What kind of change, in a few words, for summaries ("New device", "Gateway changed"). */
export function changeKind(event: ChangeEvent): string {
  switch (event.changeType) {
    case 'MAC_ADDED': return 'new device';
    case 'IP_MAC_DRIFT': return 'address change';
    case 'ASN_CHANGE': return 'new ISP';
    case 'GATEWAY_CHANGE': return 'gateway change';
    case 'APP_ADDED': return 'new app';
    case 'PROTOCOL_ADDED': return 'new protocol';
    case 'VPN_DRIFT': return 'VPN change';
    case 'SECURITY_ALERT_ADDED': return 'security alert';
    case 'SECURITY_ALERT_REMOVED': return 'alert cleared';
    case 'BASELINE_MISSING': return 'missing baselined item';
    case 'BASELINE_MISMATCH': return 'baseline mismatch';
    case 'LABEL_STALE': return 'stale label';
    default: return 'change';
  }
}

const PLURAL: Record<string, string> = {
  'alert cleared': 'alerts cleared',
  'missing baselined item': 'missing baselined items',
  'new ISP': 'new ISPs',
};
/** The change kind's noun for a count: "new device" / "new devices". */
const kindNoun = (kind: string, n: number) => (n === 1 ? kind : (PLURAL[kind] ?? `${kind}s`));
/** "164 new devices · 7 new apps · 2 gateway changes", biggest first. */
export function changeSummary(events: ChangeEvent[]): string {
  const counts = new Map<string, number>();
  for (const e of events) counts.set(changeKind(e), (counts.get(changeKind(e)) ?? 0) + 1);
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([kind, n]) => `${n.toLocaleString()} ${kindNoun(kind, n)}`)
    .join(' · ');
}

