import type { ChangeEvent } from '@/features/monitor/types/monitor.types';
import type { NodeHighlight } from '@/components/network/NetworkGraph/NetworkGraph';
import { severityHex } from '@/utils/severityColors';

/**
 * The changes a capture brought, as highlights on its network map: which node each change lands on,
 * in the change's severity colour. Shared by the capture pop-up and the network page's maps.
 */
export function labelForChange(changeType: string, oldValue: Record<string, unknown> | null, newValue: Record<string, unknown> | null): string {
  switch (changeType) {
    case 'MAC_ADDED':      return 'New device';
    case 'IP_MAC_DRIFT':   return (oldValue?.['mac'] && newValue?.['mac'] && oldValue['mac'] !== newValue['mac']) ? 'Potential ARP spoof' : 'IP reassignment';
    case 'GATEWAY_CHANGE': return 'Gateway changed';
    case 'ASN_CHANGE':     return 'New ISP';
    case 'PROTOCOL_ADDED': return 'New protocol';
    case 'APP_ADDED':      return 'New app';
    case 'VPN_DRIFT':      return newValue?.['riskType'] ? 'VPN detected' : 'VPN stopped';
    case 'SECURITY_ALERT_ADDED':   return 'Security alert';
    case 'SECURITY_ALERT_REMOVED': return 'Security alert cleared';
    default:               return changeType;
  }
}

function severityRank(s: string): number {
  return s === 'CRITICAL' ? 3 : s === 'WARNING' ? 2 : 1;
}

export function buildHighlightMap(events: ChangeEvent[], toSnapshotId: string): Map<string, NodeHighlight> {
  const map = new Map<string, NodeHighlight>();
  for (const e of events.filter(ev => ev.toSnapshotId === toSnapshotId)) {
    const color = severityHex(e.severity);
    const label = labelForChange(e.changeType, e.oldValue, e.newValue);
    const addHl = (key: string, description?: string) => {
      const existing = map.get(key);
      if (!existing || severityRank(e.severity) > severityRank(existing.label)) {
        map.set(key, { color, label, description });
      }
    };
    switch (e.changeType) {
      case 'MAC_ADDED': {
        const ip = e.newValue?.['ip'] as string | undefined;
        addHl(e.entityKey, `New device appeared${ip ? ` at ${ip}` : ''}`);
        if (ip) addHl(ip, `New device with MAC ${e.entityKey}`);
        break;
      }
      case 'IP_MAC_DRIFT': {
        const oldMac = e.oldValue?.['mac'] as string | undefined;
        const newMac = e.newValue?.['mac'] as string | undefined;
        const oldIp  = e.oldValue?.['ip']  as string | undefined;
        const newIp  = e.newValue?.['ip']  as string | undefined;
        if (oldMac && newMac && oldMac !== newMac) {
          addHl(e.entityKey, `MAC changed from ${oldMac} to ${newMac}`);
          addHl(newMac, `Now claiming IP ${e.entityKey} (was ${oldMac})`);
        } else {
          addHl(e.entityKey, `IP changed from ${oldIp ?? '?'} to ${newIp ?? '?'}`);
          if (newIp) addHl(newIp, `MAC ${e.entityKey} moved here from ${oldIp ?? '?'}`);
        }
        break;
      }
      case 'GATEWAY_CHANGE': {
        const newIp = e.newValue?.['ip'] as string | undefined;
        const oldIp = e.oldValue?.['ip'] as string | undefined;
        if (newIp) addHl(newIp, `New gateway (was ${oldIp ?? '?'})`);
        if (oldIp) addHl(oldIp, `Previous gateway (replaced by ${newIp ?? '?'})`);
        break;
      }
      default: break;
    }
  }
  return map;
}
