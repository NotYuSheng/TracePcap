import type { HostnameSource } from '@/types';
import { SourceBadge, type SourceInfo } from '@components/common/SourceBadge/SourceBadge';

const SOURCE_INFO: Record<HostnameSource, SourceInfo> = {
  dhcp: {
    label: 'DHCP',
    tooltip: 'Hostname advertised by the host in a DHCP request (option 12).',
    color: '#0072c6',
  },
  mdns: {
    label: 'mDNS',
    tooltip: 'Hostname announced via multicast DNS (e.g. a *.local Bonjour/Avahi name).',
    color: '#5c2d91',
  },
  nbns: {
    label: 'NBNS',
    tooltip: 'NetBIOS name observed from a NetBIOS Name Service registration or response.',
    color: '#b35900',
  },
  reverse_dns: {
    label: 'rDNS',
    tooltip: 'Name resolved from a reverse DNS (PTR) lookup of the IP address.',
    color: '#107c10',
  },
  manual: {
    label: 'Manual',
    tooltip: 'Hostname set manually by an analyst.',
    color: '#6c757d',
  },
};

interface HostnameSourceBadgeProps {
  source?: HostnameSource | string | null;
}

/** Small coloured chip showing how a host's name was discovered (DHCP, mDNS, NBNS, rDNS). */
export const HostnameSourceBadge = ({ source }: HostnameSourceBadgeProps) => (
  <SourceBadge source={source} info={SOURCE_INFO} />
);
