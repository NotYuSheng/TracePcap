import type { HostnameSource } from '@/types';

const SOURCE_INFO: Record<HostnameSource, { label: string; tooltip: string; color: string }> = {
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
export const HostnameSourceBadge = ({ source }: HostnameSourceBadgeProps) => {
  if (!source) return null;
  const info = SOURCE_INFO[source as HostnameSource];
  if (!info) return null;
  return (
    <span
      title={info.tooltip}
      style={{
        fontSize: 9,
        fontWeight: 600,
        color: '#fff',
        background: info.color,
        borderRadius: 3,
        padding: '1px 4px',
        cursor: 'help',
        whiteSpace: 'nowrap',
        flexShrink: 0,
      }}
    >
      {info.label}
    </span>
  );
};
