import { SnapshotSecurityTab } from '@/components/monitor/SnapshotSecurityTab/SnapshotSecurityTab';
import { useNetworkData } from '@/features/network/hooks/useNetworkData';

/** This capture's security signals (IDS alerts, risks, rule matches, file types) in this network. */
export function SnapshotSecurityPane({ networkId, fileId }: { networkId: string; fileId: string }) {
  const { edges, loading } = useNetworkData(fileId, undefined, undefined, networkId);
  return <SnapshotSecurityTab edges={edges} loading={loading} fileId={fileId} networkId={networkId} />;
}
