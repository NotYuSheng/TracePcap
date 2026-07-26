import { Spinner } from '@components/common/Spinner/Spinner';
import { useState, useEffect, type CSSProperties } from 'react';
import { Button } from '@govtechsg/sgds-react';
import { apiClient } from '@/services/api/client';
import type { NetworkSnapshot, AbsentEntity } from '@/features/monitor/types/monitor.types';
import { EntityDetailModal } from '@components/common/EntityDetailModal';
import { Pagination } from '@components/common/Pagination/Pagination';

/** Deterministic hue (0–360) from any string. */
function stringHue(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) & 0xffffffff;
  return Math.abs(h) % 360;
}

/** Muted badge style derived from string — works in light and dark mode. */
function hashBadgeStyle(s: string): CSSProperties {
  const hue = stringHue(s);
  return {
    '--badge-hue': hue,
    background: `hsl(${hue}, 40%, 88%)`,
    color: `hsl(${hue}, 50%, 28%)`,
    border: `1px solid hsl(${hue}, 35%, 72%)`,
  } as CSSProperties;
}

interface DeviceDriftPanelProps {
  snapshots: NetworkSnapshot[];
}

interface HostClassification {
  mac: string | null;
  ip: string | null;
}

type SelectedMac =
  | { mac: string; fileId: string; isActive: boolean; lastSeenTime?: string | null }
  | null;

export const DeviceDriftPanel = ({ snapshots }: DeviceDriftPanelProps) => {
  const [selectedAbsent, setSelectedAbsent] = useState<AbsentEntity | null>(null);
  const [selectedMac, setSelectedMac] = useState<SelectedMac>(null);
  const [activeMacs, setActiveMacs] = useState<string[]>([]);
  const [absentMacs, setAbsentMacs] = useState<AbsentEntity[]>([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const BADGE_PAGE_SIZE = 50;

  const sorted = [...snapshots].sort((a, b) => a.snapshotOrder - b.snapshotOrder);
  const latestSnap = sorted[sorted.length - 1];
  const latestFileId = latestSnap?.fileId ?? '';
  const latestStartTime = (latestSnap?.startTime as unknown as string | null) ?? null;

  // Discover which MACs appear across the network's snapshots: those present in the latest
  // snapshot are "active", the rest are "absent" (kept with their last-seen snapshot). The
  // per-snapshot IP/device/role/conflict detail is rendered by EntityDetailModal on click.
  useEffect(() => {
    if (sorted.length === 0) return;
    setLoading(true);
    Promise.all(
      sorted.map(snap =>
        apiClient
          .get<HostClassification[]>(`/files/${snap.fileId}/host-classifications`)
          .then(r => ({ snap, macs: r.data.map(h => h.mac).filter((m): m is string => !!m) }))
          .catch(() => ({ snap, macs: [] as string[] }))
      )
    ).then(results => {
      const latestMacs = new Set(results[results.length - 1]?.macs ?? []);
      const lastSeen = new Map<string, NetworkSnapshot>();
      for (const { snap, macs } of results) {
        for (const mac of macs) lastSeen.set(mac, snap);
      }

      const active = Array.from(latestMacs).sort();
      const absent: AbsentEntity[] = [];
      for (const [mac, snap] of lastSeen.entries()) {
        if (!latestMacs.has(mac)) {
          absent.push({
            key: mac,
            type: 'DEVICE',
            lastSeenFileName: snap.fileName,
            lastSeenStartTime: snap.startTime,
            lastSeenFileId: snap.fileId,
          });
        }
      }
      absent.sort((a, b) => a.key.localeCompare(b.key));

      setActiveMacs(active);
      setAbsentMacs(absent);
      setLoading(false);
    });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [snapshots.map(s => s.id).join(',')]);

  if (loading) {
    return <div className="text-muted small text-center py-3"><Spinner animation="border" size="sm" className="me-2" />Loading…</div>;
  }

  if (activeMacs.length + absentMacs.length === 0) {
    return <div className="text-muted small text-center py-3">No devices found. Add at least one snapshot.</div>;
  }

  const q = search.trim().toLowerCase();
  const visibleActive = q ? activeMacs.filter(mac => mac.toLowerCase().includes(q)) : activeMacs;
  const visibleAbsent = q ? absentMacs.filter(e => e.key.toLowerCase().includes(q)) : absentMacs;

  // One paginated stream over active-then-absent badges, so a large device set doesn't render
  // hundreds of badges at once. Clamp in render so the search shrinking the list can't strand us.
  const combined: Array<{ active: true; mac: string } | { active: false; entity: AbsentEntity }> = [
    ...visibleActive.map(mac => ({ active: true as const, mac })),
    ...visibleAbsent.map(entity => ({ active: false as const, entity })),
  ];
  const totalPages = Math.ceil(combined.length / BADGE_PAGE_SIZE);
  const currentPage = Math.min(page, Math.max(1, totalPages));
  const pageItems = combined.slice((currentPage - 1) * BADGE_PAGE_SIZE, currentPage * BADGE_PAGE_SIZE);

  return (
    <>
      <div className="mb-3">
        <input
          type="search"
          className="form-control form-control-sm"
          placeholder="Search MAC addresses…"
          value={search}
          onChange={e => { setSearch(e.target.value); setPage(1); }}
        />
      </div>
      <div className="d-flex flex-wrap gap-2">
        {pageItems.map(item => item.active ? (
          <Button
            key={item.mac}
            type="button"
            variant="secondary"
            size="sm"
            className="border-0 py-0 px-1"
            style={{ fontSize: '0.75em', ...hashBadgeStyle(item.mac) }}
            onClick={() => setSelectedMac({ mac: item.mac, fileId: latestFileId, isActive: true, lastSeenTime: latestStartTime })}
            title="View device history"
          >
            {item.mac}
          </Button>
        ) : (
          <Button
            key={item.entity.key}
            type="button"
            variant="secondary"
            size="sm"
            className="text-decoration-line-through border-0 py-0 px-1"
            style={{ fontSize: '0.75em', opacity: 0.5, ...hashBadgeStyle(item.entity.key) }}
            onClick={() => setSelectedAbsent(item.entity)}
            title={`Last seen in ${item.entity.lastSeenFileName}`}
          >
            {item.entity.key}
          </Button>
        ))}
      </div>
      {totalPages > 1 && (
        <Pagination
          currentPage={currentPage}
          totalPages={totalPages}
          totalItems={combined.length}
          pageSize={BADGE_PAGE_SIZE}
          onPageChange={setPage}
          showPageSizeSelector={false}
          compact
        />
      )}
      {absentMacs.length > 0 && (
        <small className="text-muted d-block mt-2">
          <i className="bi bi-info-circle me-1"></i>
          Greyed-out devices are no longer seen. Click any device for history.
        </small>
      )}

      {selectedAbsent && (
        <EntityDetailModal
          entityType="DEVICE"
          entityKey={selectedAbsent.key}
          displayName={selectedAbsent.key}
          fileId={selectedAbsent.lastSeenFileId ?? ''}
          isActive={false}
          lastSeenTime={selectedAbsent.lastSeenStartTime}
          lastSeenFileName={selectedAbsent.lastSeenFileName}
          snapshots={snapshots}
          onClose={() => setSelectedAbsent(null)}
        />
      )}
      {selectedMac && (
        <EntityDetailModal
          entityType="DEVICE"
          entityKey={selectedMac.mac}
          displayName={selectedMac.mac}
          fileId={selectedMac.fileId}
          isActive={selectedMac.isActive}
          lastSeenTime={selectedMac.lastSeenTime}
          snapshots={snapshots}
          onClose={() => setSelectedMac(null)}
        />
      )}
    </>
  );
};
