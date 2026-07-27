import { Spinner } from '@components/common/Spinner/Spinner';
import { useState, useEffect, type CSSProperties } from 'react';
import { Button } from '@govtechsg/sgds-react';
import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import type {
  NetworkSnapshot,
  AbsentEntity,
} from '@/features/monitor/types/monitor.types';
import { EntityDetailModal } from '@components/common/EntityDetailModal';
import { Pagination } from '@components/common/Pagination/Pagination';
import type { EntityType } from '@/features/notes/services/entityNotesService';

function stringHue(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) & 0xffffffff;
  return Math.abs(h) % 360;
}

function hashBadgeStyle(s: string): CSSProperties {
  const hue = stringHue(s);
  return {
    '--badge-hue': hue,
    background: `hsl(${hue}, 40%, 88%)`,
    color: `hsl(${hue}, 50%, 28%)`,
    border: `1px solid hsl(${hue}, 35%, 72%)`,
  } as CSSProperties;
}

interface ProtocolDriftPanelProps {
  snapshots: NetworkSnapshot[];
}

type EntityGroup = {
  active: string[];
  absent: AbsentEntity[];
};

const BADGE_GROUP_PAGE_SIZE = 50;

function BadgeGroup({
  items,
  absentItems,
  onAbsentClick,
  onActiveClick,
}: {
  items: string[];
  absentItems: AbsentEntity[];
  onAbsentClick: (e: AbsentEntity) => void;
  onActiveClick: (name: string) => void;
}) {
  const [page, setPage] = useState(1);
  // Reset to page 1 when the filtered set changes (e.g. the parent's search box) so a
  // cleared/narrowed search can't leave us on a now-out-of-range page.
  useEffect(() => { setPage(1); }, [items.length, absentItems.length]);
  if (items.length === 0 && absentItems.length === 0) return null;

  // Paginate active-then-absent badges so a large group can't render hundreds at once.
  const combined: Array<{ active: true; name: string } | { active: false; entity: AbsentEntity }> = [
    ...items.map(name => ({ active: true as const, name })),
    ...absentItems.map(entity => ({ active: false as const, entity })),
  ];
  const totalPages = Math.ceil(combined.length / BADGE_GROUP_PAGE_SIZE);
  const currentPage = Math.min(page, Math.max(1, totalPages));
  const pageItems = combined.slice((currentPage - 1) * BADGE_GROUP_PAGE_SIZE, currentPage * BADGE_GROUP_PAGE_SIZE);

  return (
    <>
      <div className="d-flex flex-wrap gap-2">
        {pageItems.map(item => item.active ? (
          <Button
            key={item.name}
            type="button"
            variant="secondary"
            size="sm"
            className="border-0 py-0 px-1"
            style={{ fontSize: '0.75em', ...hashBadgeStyle(item.name) }}
            onClick={() => onActiveClick(item.name)}
            title="Click for details & notes"
          >
            {item.name}
          </Button>
        ) : (
          <Button
            key={item.entity.key}
            type="button"
            variant="secondary"
            size="sm"
            className="text-decoration-line-through border-0 py-0 px-1"
            style={{ fontSize: '0.75em', opacity: 0.5, ...hashBadgeStyle(item.entity.key) }}
            onClick={() => onAbsentClick(item.entity)}
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
          pageSize={BADGE_GROUP_PAGE_SIZE}
          onPageChange={setPage}
          showPageSizeSelector={false}
          compact
        />
      )}
    </>
  );
}

type SelectedEntity = { key: string; entityType: EntityType; fileId: string; isActive: boolean; lastSeenTime?: string | null; lastSeenFileName?: string | null } | null;

export const ProtocolDriftPanel = ({ snapshots }: ProtocolDriftPanelProps) => {
  const [selectedEntity, setSelectedEntity] = useState<SelectedEntity>(null);
  const [apps, setApps] = useState<EntityGroup>({ active: [], absent: [] });
  const [protocols, setProtocols] = useState<EntityGroup>({ active: [], absent: [] });
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');

  const sorted = [...snapshots].sort((a, b) => a.snapshotOrder - b.snapshotOrder);
  const latestSnap = sorted[sorted.length - 1];
  const latestFileId = latestSnap?.fileId ?? '';
  const latestStartTime = latestSnap?.startTime as unknown as string | null ?? null;

  useEffect(() => {
    if (sorted.length === 0) return;
    setLoading(true);
    Promise.all(
      sorted.map(snap =>
        // Distinct apps/protocols are computed server-side, so we no longer pull every conversation
        // row (which truncated at the backend's pageSize cap on busy snapshots).
        Promise.all([
          apiClient.get<string[]>(API_ENDPOINTS.DISTINCT_APPS(snap.fileId)).then(r => r.data),
          apiClient.get<string[]>(API_ENDPOINTS.DISTINCT_PROTOCOLS(snap.fileId)).then(r => r.data),
        ])
          .then(([apps, protos]) => ({
            snap,
            apps: new Set(apps),
            protos: new Set(protos),
          }))
          .catch(() => ({ snap, apps: new Set<string>(), protos: new Set<string>() }))
      )
    ).then(results => {
      const latestResult = results[results.length - 1];
      const latestApps = latestResult?.apps ?? new Set<string>();
      const latestProtos = latestResult?.protos ?? new Set<string>();

      // Build last-seen maps across all snapshots
      const appLastSeen = new Map<string, NetworkSnapshot>();
      const protoLastSeen = new Map<string, NetworkSnapshot>();
      for (const { snap, apps: a, protos: p } of results) {
        for (const app of a) appLastSeen.set(app, snap);
        for (const proto of p) protoLastSeen.set(proto, snap);
      }

      const buildGroup = (
        latestSet: Set<string>,
        lastSeen: Map<string, NetworkSnapshot>,
        type: 'APP' | 'PROTOCOL',
      ): EntityGroup => {
        const active = Array.from(latestSet);
        const absent: AbsentEntity[] = [];
        for (const [key, snap] of lastSeen.entries()) {
          if (!latestSet.has(key)) {
            absent.push({
              key,
              type,
              lastSeenFileName: snap.fileName,
              lastSeenStartTime: snap.startTime,
              lastSeenFileId: snap.fileId,
            });
          }
        }
        return { active, absent };
      };

      setApps(buildGroup(latestApps, appLastSeen, 'APP'));
      setProtocols(buildGroup(latestProtos, protoLastSeen, 'PROTOCOL'));
      setLoading(false);
    });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [snapshots.map(s => s.id).join(',')]);

  if (loading) {
    return <div className="text-muted small text-center py-3"><Spinner animation="border" size="sm" className="me-2" />Loading…</div>;
  }

  const hasData =
    apps.active.length + apps.absent.length + protocols.active.length + protocols.absent.length > 0;

  if (!hasData) {
    return (
      <div className="text-muted small text-center py-3">
        No protocol/app data yet. Add at least one snapshot.
      </div>
    );
  }

  const hasAbsent = apps.absent.length > 0 || protocols.absent.length > 0;

  const q = search.trim().toLowerCase();
  const filterItems = (items: string[]) => q ? items.filter(i => i.toLowerCase().includes(q)) : items;
  const filterAbsent = (ents: AbsentEntity[]) => q ? ents.filter(e => e.key.toLowerCase().includes(q)) : ents;

  return (
    <>
      {hasData && (
        <div className="mb-3">
          <input
            type="search"
            className="form-control form-control-sm"
            placeholder="Search applications & protocols…"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
      )}
      {(apps.active.length > 0 || apps.absent.length > 0) && (
        <div className="mb-3">
          <small className="text-muted fw-semibold d-block mb-2">Applications</small>
          <BadgeGroup
            items={filterItems(apps.active)}
            absentItems={filterAbsent(apps.absent)}
            onAbsentClick={e => setSelectedEntity({ key: e.key, entityType: 'APPLICATION', fileId: e.lastSeenFileId ?? latestFileId, isActive: false, lastSeenTime: e.lastSeenStartTime, lastSeenFileName: e.lastSeenFileName })}
            onActiveClick={name => setSelectedEntity({ key: name, entityType: 'APPLICATION', fileId: latestFileId, isActive: true, lastSeenTime: latestStartTime })}
          />
        </div>
      )}
      {(protocols.active.length > 0 || protocols.absent.length > 0) && (
        <div className="mb-3">
          <small className="text-muted fw-semibold d-block mb-2">Protocols</small>
          <BadgeGroup
            items={filterItems(protocols.active)}
            absentItems={filterAbsent(protocols.absent)}
            onAbsentClick={e => setSelectedEntity({ key: e.key, entityType: 'PROTOCOL', fileId: e.lastSeenFileId ?? latestFileId, isActive: false, lastSeenTime: e.lastSeenStartTime, lastSeenFileName: e.lastSeenFileName })}
            onActiveClick={name => setSelectedEntity({ key: name, entityType: 'PROTOCOL', fileId: latestFileId, isActive: true, lastSeenTime: latestStartTime })}
          />
        </div>
      )}
      {hasAbsent && (
        <small className="text-muted d-block mt-1">
          <i className="bi bi-info-circle me-1"></i>
          Greyed-out items are no longer seen. Click for details.
        </small>
      )}
      {selectedEntity && (
        <EntityDetailModal
          entityType={selectedEntity.entityType}
          entityKey={selectedEntity.key}
          displayName={selectedEntity.key}
          fileId={selectedEntity.fileId}
          isActive={selectedEntity.isActive}
          lastSeenTime={selectedEntity.lastSeenTime}
          lastSeenFileName={selectedEntity.lastSeenFileName}
          onClose={() => setSelectedEntity(null)}
        />
      )}
    </>
  );
};
