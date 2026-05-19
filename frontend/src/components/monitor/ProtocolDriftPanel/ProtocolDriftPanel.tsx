import { Spinner } from '@components/common/Spinner/Spinner';
import { useState, useEffect, type CSSProperties } from 'react';
import { Badge, Button } from '@govtechsg/sgds-react';
import { apiClient } from '@/services/api/client';
import type {
  NetworkSnapshot,
  AbsentEntity,
} from '@/features/monitor/types/monitor.types';
import { LastSeenModal } from '../LastSeenModal/LastSeenModal';

function stringHue(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) & 0xffffffff;
  return Math.abs(h) % 360;
}

function hashBadgeStyle(s: string): CSSProperties {
  const hue = stringHue(s);
  return {
    background: `hsl(${hue}, 40%, 88%)`,
    color: `hsl(${hue}, 50%, 28%)`,
    border: `1px solid hsl(${hue}, 35%, 72%)`,
  };
}

interface ProtocolDriftPanelProps {
  snapshots: NetworkSnapshot[];
}

type EntityGroup = {
  active: string[];
  absent: AbsentEntity[];
};

interface ConversationSummary {
  appName: string | null;
  tsharkProtocol: string | null;
}

interface ConversationsResponse {
  data: ConversationSummary[];
}

function BadgeGroup({
  items,
  absentItems,
  onAbsentClick,
}: {
  items: string[];
  absentItems: AbsentEntity[];
  onAbsentClick: (e: AbsentEntity) => void;
}) {
  if (items.length === 0 && absentItems.length === 0) return null;
  return (
    <div className="d-flex flex-wrap gap-2">
      {items.map(name => (
        <Badge key={name} style={hashBadgeStyle(name)}>
          {name}
        </Badge>
      ))}
      {absentItems.map(entity => (
        <Button
          key={entity.key}
          type="button"
          variant="secondary"
          size="sm"
          className="text-decoration-line-through border-0 py-0 px-1"
          style={{ fontSize: '0.75em', opacity: 0.5, ...hashBadgeStyle(entity.key) }}
          onClick={() => onAbsentClick(entity)}
          title={`Last seen in ${entity.lastSeenFileName}`}
        >
          {entity.key}
        </Button>
      ))}
    </div>
  );
}

export const ProtocolDriftPanel = ({ snapshots }: ProtocolDriftPanelProps) => {
  const [selectedAbsent, setSelectedAbsent] = useState<AbsentEntity | null>(null);
  const [apps, setApps] = useState<EntityGroup>({ active: [], absent: [] });
  const [protocols, setProtocols] = useState<EntityGroup>({ active: [], absent: [] });
  const [loading, setLoading] = useState(false);

  const sorted = [...snapshots].sort((a, b) => a.snapshotOrder - b.snapshotOrder);

  useEffect(() => {
    if (sorted.length === 0) return;
    setLoading(true);
    Promise.all(
      sorted.map(snap =>
        apiClient
          .get<ConversationsResponse>(`/conversations/${snap.fileId}?pageSize=10000`)
          .then(r => ({
            snap,
            apps: new Set(r.data.data.map(c => c.appName).filter(Boolean) as string[]),
            protos: new Set(r.data.data.map(c => c.tsharkProtocol).filter(Boolean) as string[]),
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

  return (
    <>
      {(apps.active.length > 0 || apps.absent.length > 0) && (
        <div className="mb-3">
          <small className="text-muted fw-semibold d-block mb-2">Applications</small>
          <BadgeGroup
            items={apps.active}
            absentItems={apps.absent}
            onAbsentClick={setSelectedAbsent}
          />
        </div>
      )}
      {(protocols.active.length > 0 || protocols.absent.length > 0) && (
        <div className="mb-3">
          <small className="text-muted fw-semibold d-block mb-2">Protocols</small>
          <BadgeGroup
            items={protocols.active}
            absentItems={protocols.absent}
            onAbsentClick={setSelectedAbsent}
          />
        </div>
      )}
      {hasAbsent && (
        <small className="text-muted d-block mt-1">
          <i className="bi bi-info-circle me-1"></i>
          Greyed-out items are no longer seen. Click for details.
        </small>
      )}
      <LastSeenModal
        show={selectedAbsent !== null}
        onHide={() => setSelectedAbsent(null)}
        entity={selectedAbsent}
      />
    </>
  );
};
