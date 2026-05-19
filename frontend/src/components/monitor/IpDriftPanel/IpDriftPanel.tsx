import { Spinner } from '@components/common/Spinner/Spinner';
import { useState, useEffect, type CSSProperties } from 'react';
import { Badge } from '@govtechsg/sgds-react';
import { apiClient } from '@/services/api/client';
import type { NetworkSnapshot, AbsentEntity } from '@/features/monitor/types/monitor.types';
import { LastSeenModal } from '../LastSeenModal/LastSeenModal';

interface IpDriftPanelProps {
  snapshots: NetworkSnapshot[];
}

type EntityGroup = {
  active: string[];
  absent: AbsentEntity[];
};

interface ConversationSummary {
  srcIp: string;
  dstIp: string;
}

interface ConversationsResponse {
  data: ConversationSummary[];
}

function isPrivateIp(ip: string): boolean {
  return /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|f[cd][0-9a-f]{2}:|fe80:)/i.test(ip);
}

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

function IpBadgeGroup({
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
      {items.map(ip => (
        <Badge key={ip} style={hashBadgeStyle(ip)}>
          {ip}
        </Badge>
      ))}
      {absentItems.map(entity => (
        <Badge
          key={entity.key}
          as="button"
          type="button"
          className="text-decoration-line-through"
          style={{ cursor: 'pointer', opacity: 0.5, ...hashBadgeStyle(entity.key) }}
          onClick={() => onAbsentClick(entity)}
          title={`Last seen in ${entity.lastSeenFileName}`}
        >
          {entity.key}
        </Badge>
      ))}
    </div>
  );
}

export const IpDriftPanel = ({ snapshots }: IpDriftPanelProps) => {
  const [selectedAbsent, setSelectedAbsent] = useState<AbsentEntity | null>(null);
  const [privateIps, setPrivateIps] = useState<EntityGroup>({ active: [], absent: [] });
  const [publicIps, setPublicIps] = useState<EntityGroup>({ active: [], absent: [] });
  const [loading, setLoading] = useState(false);

  const sorted = [...snapshots].sort((a, b) => a.snapshotOrder - b.snapshotOrder);

  useEffect(() => {
    if (sorted.length === 0) return;
    setLoading(true);
    Promise.all(
      sorted.map(snap =>
        apiClient
          .get<ConversationsResponse>(`/conversations/${snap.fileId}?pageSize=10000`)
          .then(r => {
            const ips = new Set<string>();
            for (const c of r.data.data) {
              if (c.srcIp) ips.add(c.srcIp);
              if (c.dstIp) ips.add(c.dstIp);
            }
            return { snap, ips };
          })
          .catch(() => ({ snap, ips: new Set<string>() }))
      )
    ).then(results => {
      const latestIps = results[results.length - 1]?.ips ?? new Set<string>();
      const lastSeen = new Map<string, NetworkSnapshot>();
      for (const { snap, ips } of results) {
        for (const ip of ips) lastSeen.set(ip, snap);
      }

      const buildGroup = (filter: (ip: string) => boolean): EntityGroup => {
        const active = Array.from(latestIps).filter(filter).sort();
        const absent: AbsentEntity[] = [];
        for (const [ip, snap] of lastSeen.entries()) {
          if (!latestIps.has(ip) && filter(ip)) {
            absent.push({
              key: ip,
              type: 'IP',
              lastSeenFileName: snap.fileName,
              lastSeenStartTime: snap.startTime,
              lastSeenFileId: snap.fileId,
            });
          }
        }
        absent.sort((a, b) => a.key.localeCompare(b.key));
        return { active, absent };
      };

      setPrivateIps(buildGroup(isPrivateIp));
      setPublicIps(buildGroup(ip => !isPrivateIp(ip)));
      setLoading(false);
    });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [snapshots.map(s => s.id).join(',')]);

  if (loading) {
    return <div className="text-muted small text-center py-3"><Spinner animation="border" size="sm" className="me-2" />Loading…</div>;
  }

  const hasData =
    privateIps.active.length + privateIps.absent.length +
    publicIps.active.length + publicIps.absent.length > 0;

  if (!hasData) {
    return <div className="text-muted small text-center py-3">No IP data yet. Add at least one snapshot.</div>;
  }

  const hasAbsent = privateIps.absent.length > 0 || publicIps.absent.length > 0;

  return (
    <>
      {(privateIps.active.length > 0 || privateIps.absent.length > 0) && (
        <div className="mb-3">
          <small className="text-muted fw-semibold d-block mb-2">
            <i className="bi bi-house me-1"></i>Private
          </small>
          <IpBadgeGroup
            items={privateIps.active}
            absentItems={privateIps.absent}
            onAbsentClick={setSelectedAbsent}
          />
        </div>
      )}
      {(publicIps.active.length > 0 || publicIps.absent.length > 0) && (
        <div className="mb-3">
          <small className="text-muted fw-semibold d-block mb-2">
            <i className="bi bi-globe me-1"></i>Public
          </small>
          <IpBadgeGroup
            items={publicIps.active}
            absentItems={publicIps.absent}
            onAbsentClick={setSelectedAbsent}
          />
        </div>
      )}
      {hasAbsent && (
        <small className="text-muted d-block mt-1">
          <i className="bi bi-info-circle me-1"></i>
          Greyed-out addresses are no longer seen. Click for details.
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
