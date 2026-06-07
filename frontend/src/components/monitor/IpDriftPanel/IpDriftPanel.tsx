import { Spinner } from '@components/common/Spinner/Spinner';
import { useState, useEffect, type CSSProperties } from 'react';
import { Button } from '@govtechsg/sgds-react';
import { apiClient } from '@/services/api/client';
import type { NetworkSnapshot, AbsentEntity } from '@/features/monitor/types/monitor.types';
import type { SubnetDefinition } from '@/features/subnets/types/subnet.types';
import { customPrivateRangeService } from '@/features/intelligence/services/customPrivateRangeService';
import type { CustomPrivateRange } from '@/features/intelligence/types/customPrivateRange.types';
import { EntityDetailModal } from '@components/common/EntityDetailModal';

interface IpDriftPanelProps {
  snapshots: NetworkSnapshot[];
  subnets?: SubnetDefinition[];
}

type SelectedIp = { ip: string; fileId: string; isActive: boolean; lastSeenTime?: string | null } | null;

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

function isRfc1918(ip: string): boolean {
  return /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|f[cd][0-9a-f]{2}:|fe80:)/i.test(ip);
}

function isPrivateIp(ip: string, customRanges: CustomPrivateRange[]): boolean {
  if (isRfc1918(ip)) return true;
  return customRanges.some(r => ipInCidr(ip, r.cidr));
}

function ipToInt(ip: string): number {
  const parts = ip.split('.').map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function ipInCidr(ip: string, cidr: string): boolean {
  try {
    const [base, bits] = cidr.split('/');
    const mask = bits ? (0xffffffff << (32 - parseInt(bits))) >>> 0 : 0xffffffff;
    return (ipToInt(ip) & mask) === (ipToInt(base) & mask);
  } catch {
    return false;
  }
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
  onActiveClick,
}: {
  items: string[];
  absentItems: AbsentEntity[];
  onAbsentClick: (e: AbsentEntity) => void;
  onActiveClick: (ip: string) => void;
}) {
  if (items.length === 0 && absentItems.length === 0) return null;
  return (
    <div className="d-flex flex-wrap gap-2">
      {items.map(ip => (
        <Button
          key={ip}
          type="button"
          variant="secondary"
          size="sm"
          className="border-0 py-0 px-1"
          style={{ fontSize: '0.75em', ...hashBadgeStyle(ip) }}
          onClick={() => onActiveClick(ip)}
          title="Click for details & notes"
        >
          {ip}
        </Button>
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

function PrivateOverridesSection({
  customRanges,
  onSaved,
  onDeleted,
}: {
  customRanges: CustomPrivateRange[];
  onSaved: (r: CustomPrivateRange) => void;
  onDeleted: (id: number) => void;
}) {
  const [open, setOpen] = useState(false);
  const [cidr, setCidr] = useState('');
  const [label, setLabel] = useState('');
  const [adding, setAdding] = useState(false);
  const [addError, setAddError] = useState<string | null>(null);

  const handleAdd = async () => {
    const trimmed = cidr.trim();
    if (!trimmed) return;
    setAdding(true);
    setAddError(null);
    try {
      const created = await customPrivateRangeService.create(trimmed, label.trim());
      onSaved(created);
      setCidr('');
      setLabel('');
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: unknown } })?.response?.data;
      setAddError(typeof msg === 'string' ? msg : 'Failed to add range');
    } finally {
      setAdding(false);
    }
  };

  const handleDelete = async (id: number) => {
    try {
      await customPrivateRangeService.delete(id);
      onDeleted(id);
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: unknown } })?.response?.data;
      setAddError(typeof msg === 'string' ? msg : 'Failed to delete range');
    }
  };

  return (
    <div className="mt-3 pt-2 border-top">
      <button
        type="button"
        className="btn btn-link btn-sm p-0 text-muted text-decoration-none d-flex align-items-center gap-1"
        style={{ fontSize: '0.8rem' }}
        onClick={() => setOpen(o => !o)}
      >
        <i className={`bi bi-chevron-${open ? 'up' : 'down'}`}></i>
        <i className="bi bi-lock ms-1"></i>
        Private IP overrides
        {customRanges.length > 0 && (
          <span className="badge bg-secondary ms-1" style={{ fontSize: '0.7rem' }}>
            {customRanges.length}
          </span>
        )}
      </button>

      {open && (
        <div className="mt-2" style={{ fontSize: '0.82rem' }}>
          <p className="text-muted mb-2" style={{ fontSize: '0.78rem' }}>
            Add a public IP or CIDR that should be treated as internal (e.g. a public address used by a private terminal).
          </p>
          {customRanges.length > 0 && (
            <table className="table table-sm table-borderless mb-2">
              <tbody>
                {customRanges.map(r => (
                  <tr key={r.id}>
                    <td className="font-monospace py-1 ps-0">{r.cidr}</td>
                    <td className="text-muted py-1">{r.label ?? <em>—</em>}</td>
                    <td className="text-end py-1 pe-0">
                      <button
                        type="button"
                        className="btn btn-link btn-sm p-0 text-danger"
                        onClick={() => handleDelete(r.id)}
                        title="Remove override"
                      >
                        <i className="bi bi-trash"></i>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <div className="d-flex gap-2 flex-wrap align-items-center">
            <input
              type="text"
              className="form-control form-control-sm font-monospace"
              style={{ maxWidth: 180 }}
              placeholder="IP or CIDR"
              value={cidr}
              onChange={e => setCidr(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleAdd()}
            />
            <input
              type="text"
              className="form-control form-control-sm"
              style={{ maxWidth: 160 }}
              placeholder="Label (optional)"
              value={label}
              onChange={e => setLabel(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleAdd()}
            />
            <Button
              type="button"
              variant="primary"
              size="sm"
              onClick={handleAdd}
              disabled={adding || !cidr.trim()}
            >
              {adding ? 'Adding…' : 'Add'}
            </Button>
          </div>
          {addError && <div className="text-danger mt-1" style={{ fontSize: '0.78rem' }}>{addError}</div>}
        </div>
      )}
    </div>
  );
}

export const IpDriftPanel = ({ snapshots, subnets = [] }: IpDriftPanelProps) => {
  const [selectedAbsent, setSelectedAbsent] = useState<AbsentEntity | null>(null);
  const [selectedIp, setSelectedIp] = useState<SelectedIp>(null);
  const [privateIps, setPrivateIps] = useState<EntityGroup>({ active: [], absent: [] });
  const [publicIps, setPublicIps] = useState<EntityGroup>({ active: [], absent: [] });
  const [customRanges, setCustomRanges] = useState<CustomPrivateRange[]>([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');

  const sorted = [...snapshots].sort((a, b) => a.snapshotOrder - b.snapshotOrder);
  const latestSnap = sorted[sorted.length - 1];
  const latestFileId = latestSnap?.fileId ?? '';
  const latestStartTime = latestSnap?.startTime as unknown as string | null ?? null;

  useEffect(() => {
    customPrivateRangeService.list().then(setCustomRanges).catch(() => {});
  }, []);

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

      const sortIps = (ips: string[]) =>
        ips.sort((a, b) => {
          const ai = ipToInt(a), bi = ipToInt(b);
          return ai < bi ? -1 : ai > bi ? 1 : 0;
        });

      const buildGroup = (filter: (ip: string) => boolean): EntityGroup => {
        const active = sortIps(Array.from(latestIps).filter(filter));
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
        absent.sort((a, b) => {
          const ai = ipToInt(a.key), bi = ipToInt(b.key);
          return ai < bi ? -1 : ai > bi ? 1 : 0;
        });
        return { active, absent };
      };

      setPrivateIps(buildGroup(ip => isPrivateIp(ip, customRanges)));
      setPublicIps(buildGroup(ip => !isPrivateIp(ip, customRanges)));
      setLoading(false);
    });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [snapshots.map(s => s.id).join(','), customRanges]);

  if (loading) {
    return <div className="text-muted small text-center py-3"><Spinner animation="border" size="sm" className="me-2" />Loading…</div>;
  }

  const hasData =
    privateIps.active.length + privateIps.absent.length +
    publicIps.active.length + publicIps.absent.length > 0;

  if (!hasData) {
    return <div className="text-muted small text-center py-3">No IP data yet. Add at least one snapshot.</div>;
  }

  const allActive = [...privateIps.active, ...publicIps.active];
  const allAbsent = [...privateIps.absent, ...publicIps.absent];
  const hasAbsent = allAbsent.length > 0;

  // Build subnet groups when subnets are defined
  const subnetGroups: { subnet: SubnetDefinition; active: string[]; absent: AbsentEntity[] }[] = [];
  let unmatchedActive: string[] = [];
  let unmatchedAbsent: AbsentEntity[] = [];

  if (subnets.length > 0) {
    const matched = new Set<string>();
    for (const subnet of subnets) {
      const active = allActive.filter(ip => ipInCidr(ip, subnet.cidr));
      const absent = allAbsent.filter(e => ipInCidr(e.key, subnet.cidr));
      if (active.length > 0 || absent.length > 0) {
        subnetGroups.push({ subnet, active, absent });
        active.forEach(ip => matched.add(ip));
        absent.forEach(e => matched.add(e.key));
      }
    }
    unmatchedActive = allActive.filter(ip => !matched.has(ip));
    unmatchedAbsent = allAbsent.filter(e => !matched.has(e.key));
  }

  const useSubnetGroups = subnets.length > 0;

  const q = search.trim().toLowerCase();
  const filterIps = (ips: string[]) => q ? ips.filter(ip => ip.includes(q)) : ips;
  const filterAbsent = (ents: AbsentEntity[]) => q ? ents.filter(e => e.key.includes(q)) : ents;

  return (
    <>
      {/* Search */}
      {hasData && (
        <div className="mb-3">
          <input
            type="search"
            className="form-control form-control-sm"
            placeholder="Search IP addresses…"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
      )}
      {useSubnetGroups ? (
        <>
          {subnetGroups.map(({ subnet, active, absent }) => (
            <div key={subnet.cidr} className="mb-3">
              <small className="text-muted fw-semibold d-block mb-1">
                <i className="bi bi-diagram-2 me-1"></i>
                {subnet.label ? <>{subnet.label} <span className="fw-normal font-monospace">({subnet.cidr})</span></> : <span className="font-monospace">{subnet.cidr}</span>}
              </small>
              <IpBadgeGroup
                items={filterIps(active)}
                absentItems={filterAbsent(absent)}
                onAbsentClick={setSelectedAbsent}
                onActiveClick={ip => setSelectedIp({ ip, fileId: latestFileId, isActive: true, lastSeenTime: latestStartTime })}
              />
            </div>
          ))}
          {unmatchedActive.filter(ip => isPrivateIp(ip, customRanges)).length > 0 || unmatchedAbsent.filter(e => isPrivateIp(e.key, customRanges)).length > 0 ? (
            <div className="mb-3">
              <small className="text-muted fw-semibold d-block mb-1">
                <i className="bi bi-house me-1"></i>Private
              </small>
              <IpBadgeGroup
                items={filterIps(unmatchedActive.filter(ip => isPrivateIp(ip, customRanges)))}
                absentItems={filterAbsent(unmatchedAbsent.filter(e => isPrivateIp(e.key, customRanges)))}
                onAbsentClick={setSelectedAbsent}
                onActiveClick={ip => setSelectedIp({ ip, fileId: latestFileId, isActive: true, lastSeenTime: latestStartTime })}
              />
            </div>
          ) : null}
          {unmatchedActive.filter(ip => !isPrivateIp(ip, customRanges)).length > 0 || unmatchedAbsent.filter(e => !isPrivateIp(e.key, customRanges)).length > 0 ? (
            <div className="mb-3">
              <small className="text-muted fw-semibold d-block mb-1">
                <i className="bi bi-globe me-1"></i>Public
              </small>
              <IpBadgeGroup
                items={filterIps(unmatchedActive.filter(ip => !isPrivateIp(ip, customRanges)))}
                absentItems={filterAbsent(unmatchedAbsent.filter(e => !isPrivateIp(e.key, customRanges)))}
                onAbsentClick={setSelectedAbsent}
                onActiveClick={ip => setSelectedIp({ ip, fileId: latestFileId, isActive: true, lastSeenTime: latestStartTime })}
              />
            </div>
          ) : null}
        </>
      ) : (
        <>
          {(privateIps.active.length > 0 || privateIps.absent.length > 0) && (
            <div className="mb-3">
              <small className="text-muted fw-semibold d-block mb-2">
                <i className="bi bi-house me-1"></i>Private
              </small>
              <IpBadgeGroup
                items={filterIps(privateIps.active)}
                absentItems={filterAbsent(privateIps.absent)}
                onAbsentClick={setSelectedAbsent}
                onActiveClick={ip => setSelectedIp({ ip, fileId: latestFileId, isActive: true, lastSeenTime: latestStartTime })}
              />
            </div>
          )}
          {(publicIps.active.length > 0 || publicIps.absent.length > 0) && (
            <div className="mb-3">
              <small className="text-muted fw-semibold d-block mb-2">
                <i className="bi bi-globe me-1"></i>Public
              </small>
              <IpBadgeGroup
                items={filterIps(publicIps.active)}
                absentItems={filterAbsent(publicIps.absent)}
                onAbsentClick={setSelectedAbsent}
                onActiveClick={ip => setSelectedIp({ ip, fileId: latestFileId, isActive: true, lastSeenTime: latestStartTime })}
              />
            </div>
          )}
        </>
      )}
      {hasAbsent && (
        <small className="text-muted d-block mt-1">
          <i className="bi bi-info-circle me-1"></i>
          Greyed-out addresses are no longer seen. Click for details.
        </small>
      )}
      <PrivateOverridesSection
        customRanges={customRanges}
        onSaved={r => setCustomRanges(prev => [r, ...prev.filter(x => x.cidr !== r.cidr)])}
        onDeleted={id => setCustomRanges(prev => prev.filter(r => r.id !== id))}
      />
      {selectedAbsent && (
        <EntityDetailModal
          entityType="IP"
          entityKey={selectedAbsent.key}
          displayName={selectedAbsent.key}
          fileId={selectedAbsent.lastSeenFileId ?? ''}
          isActive={false}
          lastSeenTime={selectedAbsent.lastSeenStartTime}
          snapshots={snapshots}
          onClose={() => setSelectedAbsent(null)}
        />
      )}
      {selectedIp && (
        <EntityDetailModal
          entityType="IP"
          entityKey={selectedIp.ip}
          displayName={selectedIp.ip}
          fileId={selectedIp.fileId}
          isActive={selectedIp.isActive}
          lastSeenTime={selectedIp.lastSeenTime}
          snapshots={snapshots}
          onClose={() => setSelectedIp(null)}
        />
      )}
    </>
  );
};
