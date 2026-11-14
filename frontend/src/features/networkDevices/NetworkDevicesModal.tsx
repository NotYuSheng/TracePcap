import { useEffect, useMemo, useState } from 'react';
import { Button, Form, Modal } from '@govtechsg/sgds-react';
import { Link } from 'react-router-dom';
import { Alert } from '@components/common/Alert';
import { Pagination } from '@/components/common/Pagination';
import { deviceTypeLabel } from '@/utils/deviceType';
import type { DeviceType } from '@/types';
import type { NetworkSnapshot } from '@/features/monitor/types/monitor.types';
import {
  networkDeviceService,
  type DeviceLink,
  type DeviceLinkSuggestion,
  type DeviceShow,
  type NetworkDevice,
  type NetworkDeviceCounts,
} from './networkDeviceService';

function apiMessage(err: unknown): string | null {
  return (err as { response?: { data?: { message?: string } } })?.response?.data?.message ?? null;
}

const STRENGTH_BADGE: Record<string, string> = {
  strong: 'bg-primary-subtle text-primary-emphasis',
  medium: 'bg-info-subtle text-info-emphasis',
  weak: 'bg-body-secondary text-body',
};

/** A decision being made: which two MACs, and same or not. */
interface Pending {
  macA: string;
  macB: string;
  name: string;
  decision: 'same' | 'not_same';
}

const PAGE_SIZE = 20;

const MAC_KIND_BADGE: Record<NetworkDevice['macKind'], { text: string; cls: string } | null> = {
  HARDWARE: null,
  PRIVATE: { text: 'Private MAC', cls: 'bg-info-subtle text-info-emphasis' },
  VIRTUAL_MACHINE: { text: 'Virtual machine', cls: 'bg-secondary-subtle text-secondary-emphasis' },
  CONTAINER: { text: 'Container', cls: 'bg-secondary-subtle text-secondary-emphasis' },
};

const SEVERITY_DOT: Record<string, string> = { high: 'bg-danger', medium: 'bg-warning', info: 'bg-info' };

interface Props {
  show: boolean;
  networkId: string;
  networkName: string;
  snapshots: NetworkSnapshot[];
  onHide: () => void;
}

/** Snapshot n (1-based) to the first and last it covers, e.g. "snapshots 1–3". */
function range(a: { firstSnapshot: number; lastSnapshot: number }): string {
  return a.firstSnapshot === a.lastSnapshot
    ? `snapshot ${a.firstSnapshot}`
    : `snapshots ${a.firstSnapshot}–${a.lastSnapshot}`;
}

/**
 * A monitored network's devices across its snapshots (#918 slice 4): one row per MAC, wherever the
 * device was on the network, with anything irregular about its MAC.
 */
export function NetworkDevicesModal({ show, networkId, networkName, snapshots, onHide }: Props) {
  const [q, setQ] = useState('');
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<DeviceShow>('all');
  const [page, setPage] = useState(1);
  const [rows, setRows] = useState<NetworkDevice[]>([]);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(0);
  const [counts, setCounts] = useState<NetworkDeviceCounts | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<NetworkDevice | null>(null);
  const [helpOpen, setHelpOpen] = useState(false);
  const [suggestions, setSuggestions] = useState<DeviceLinkSuggestion[]>([]);
  const [pending, setPending] = useState<Pending | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  // Bumped after a decision, so the list, counts and suggestions are read again.
  const [version, setVersion] = useState(0);

  // Search as you type, without a request per keystroke.
  useEffect(() => {
    const t = setTimeout(() => {
      setQuery(q.trim());
      setPage(1);
    }, 250);
    return () => clearTimeout(t);
  }, [q]);

  useEffect(() => {
    if (!show) return;
    networkDeviceService.counts(networkId).then(setCounts).catch(() => setCounts(null));
    networkDeviceService.suggestions(networkId).then(setSuggestions).catch(() => setSuggestions([]));
  }, [show, networkId, version]);

  useEffect(() => {
    if (!show) return;
    let alive = true;
    setLoading(true);
    setError(null);
    networkDeviceService
      .list(networkId, { q: query, show: filter, page, pageSize: PAGE_SIZE })
      .then(r => {
        if (!alive) return;
        setRows(r.data);
        setTotal(r.total);
        setTotalPages(r.totalPages);
      })
      .catch(() => {
        if (alive) setError("Couldn't load this network's devices.");
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [show, networkId, query, filter, page, version]);

  const decide = async (p: Pending, reason: string) => {
    await networkDeviceService.decide(networkId, { macA: p.macA, macB: p.macB, decision: p.decision, reason });
    setPending(null);
    setSelected(null);
    setVersion(v => v + 1);
  };

  const undo = async (link: DeviceLink) => {
    setActionError(null);
    try {
      await networkDeviceService.undo(networkId, link.id);
      setSelected(null);
      setVersion(v => v + 1);
    } catch (e) {
      setActionError(apiMessage(e) ?? "Couldn't undo that.");
    }
  };

  const chips: { key: DeviceShow; label: string; count?: number }[] = [
    { key: 'all', label: 'All', count: counts?.all },
    { key: 'irregular', label: 'Irregular', count: counts?.irregular },
    { key: 'private', label: 'Private MAC', count: counts?.privateMac },
  ];

  return (
    <>
    <Modal show={show} onHide={selected ? () => setSelected(null) : onHide} size="xl" scrollable>
      <Modal.Header closeButton>
        <Modal.Title as="h5" className="d-flex align-items-center gap-2">
          {selected ? (
            <>
              <button type="button" className="btn btn-link p-0" onClick={() => setSelected(null)}>
                <i className="bi bi-arrow-left me-1" aria-hidden="true" />
                Devices
              </button>
              <span>{selected.name ?? selected.mac}</span>
            </>
          ) : (
            <>
              Devices
              <button
                type="button"
                aria-label="How devices are recognised"
                aria-expanded={helpOpen}
                className="btn btn-link p-0 text-muted"
                style={{ fontSize: '0.9rem', lineHeight: 1 }}
                onClick={() => setHelpOpen(o => !o)}
              >
                <i className="bi bi-info-circle" aria-hidden="true" />
              </button>
            </>
          )}
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {selected ? (
          <>
            {actionError && <Alert variant="danger" className="small py-2">{actionError}</Alert>}
            <DeviceDetail device={selected} snapshots={snapshots} onNavigate={onHide} onUndo={undo} />
          </>
        ) : (
          <>
            <p className="text-muted small mb-2">
              {networkName} · {snapshots.length} snapshot{snapshots.length === 1 ? '' : 's'} · one row per
              device, wherever it was on the network
            </p>
            {helpOpen && (
              <Alert variant="info" className="small py-2" data-testid="devices-help">
                A device is recognised by its <strong>MAC</strong>, so a laptop that moved from one address
                to another is one row, and two devices that shared an address are two. Hosts outside the
                local network have no MAC of their own (their frames carry the router's) and aren't listed.{' '}
                <strong>Irregular</strong> devices have a MAC that may not identify one machine: a virtual
                machine or container MAC, or one MAC answering as two machines at once.{' '}
                <strong>Private</strong> MACs are made up by the device (phones do this per network) and
                can change, so the same phone may appear under more than one.
              </Alert>
            )}

            <div className="d-flex flex-wrap align-items-center gap-2 mb-3">
              <Form.Label htmlFor="devices-search" className="visually-hidden">
                Search devices
              </Form.Label>
              <Form.Control
                id="devices-search"
                type="search"
                size="sm"
                placeholder="Search name, MAC, address, vendor or label"
                value={q}
                onChange={e => setQ(e.target.value)}
                style={{ flex: '1 1 280px', maxWidth: 420 }}
              />
              <div role="group" aria-label="Show" className="d-flex gap-1">
                {chips.map(c => (
                  <Button
                    key={c.key}
                    type="button"
                    size="sm"
                    variant={filter === c.key ? 'primary' : 'outline-secondary'}
                    aria-pressed={filter === c.key}
                    onClick={() => {
                      setFilter(c.key);
                      setPage(1);
                    }}
                  >
                    {c.label}
                    {c.count != null && <> <span>{c.count}</span></>}
                  </Button>
                ))}
              </div>
            </div>

            {error && <Alert variant="danger" className="small py-2">{error}</Alert>}

            {filter === 'all' && !query && suggestions.slice(0, 3).map(sg => (
              <Alert key={sg.macA + sg.macB} variant="warning" className="small py-2" data-testid="device-suggestion">
                <div className="d-flex flex-wrap gap-2 align-items-start justify-content-between">
                  <div style={{ flex: '1 1 420px', minWidth: 0 }}>
                    <strong>
                      2 private MACs look like one device{sg.nameB ? `: ${sg.nameB}` : ''}
                    </strong>
                    <div>
                      <span className="font-monospace">{sg.macA}</span> in {range({ firstSnapshot: sg.firstSnapshotA, lastSnapshot: sg.lastSnapshotA })},
                      then <span className="font-monospace">{sg.macB}</span> in {range({ firstSnapshot: sg.firstSnapshotB, lastSnapshot: sg.lastSnapshotB })}.
                    </div>
                    <ul className="list-unstyled mb-0 mt-1">
                      {sg.evidence.map(e => (
                        <li key={e.what} className="d-flex gap-2 align-items-start">
                          <span className={`badge ${STRENGTH_BADGE[e.strength] ?? ''}`} style={{ minWidth: 58 }}>{e.strength}</span>
                          <span><strong>{e.what}.</strong> {e.detail}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                  <div className="d-flex gap-2 flex-shrink-0">
                    <Button
                      type="button"
                      size="sm"
                      variant="primary"
                      onClick={() => setPending({ macA: sg.macA, macB: sg.macB, name: sg.nameB ?? sg.macB, decision: 'same' })}
                    >
                      Same device
                    </Button>
                    <Button
                      type="button"
                      size="sm"
                      variant="outline-secondary"
                      onClick={() => setPending({ macA: sg.macA, macB: sg.macB, name: sg.nameB ?? sg.macB, decision: 'not_same' })}
                    >
                      Not the same
                    </Button>
                  </div>
                </div>
              </Alert>
            ))}
            {filter === 'all' && !query && suggestions.length > 3 && (
              <p className="small text-muted">And {suggestions.length - 3} more possible matches.</p>
            )}

            {!error && !loading && rows.length === 0 && (
              <p className="text-muted small" data-testid="devices-empty">
                {query || filter !== 'all'
                  ? 'No devices match.'
                  : 'No devices yet: add a snapshot with local traffic to see its devices.'}
              </p>
            )}

            {rows.length > 0 && (
              <div className="table-responsive">
                <table className="table table-sm align-top small mb-2">
                  <thead>
                    <tr className="text-muted">
                      <th scope="col">Device</th>
                      <th scope="col">MAC</th>
                      <th scope="col">Addresses it used</th>
                      <th scope="col">Seen in</th>
                      <th scope="col">Label</th>
                      <th scope="col">Irregularities</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map(d => (
                      <tr key={d.mac} data-testid="device-row">
                        <td>
                          <button
                            type="button"
                            className="btn btn-link p-0 fw-semibold text-start"
                            onClick={() => setSelected(d)}
                          >
                            {d.name ?? d.mac}
                          </button>
                          {d.deviceType && (
                            <div className="text-muted">{deviceTypeLabel(d.deviceType as DeviceType)}</div>
                          )}
                        </td>
                        <td>
                          {d.macs.map(m => (
                            <div key={m} className="font-monospace">{m}</div>
                          ))}
                          {d.vendor && <div className="text-muted">{d.vendor}</div>}
                          {MAC_KIND_BADGE[d.macKind] && (
                            <span className={`badge ${MAC_KIND_BADGE[d.macKind]!.cls}`}>
                              {MAC_KIND_BADGE[d.macKind]!.text}
                            </span>
                          )}
                        </td>
                        <td>
                          {d.addresses.map(a => (
                            <div key={a.ip}>
                              <span className="font-monospace">{a.ip}</span>{' '}
                              <span className="text-muted">{range(a)}</span>
                            </div>
                          ))}
                        </td>
                        <td>
                          <SeenStrip device={d} snapshots={snapshots} />
                        </td>
                        <td>{d.label ? <span className="badge bg-primary-subtle text-primary-emphasis">{d.label}</span> : <span className="text-muted">—</span>}</td>
                        <td style={{ maxWidth: 300 }}>
                          <Flags device={d} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {totalPages > 1 && (
              <Pagination
                currentPage={page}
                totalPages={totalPages}
                totalItems={total}
                pageSize={PAGE_SIZE}
                onPageChange={setPage}
                showPageSizeSelector={false}
              />
            )}
          </>
        )}
      </Modal.Body>
    </Modal>
    <DecisionModal pending={pending} onHide={() => setPending(null)} onSubmit={decide} />
    </>
  );
}

/** Asks for the reason behind a same / not-the-same decision, and records it. */
function DecisionModal({
  pending,
  onHide,
  onSubmit,
}: {
  pending: Pending | null;
  onHide: () => void;
  onSubmit: (p: Pending, reason: string) => Promise<void>;
}) {
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    setReason('');
    setErr(null);
  }, [pending]);
  if (!pending) return null;
  const same = pending.decision === 'same';
  const save = async () => {
    setBusy(true);
    setErr(null);
    try {
      await onSubmit(pending, reason.trim());
    } catch (e) {
      setErr(apiMessage(e) ?? "Couldn't save that.");
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal show onHide={onHide} centered>
      <Modal.Header closeButton>
        <Modal.Title as="h5">{same ? 'Same device?' : 'Not the same device?'}</Modal.Title>
      </Modal.Header>
      <Modal.Body className="small">
        <p>
          <span className="font-monospace">{pending.macA}</span> and{' '}
          <span className="font-monospace">{pending.macB}</span>
          {same
            ? ' will show as one device, in every snapshot. Its label then applies under both MACs.'
            : " won't be suggested as one device again."}{' '}
          Your reason is kept and audited, and you can undo it from the device.
        </p>
        {err && <Alert variant="danger" className="py-2">{err}</Alert>}
        <Form.Label htmlFor="device-link-reason">Reason</Form.Label>
        <Form.Control
          id="device-link-reason"
          as="textarea"
          rows={2}
          value={reason}
          onChange={e => setReason(e.target.value)}
          placeholder={same ? "e.g. Bob's phone rotated its private address" : 'e.g. two staff with the same phone model'}
        />
      </Modal.Body>
      <Modal.Footer>
        <Button type="button" variant="outline-secondary" onClick={onHide}>
          Cancel
        </Button>
        <Button type="button" variant="primary" onClick={save} disabled={busy || !reason.trim()}>
          {same ? 'Link as one device' : 'Mark as different'}
        </Button>
      </Modal.Footer>
    </Modal>
  );
}

/** One square per snapshot, filled where the device was seen. */
function SeenStrip({ device, snapshots }: { device: NetworkDevice; snapshots: NetworkSnapshot[] }) {
  const seen = useMemo(() => new Set(device.seenInFileIds), [device.seenInFileIds]);
  return (
    <div
      role="img"
      aria-label={`Seen in ${seen.size} of ${snapshots.length} snapshots`}
      className="d-flex gap-1 pt-1"
      data-testid="device-seen"
    >
      {snapshots.map(s => (
        <span
          key={s.id}
          className={seen.has(s.fileId) ? 'bg-primary' : 'bg-body-secondary'}
          style={{ width: 10, height: 10, borderRadius: 2, display: 'inline-block' }}
        />
      ))}
    </div>
  );
}

function Flags({ device }: { device: NetworkDevice }) {
  if (device.flags.length === 0) return <span className="text-muted">—</span>;
  return (
    <>
      {device.flags.map(f => (
        <div key={f.kind + f.text} className="d-flex gap-2 align-items-start mb-1" data-testid="device-flag">
          <span
            className={`rounded-circle flex-shrink-0 ${SEVERITY_DOT[f.severity] ?? 'bg-secondary'}`}
            style={{ width: 8, height: 8, marginTop: 5 }}
            aria-hidden="true"
          />
          <span>
            <span className="visually-hidden">{f.severity}: </span>
            {f.text}
          </span>
        </div>
      ))}
    </>
  );
}

/** One device: where it was in each snapshot, its irregularities and its label. */
function DeviceDetail({
  device,
  snapshots,
  onNavigate,
  onUndo,
}: {
  device: NetworkDevice;
  snapshots: NetworkSnapshot[];
  onNavigate: () => void;
  onUndo: (link: DeviceLink) => void;
}) {
  const seen = new Set(device.seenInFileIds);
  const badge = MAC_KIND_BADGE[device.macKind];
  return (
    <div className="small" data-testid="device-detail">
      <p className="text-muted mb-3">
        <span className="font-monospace">{device.macs.join(', ')}</span>
        {device.vendor && <> · {device.vendor}</>}
        {device.deviceType && <> · {deviceTypeLabel(device.deviceType as DeviceType)}</>}
        {badge && <span className={`badge ms-2 ${badge.cls}`}>{badge.text}</span>}
      </p>

      <h6 className="text-muted fw-normal border-bottom pb-1">Where it was</h6>
      <div className="table-responsive mb-3">
        <table className="table table-sm table-borderless mb-0" style={{ width: 'auto' }}>
          <thead>
            <tr className="text-muted">
              <th scope="col">Address</th>
              {snapshots.map((s, i) => (
                <th key={s.id} scope="col" className="text-center fw-normal">
                  {i + 1}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {device.addresses.map(a => (
              <tr key={a.ip}>
                <th scope="row" className="font-monospace fw-normal">{a.ip}</th>
                {snapshots.map((s, i) => {
                  const on = seen.has(s.fileId) && i + 1 >= a.firstSnapshot && i + 1 <= a.lastSnapshot;
                  return (
                    <td key={s.id} className="text-center">
                      <span
                        className={on ? 'bg-primary' : 'bg-body-secondary'}
                        style={{ width: 22, height: 14, borderRadius: 3, display: 'inline-block' }}
                        aria-label={on ? `Seen in snapshot ${i + 1}` : `Not seen in snapshot ${i + 1}`}
                        role="img"
                      />
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h6 className="text-muted fw-normal border-bottom pb-1">Irregularities</h6>
      <div className="mb-3">
        <Flags device={device} />
      </div>

      {device.links.length > 0 && (
        <>
          <h6 className="text-muted fw-normal border-bottom pb-1">Your decisions</h6>
          <ul className="list-unstyled mb-3" data-testid="device-links">
            {device.links.map(l => (
              <li key={l.id} className="mb-1">
                <strong>{l.decision === 'same' ? 'Same device' : 'Not the same'}:</strong>{' '}
                <span className="font-monospace">{l.macA}</span> and <span className="font-monospace">{l.macB}</span>
                {' · '}
                {l.reason}
                {l.actor && <span className="text-muted"> ({l.actor})</span>}
                <button type="button" className="btn btn-link p-0 ms-2 align-baseline small" onClick={() => onUndo(l)}>
                  Undo
                </button>
              </li>
            ))}
          </ul>
        </>
      )}

      <h6 className="text-muted fw-normal border-bottom pb-1">Label</h6>
      <p className="mb-3">
        {device.label ?? <span className="text-muted">None yet.</span>}{' '}
        <span className="text-muted">
          Set it on the device's node in a snapshot; it follows the device's MAC into later snapshots.
        </span>
      </p>

      {device.lastFileId && (
        <Link to={`/analysis/${device.lastFileId}`} onClick={onNavigate}>
          Open the latest snapshot it was seen in
        </Link>
      )}
    </div>
  );
}
