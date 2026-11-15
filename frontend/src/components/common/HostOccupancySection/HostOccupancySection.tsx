import { useEffect, useRef, useState } from 'react';
import { Button, Form, Modal } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { parseDateTime } from '@/utils/dateUtils';
import { deviceTypeLabel } from '@/utils/deviceType';
import type { DeviceType } from '@/types';
import {
  occupancyService,
  toInputValue,
  type ApiDateTime,
  type HostOccupancy,
  type Occupancy,
} from '@/features/occupancy/occupancyService';

function fmt(dt: ApiDateTime | null | undefined): string {
  return dt ? new Date(parseDateTime(dt)).toLocaleString() : '';
}

function apiMessage(err: unknown): string | null {
  return (err as { response?: { data?: { message?: string } } })?.response?.data?.message ?? null;
}

function range(o: Occupancy): string {
  const from = o.startsAt ? fmt(o.startsAt) : 'Start of capture';
  const to = o.endsAt ? fmt(o.endsAt) : 'end';
  return `${from} – ${to}`;
}

interface Props {
  fileId: string;
  ip: string;
  /** The device being looked at (#918): its row is marked. */
  focusIdx?: number;
  /** How the marked row is labelled: "this node" in the graph, "showing" in the device picker. */
  focusLabel?: string;
  /**
   * When set, each other device has a "Show" button that picks it (#918 slice 3), with its key:
   * the bare IP for the first device, `ip@<start>` for a later one.
   */
  onSelect?: (o: Occupancy, key: string) => void;
  /** Called with the number of devices once loaded, and after a split or merge. */
  onDevices?: (count: number) => void;
}

/** A device's key (#918 slice 3): the bare IP for the first, `ip@<start>` for a later one. */
export function deviceKey(ip: string, o: Occupancy): string {
  if (o.key) return o.key;
  return o.startsAt && o.boundaryKey ? `${ip}@${o.boundaryKey}` : ip;
}

/** One device's own verdict: "Mobile · 67% · Samsung · TTL 64". */
function verdictLine(o: Occupancy): string | null {
  const c = o.classification;
  if (!c) return null;
  const parts = [deviceTypeLabel(c.deviceType as DeviceType)];
  if (c.confidence != null) parts.push(`${c.confidence}%`);
  if (c.manufacturer) parts.push(c.manufacturer);
  if (c.ttl != null) parts.push(`TTL ${c.ttl}`);
  if (c.loggedInUser) parts.push(`signed in: ${c.loggedInUser}`);
  return parts.join(' · ');
}

/**
 * Which devices held this address, and when (#918 item 3). An address can pass from one device to
 * another inside a capture (DHCP handing it on); ARP and DHCP show the MAC changing. The analyst can
 * split an address the evidence didn't (a cloned VM, an off-subnet address), or merge away a split
 * that's wrong (a phone rotating its private MAC). Decisions are kept and audited.
 */
export function HostOccupancySection({ fileId, ip, focusIdx, focusLabel = 'this node', onSelect, onDevices }: Props) {
  const [data, setData] = useState<HostOccupancy | null>(null);
  const [failed, setFailed] = useState(false);
  const [splitOpen, setSplitOpen] = useState(false);
  const [mergeTarget, setMergeTarget] = useState<Occupancy | null>(null);
  const [infoOpen, setInfoOpen] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const currentIp = useRef(ip);
  currentIp.current = ip;

  const load = () => {
    setFailed(false);
    occupancyService
      .get(fileId, ip)
      .then(d => {
        if (currentIp.current !== ip) return;
        setData(d);
        onDevices?.(d.occupancies.length);
      })
      .catch(() => {
        if (currentIp.current === ip) setFailed(true);
      });
  };

  useEffect(() => {
    setData(null);
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fileId, ip]);

  if (failed) return null; // supplementary: the rest of the host's details still show
  if (!data) return null;
  const multiple = data.occupancies.length > 1;
  // A failover address is shared by design; there's nothing to split.
  if (data.virtualAddress && !multiple && data.decisions.length === 0) return null;

  const undo = async (id: number) => {
    setActionError(null);
    try {
      await occupancyService.undo(fileId, ip, id);
      load();
    } catch (e) {
      setActionError(apiMessage(e) ?? "Couldn't undo that.");
    }
  };

  return (
    <div className="mb-4" data-testid="host-occupancy">
      <h6 className="border-bottom pb-1 mb-2 d-flex align-items-center">
        <span className="text-muted fw-normal" style={{ fontSize: '0.8rem' }}>
          {multiple ? `Devices on this address (${data.occupancies.length})` : 'Devices on this address'}
        </span>
        <button
          type="button"
          aria-label="How devices on an address are worked out"
          className="btn btn-link p-0 ms-1 text-muted"
          style={{ fontSize: '0.8rem', lineHeight: 1 }}
          onClick={() => setInfoOpen(true)}
        >
          <i className="bi bi-info-circle" aria-hidden="true" />
        </button>
      </h6>

      {multiple ? (
        <ol className="list-unstyled mb-2" style={{ fontSize: '0.8rem' }}>
          {data.occupancies.map(o => (
            <li
              key={o.idx}
              className={`mb-2${focusIdx === o.idx ? ' border-start border-3 border-primary ps-2' : ''}`}
              data-testid="occupancy-row"
            >
              <div>
                <strong>{o.network ? `On ${o.network}` : range(o)}</strong>
                {focusIdx === o.idx && (
                  <span className="badge bg-primary-subtle text-primary-emphasis ms-2" data-testid="occupancy-this-node">
                    {focusLabel}
                  </span>
                )}
                {onSelect && focusIdx !== o.idx && (
                  <button
                    type="button"
                    className="btn btn-link p-0 ms-2 align-baseline"
                    style={{ fontSize: '0.75rem' }}
                    onClick={() => onSelect(o, deviceKey(ip, o))}
                  >
                    Show this device
                  </button>
                )}
              </div>
              {verdictLine(o) && (
                <div data-testid="occupancy-verdict">
                  <i className="bi bi-cpu me-1 text-muted" aria-hidden="true" />
                  {verdictLine(o)}
                </div>
              )}
              <div>
                {o.mac ? <span className="font-monospace">{o.mac}</span> : <span className="text-muted">MAC unknown</span>}
                {o.hostname && <> · {o.hostname}</>}
                {' · '}
                {o.conversations} conversation{o.conversations === 1 ? '' : 's'}
              </div>
              {o.startEvidence && (
                <div className="text-muted" style={{ fontSize: '0.72rem' }}>
                  {o.startSource === 'manual' && <i className="bi bi-person me-1" aria-hidden="true" />}
                  {o.startEvidence}
                  {o.automatic && data.canEdit && (
                    <button
                      type="button"
                      className="btn btn-link p-0 ms-2 align-baseline"
                      style={{ fontSize: '0.72rem' }}
                      onClick={() => {
                        setActionError(null);
                        setMergeTarget(o);
                      }}
                    >
                      Not a different device?
                    </button>
                  )}
                </div>
              )}
            </li>
          ))}
        </ol>
      ) : (
        <p className="text-muted mb-2" style={{ fontSize: '0.78rem' }}>
          {data.networks && data.networks.length > 1 ? (
            <>
              A different machine on each of {data.networks.length} networks that share this range:{' '}
              {data.networks.join(', ')}. They aren't split by time, since they were on the network at once.
            </>
          ) : (
            'One device for the whole capture.'
          )}
          {data.overlapping && (
            <> Two MACs claimed it at the same time, so it wasn't split automatically.</>
          )}
        </p>
      )}

      {data.decisions.length > 0 && (
        <ul className="list-unstyled mb-2" style={{ fontSize: '0.72rem' }} data-testid="occupancy-decisions">
          {data.decisions.map(d => (
            <li key={d.id} className="text-muted">
              {d.action === 'split' ? 'Split' : 'Merged'} at {fmt(d.at)}
              {d.actor && <> by {d.actor}</>}: {d.reason}
              {data.canEdit && (
                <button
                  type="button"
                  className="btn btn-link p-0 ms-2 align-baseline"
                  style={{ fontSize: '0.72rem' }}
                  onClick={() => undo(d.id)}
                >
                  Undo
                </button>
              )}
            </li>
          ))}
        </ul>
      )}

      {actionError && (
        <Alert variant="danger" className="py-1 small mb-2">
          {actionError}
        </Alert>
      )}

      {data.firstActivity && (
        <Button
          variant="outline-secondary"
          size="sm"
          disabled={!data.canEdit}
          onClick={() => {
            setActionError(null);
            setSplitOpen(true);
          }}
        >
          <i className="bi bi-scissors me-1" aria-hidden="true" />
          Split by time…
        </Button>
      )}
      {!data.canEdit && data.editReason && (
        <div className="text-muted mt-1" style={{ fontSize: '0.7rem' }}>
          {data.editReason}
        </div>
      )}

      <SplitModal
        show={splitOpen}
        data={data}
        onHide={() => setSplitOpen(false)}
        onSubmit={async (at, reason) => {
          const updated = await occupancyService.decide(fileId, ip, { at, action: 'split', reason });
          setData(updated);
          onDevices?.(updated.occupancies.length);
          setSplitOpen(false);
        }}
      />
      <MergeModal
        target={mergeTarget}
        onHide={() => setMergeTarget(null)}
        onSubmit={async reason => {
          if (!mergeTarget?.boundaryKey) return;
          const updated = await occupancyService.decide(fileId, ip, {
            at: mergeTarget.boundaryKey,
            action: 'merge',
            reason,
          });
          setData(updated);
          onDevices?.(updated.occupancies.length);
          setMergeTarget(null);
        }}
      />

      <Modal show={infoOpen} onHide={() => setInfoOpen(false)} centered>
        <Modal.Header closeButton>
          <Modal.Title style={{ fontSize: '1rem' }}>Devices on an address</Modal.Title>
        </Modal.Header>
        <Modal.Body style={{ fontSize: '0.85rem' }}>
          <p>
            An address can pass from one device to another during a capture, for example when DHCP
            hands a laptop's address to a phone. When ARP or DHCP shows a <strong>different MAC</strong>{' '}
            taking over the address, it's split into one entry per device, with the evidence.
          </p>
          <p>
            A different TTL or hostname alone doesn't split it, because one machine rebooting into
            another system looks the same. Those, and long silences, are offered as suggestions when you
            split by hand.
          </p>
          <p className="mb-0">
            <strong>Split by time</strong> when you know it's two devices (a cloned VM, a re-imaged
            machine). <strong>Not a different device?</strong> merges a split that's wrong, such as a
            phone rotating its private MAC. Both are kept with your reason, recorded in the audit log,
            and can be undone.
          </p>
        </Modal.Body>
      </Modal>
    </div>
  );
}

function SplitModal({
  show,
  data,
  onHide,
  onSubmit,
}: {
  show: boolean;
  data: HostOccupancy;
  onHide: () => void;
  onSubmit: (at: string, reason: string) => Promise<void>;
}) {
  const [choice, setChoice] = useState<string>('custom');
  const [custom, setCustom] = useState('');
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!show) return;
    setChoice(data.suggestions[0]?.key ?? 'custom');
    setCustom(toInputValue(data.firstActivity));
    setReason('');
    setError(null);
  }, [show, data]);

  const at = choice === 'custom' ? custom : choice;
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await onSubmit(at, reason.trim());
    } catch (e) {
      setError(apiMessage(e) ?? "Couldn't split the address.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal show={show} onHide={busy ? undefined : onHide} centered>
      <Modal.Header closeButton={!busy}>
        <Modal.Title style={{ fontSize: '1rem' }}>Split {data.ip} by time</Modal.Title>
      </Modal.Header>
      <Modal.Body style={{ fontSize: '0.85rem' }}>
        <p>
          From the time you pick, this address is treated as a different device. Labels, roles and
          evidence already on the device stay with the part before that time.
        </p>
        <Form.Group className="mb-3">
          <Form.Label className="small text-muted mb-1">Where</Form.Label>
          {data.suggestions.map(s => (
            <Form.Check
              key={s.key}
              type="radio"
              id={`split-${s.key}`}
              name="split-at"
              checked={choice === s.key}
              onChange={() => setChoice(s.key)}
              label={
                <>
                  {fmt(s.at)} <span className="text-muted">· {s.description}</span>
                </>
              }
            />
          ))}
          <Form.Check
            type="radio"
            id="split-custom"
            name="split-at"
            checked={choice === 'custom'}
            onChange={() => setChoice('custom')}
            label={data.suggestions.length ? 'Another time' : 'At'}
          />
          {choice === 'custom' && (
            <Form.Control
              type="datetime-local"
              step={1}
              aria-label="Split time"
              className="mt-1"
              value={custom}
              min={toInputValue(data.firstActivity)}
              max={toInputValue(data.lastActivity)}
              onChange={e => setCustom(e.target.value)}
            />
          )}
          <Form.Text className="text-muted">
            Activity on this address runs from {fmt(data.firstActivity)} to {fmt(data.lastActivity)}.
          </Form.Text>
        </Form.Group>
        <Form.Group>
          <Form.Label htmlFor="split-reason" className="small text-muted mb-1">
            Why (kept with the split)
          </Form.Label>
          <Form.Control
            id="split-reason"
            as="textarea"
            rows={2}
            maxLength={1000}
            value={reason}
            onChange={e => setReason(e.target.value)}
            placeholder="e.g. two VMs cloned from one image"
          />
        </Form.Group>
        {error && (
          <Alert variant="danger" className="py-1 small mt-3 mb-0">
            {error}
          </Alert>
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={onHide} disabled={busy}>
          Cancel
        </Button>
        <Button variant="primary" onClick={submit} disabled={busy || !at || !reason.trim()}>
          Split
        </Button>
      </Modal.Footer>
    </Modal>
  );
}

function MergeModal({
  target,
  onHide,
  onSubmit,
}: {
  target: Occupancy | null;
  onHide: () => void;
  onSubmit: (reason: string) => Promise<void>;
}) {
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    setReason('');
    setError(null);
  }, [target]);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await onSubmit(reason.trim());
    } catch (e) {
      setError(apiMessage(e) ?? "Couldn't merge.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal show={!!target} onHide={busy ? undefined : onHide} centered>
      <Modal.Header closeButton={!busy}>
        <Modal.Title style={{ fontSize: '1rem' }}>Not a different device?</Modal.Title>
      </Modal.Header>
      <Modal.Body style={{ fontSize: '0.85rem' }}>
        <p>
          This joins the device from {target ? fmt(target.startsAt) : ''} with the one before it.
          {target?.startEvidence && <> The split came from: {target.startEvidence}.</>}
        </p>
        <p>
          Labels, roles and evidence on the later device move to the joined one. If it already has its
          own, the later device's are kept aside. Undoing the merge moves them back.
        </p>
        <Form.Label htmlFor="merge-reason" className="small text-muted mb-1">
          Why (kept with the merge)
        </Form.Label>
        <Form.Control
          id="merge-reason"
          as="textarea"
          rows={2}
          maxLength={1000}
          value={reason}
          onChange={e => setReason(e.target.value)}
          placeholder="e.g. the same phone, rotating its private MAC"
        />
        {error && (
          <Alert variant="danger" className="py-1 small mt-3 mb-0">
            {error}
          </Alert>
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={onHide} disabled={busy}>
          Cancel
        </Button>
        <Button variant="primary" onClick={submit} disabled={busy || !reason.trim()}>
          Merge
        </Button>
      </Modal.Footer>
    </Modal>
  );
}
