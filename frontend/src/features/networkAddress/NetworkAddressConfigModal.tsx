import { useEffect, useMemo, useState } from 'react';
import { Badge, Button, Form, Modal } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { Spinner } from '@components/common/Spinner/Spinner';
import { usePermission } from '@/features/me/useMe';
import {
  networkSource,
  type AddressEntry,
  type AddressEntryInput,
  type AddressKind,
  type AddressSource,
} from './networkAddressService';

interface KindConfig {
  kind: AddressKind;
  title: string;
  /** What the value column is called. */
  valueLabel: string;
  intro: string;
}

const KINDS: KindConfig[] = [
  {
    kind: 'subnets',
    title: 'Subnet labels',
    valueLabel: 'Label',
    intro: 'Names for address ranges, shown in the subnet views and used for staleness checks.',
  },
  {
    kind: 'custom-private-ranges',
    title: 'Internal / external ranges',
    valueLabel: 'Treat as',
    intro: 'Ranges forced to count as internal or external, overriding the usual private-address rules.',
  },
  {
    kind: 'ip-org-rules',
    title: 'Organisations',
    valueLabel: 'Organisation',
    intro: 'Network labels: which organisation owns a range, used to group hosts in the Network Cluster view (Network Labels grouping).',
  },
];

function apiMessage(err: unknown): string | null {
  return (err as { response?: { data?: { message?: string } } })?.response?.data?.message ?? null;
}

function valueOf(e: AddressEntry, kind: AddressKind): string {
  if (kind === 'custom-private-ranges') return e.classification === 'PUBLIC' ? 'External' : 'Internal';
  return e.label ?? '';
}

interface Props {
  show: boolean;
  networkId: string;
  networkName: string;
  onHide: () => void;
  /** Called after any change, so the page can refresh what it shows. */
  onChanged?: () => void;
}

/**
 * A network's address configuration (#915 phase 4): subnet labels, internal/external ranges and
 * organisations. Each list is the shared default with this network's own entries layered on top,
 * per CIDR: override a default entry here, hide it here, add one only this network has, or revert
 * to the default.
 */
export function NetworkAddressConfigModal({ show, networkId, networkName, onHide, onChanged }: Props) {
  const source = useMemo(() => networkSource(networkId), [networkId]);
  return (
    <Modal show={show} onHide={onHide} size="lg" centered>
      <Modal.Header closeButton>
        <Modal.Title style={{ fontSize: '1rem' }}>Address configuration · {networkName}</Modal.Title>
      </Modal.Header>
      <Modal.Body style={{ fontSize: '0.85rem' }}>
        <p className="text-muted small">
          Each list starts from the shared default, which applies to every network. Entries you set here
          apply in this network only, to its existing snapshots too: override a default entry, hide it,
          or add one only this network has.
        </p>
        <AddressTabs source={source} idPrefix="network-address" onChanged={onChanged} />
      </Modal.Body>
    </Modal>
  );
}

/**
 * The three address lists as tabs, over a network's layer or the shared default.
 */
export function AddressTabs({
  source,
  idPrefix,
  onChanged,
}: {
  source: AddressSource;
  idPrefix: string;
  onChanged?: () => void;
}) {
  const [active, setActive] = useState<AddressKind>('subnets');
  return (
    <>
      {/* SGDS buttons as the tabs: plain nav-tabs inside a card body collapse to zero width in
          this theme and the panel covers them, so the lists couldn't be reached. */}
      <div className="d-flex flex-wrap gap-2 mb-3" role="tablist" aria-label="Address lists">
        {KINDS.map(k => (
          <Button
            key={k.kind}
            type="button"
            size="sm"
            role="tab"
            id={`${idPrefix}-tab-${k.kind}`}
            aria-selected={active === k.kind}
            aria-controls={`${idPrefix}-panel-${k.kind}`}
            variant={active === k.kind ? 'primary' : 'outline-primary'}
            onClick={() => setActive(k.kind)}
          >
            {k.title}
          </Button>
        ))}
      </div>
      <div role="tabpanel" id={`${idPrefix}-panel-${active}`} aria-labelledby={`${idPrefix}-tab-${active}`}>
        <AddressList key={active} config={KINDS.find(k => k.kind === active)!} source={source} onChanged={onChanged} />
      </div>
    </>
  );
}

function AddressList({
  config,
  source,
  onChanged,
}: {
  config: KindConfig;
  source: AddressSource;
  onChanged?: () => void;
}) {
  const { kind } = config;
  const inNetwork = source.mode === 'network';
  const { allowed, reason } = usePermission(source.permission);
  const [entries, setEntries] = useState<AddressEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [editing, setEditing] = useState<{ entry?: AddressEntry } | null>(null);

  const [reloadKey, setReloadKey] = useState(0);
  const load = () => setReloadKey(k => k + 1);
  useEffect(() => {
    let alive = true;
    source
      .list(kind)
      .then(r => {
        if (!alive) return;
        setEntries(r);
        setError(null);
      })
      .catch(() => {
        if (alive) setError("Couldn't load this list.");
      });
    return () => {
      alive = false;
    };
  }, [source, kind, reloadKey]);

  const shown = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!entries) return [];
    if (!q) return entries;
    return entries.filter(
      e => e.cidr.toLowerCase().includes(q) || valueOf(e, kind).toLowerCase().includes(q),
    );
  }, [entries, search, kind]);

  const run = async (fn: () => Promise<unknown>, failure: string) => {
    setActionError(null);
    try {
      await fn();
      load();
      onChanged?.();
    } catch (e) {
      setActionError(apiMessage(e) ?? failure);
    }
  };

  if (error) return <Alert variant="danger">{error}</Alert>;
  if (!entries) {
    return (
      <div className="text-muted small d-flex align-items-center gap-2">
        <Spinner size="sm" /> Loading…
      </div>
    );
  }

  return (
    <div data-testid={`address-list-${kind}`}>
      <p className="text-muted small mb-2">{config.intro}</p>
      <div className="d-flex gap-2 mb-2">
        <Form.Control
          size="sm"
          type="search"
          placeholder="Search CIDR or value"
          aria-label={`Search ${config.title}`}
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        <Button size="sm" variant="primary" disabled={!allowed} onClick={() => setEditing({})} className="text-nowrap">
          <i className="bi bi-plus-lg me-1" aria-hidden="true" />
          {inNetwork ? 'Add for this network' : 'Add'}
        </Button>
      </div>
      {!allowed && reason && <div className="text-muted small mb-2">{reason}</div>}
      {actionError && (
        <Alert variant="danger" className="py-1 small">
          {actionError}
        </Alert>
      )}

      {entries.length === 0 ? (
        <p className="text-muted fst-italic small mb-0">
          {inNetwork ? 'Nothing here yet, in the default or this network.' : 'Nothing here yet.'}
        </p>
      ) : shown.length === 0 ? (
        <p className="text-muted fst-italic small mb-0">No entries match “{search}”.</p>
      ) : (
        <table className="table table-sm align-middle mb-0">
          <thead>
            <tr>
              <th scope="col">CIDR</th>
              <th scope="col">{config.valueLabel}</th>
              {inNetwork && <th scope="col">From</th>}
              <th scope="col" className="text-end">
                <span className="visually-hidden">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {shown.map(e => (
              <tr key={`${e.scope}-${e.id}`} data-testid="address-row" className={e.hidden ? 'text-muted' : undefined}>
                <td className="font-monospace">{e.hidden ? <s>{e.cidr}</s> : e.cidr}</td>
                <td>{e.hidden ? <s>{valueOf(e, kind)}</s> : valueOf(e, kind) || <span className="text-muted">—</span>}</td>
                {inNetwork && <td>
                  {e.scope === 'default' ? (
                    <Badge bg="secondary">default</Badge>
                  ) : e.hidden ? (
                    <Badge bg="warning" text="dark">hidden here</Badge>
                  ) : e.overridesDefault ? (
                    <Badge bg="primary">overridden here</Badge>
                  ) : (
                    <Badge bg="primary">this network</Badge>
                  )}
                </td>}
                <td className="text-end text-nowrap">
                  {!inNetwork ? (
                    <>
                      <Button size="sm" variant="link" disabled={!allowed} onClick={() => setEditing({ entry: e })}>
                        Edit
                      </Button>
                      <Button
                        size="sm"
                        variant="link"
                        className="text-danger"
                        disabled={!allowed}
                        onClick={() => run(() => source.remove(kind, e), "Couldn't delete it.")}
                      >
                        Delete
                      </Button>
                    </>
                  ) : e.scope === 'default' ? (
                    <>
                      <Button size="sm" variant="link" disabled={!allowed} onClick={() => setEditing({ entry: e })}>
                        Override
                      </Button>
                      <Button
                        size="sm"
                        variant="link"
                        disabled={!allowed}
                        onClick={() =>
                          run(() => source.put(kind, { cidr: e.cidr, hidden: true }), "Couldn't hide it.")
                        }
                      >
                        Hide here
                      </Button>
                    </>
                  ) : (
                    <>
                      {!e.hidden && (
                        <Button size="sm" variant="link" disabled={!allowed} onClick={() => setEditing({ entry: e })}>
                          Edit
                        </Button>
                      )}
                      <Button
                        size="sm"
                        variant="link"
                        disabled={!allowed}
                        onClick={() => run(() => source.remove(kind, e), "Couldn't revert it.")}
                      >
                        {e.hidden ? 'Show again' : e.overridesDefault ? 'Revert to default' : 'Remove'}
                      </Button>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <EntryModal
        config={config}
        inNetwork={inNetwork}
        editing={editing}
        onHide={() => setEditing(null)}
        onSave={async input => {
          await source.put(kind, input);
          setEditing(null);
          load();
          onChanged?.();
        }}
      />
    </div>
  );
}

function EntryModal({
  config,
  inNetwork,
  editing,
  onHide,
  onSave,
}: {
  config: KindConfig;
  inNetwork: boolean;
  editing: { entry?: AddressEntry } | null;
  onHide: () => void;
  onSave: (input: AddressEntryInput) => Promise<void>;
}) {
  const { kind } = config;
  const entry = editing?.entry;
  const [cidr, setCidr] = useState('');
  const [label, setLabel] = useState('');
  const [classification, setClassification] = useState<'PRIVATE' | 'PUBLIC'>('PRIVATE');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!editing) return;
    setCidr(entry?.cidr ?? '');
    setLabel(entry?.label ?? '');
    setClassification(entry?.classification ?? 'PRIVATE');
    setError(null);
  }, [editing, entry]);

  const overriding = inNetwork && entry?.scope === 'default';
  const title = !entry
    ? inNetwork ? 'Add for this network' : 'Add to the default'
    : overriding ? `Override ${entry.cidr} here` : `Edit ${entry.cidr}`;
  const needsLabel = kind !== 'custom-private-ranges';
  const valid = cidr.trim() !== '' && (!needsLabel || label.trim() !== '' || kind === 'subnets');

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await onSave(
        kind === 'custom-private-ranges'
          ? { cidr: cidr.trim(), classification }
          : { cidr: cidr.trim(), label: label.trim() || null },
      );
    } catch (e) {
      setError(apiMessage(e) ?? "Couldn't save it.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal show={!!editing} onHide={busy ? undefined : onHide} centered>
      <Modal.Header closeButton={!busy}>
        <Modal.Title style={{ fontSize: '1rem' }}>{title}</Modal.Title>
      </Modal.Header>
      <Modal.Body style={{ fontSize: '0.85rem' }}>
        {overriding && (
          <p className="text-muted small">
            The default says <strong>{valueOf(entry!, kind) || '—'}</strong>. What you set here applies in this
            network only; the default stays as it is everywhere else.
          </p>
        )}
        <Form.Group className="mb-3">
          <Form.Label htmlFor="address-cidr" className="small text-muted mb-1">
            CIDR or address
          </Form.Label>
          <Form.Control
            id="address-cidr"
            className="font-monospace"
            value={cidr}
            disabled={!!entry}
            placeholder="e.g. 10.20.0.0/16"
            onChange={e => setCidr(e.target.value)}
          />
        </Form.Group>
        {kind === 'custom-private-ranges' ? (
          <Form.Group>
            <Form.Label className="small text-muted mb-1">Treat as</Form.Label>
            <Form.Check
              type="radio"
              id="address-internal"
              name="address-classification"
              label="Internal"
              checked={classification === 'PRIVATE'}
              onChange={() => setClassification('PRIVATE')}
            />
            <Form.Check
              type="radio"
              id="address-external"
              name="address-classification"
              label="External"
              checked={classification === 'PUBLIC'}
              onChange={() => setClassification('PUBLIC')}
            />
          </Form.Group>
        ) : (
          <Form.Group>
            <Form.Label htmlFor="address-label" className="small text-muted mb-1">
              {config.valueLabel}
            </Form.Label>
            <Form.Control
              id="address-label"
              value={label}
              maxLength={100}
              onChange={e => setLabel(e.target.value)}
              placeholder={kind === 'subnets' ? 'e.g. HQ servers' : 'e.g. Branch office'}
            />
          </Form.Group>
        )}
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
        <Button variant="primary" onClick={submit} disabled={busy || !valid}>
          Save
        </Button>
      </Modal.Footer>
    </Modal>
  );
}
