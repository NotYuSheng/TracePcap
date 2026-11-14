import { useEffect, useState } from 'react';
import { Alert } from '@components/common/Alert';
import {
  networkSegmentService,
  type NetworkSegment,
  type NetworkSegmentOverlap,
  type NetworkSegments,
} from './networkSegmentService';

const CLIENTS_SHOWN = 8;

/** 3600 → "1 h", 86400 → "1 day". */
export function leaseText(seconds: number): string {
  if (seconds % 86400 === 0) return `${seconds / 86400} day${seconds === 86400 ? '' : 's'}`;
  if (seconds % 3600 === 0) return `${seconds / 3600} h`;
  if (seconds % 60 === 0) return `${seconds / 60} min`;
  return `${seconds} s`;
}

/**
 * Two or more networks using the same range in one capture (#462): two sites or two VLANs both on
 * 192.168.1.0/24. Shown only then. Says what told them apart and which addresses are on both,
 * since each of those is a different machine per network.
 */
export function NetworkSegmentsPanel({ fileId }: { fileId: string }) {
  const [data, setData] = useState<NetworkSegments | null>(null);

  useEffect(() => {
    let alive = true;
    networkSegmentService
      .get(fileId)
      .then(d => {
        if (alive) setData(d);
      })
      .catch(() => {
        if (alive) setData(null);
      });
    return () => {
      alive = false;
    };
  }, [fileId]);

  if (!data || data.overlaps.length === 0) return null;
  const byKey = new Map(data.segments.map(s => [s.key, s]));

  return (
    <div className="mt-4" data-testid="network-segments">
      {data.overlaps.map(o => (
        <Overlap key={o.segmentKeys.join('+')} overlap={o} segments={o.segmentKeys.map(k => byKey.get(k)!).filter(Boolean)} />
      ))}
    </div>
  );
}

function Overlap({ overlap, segments }: { overlap: NetworkSegmentOverlap; segments: NetworkSegment[] }) {
  const byVlan = segments.every(s => s.vlanId != null);
  return (
    <div className="card">
      <div className="card-body">
        <h5 className="card-title mb-1">
          {segments.length} networks share {overlap.cidr ?? 'one range'}
        </h5>
        <p className="text-muted small mb-3">
          This capture holds {segments.length} separate networks that use the same addresses, as two sites or
          two VLANs can. They were told apart by{' '}
          {byVlan ? 'their VLAN tags and ' : ''}the DHCP server that leased each address.
        </p>

        <div className="row g-3 mb-3">
          {segments.map(s => (
            <div key={s.key} className="col-md-6" data-testid="network-segment">
              <div className="border rounded p-3 h-100 small">
                <h6 className="mb-2">{s.label}</h6>
                <dl className="row mb-2" style={{ rowGap: 2 }}>
                  {s.vlanId != null && (
                    <>
                      <dt className="col-5 text-muted fw-normal">VLAN</dt>
                      <dd className="col-7 mb-0">{s.vlanId}</dd>
                    </>
                  )}
                  {s.routers.length > 0 && (
                    <>
                      <dt className="col-5 text-muted fw-normal">Router</dt>
                      <dd className="col-7 mb-0 font-monospace">{s.routers.join(', ')}</dd>
                    </>
                  )}
                  {s.serverMac && (
                    <>
                      <dt className="col-5 text-muted fw-normal">DHCP server MAC</dt>
                      <dd className="col-7 mb-0 font-monospace">{s.serverMac}</dd>
                    </>
                  )}
                  {s.domains.length > 0 && (
                    <>
                      <dt className="col-5 text-muted fw-normal">Domain</dt>
                      <dd className="col-7 mb-0">{s.domains.join(', ')}</dd>
                    </>
                  )}
                  {s.leaseSeconds.length > 0 && (
                    <>
                      <dt className="col-5 text-muted fw-normal">Lease time</dt>
                      <dd className="col-7 mb-0">{s.leaseSeconds.map(leaseText).join(', ')}</dd>
                    </>
                  )}
                </dl>
                <Clients segment={s} />
              </div>
            </div>
          ))}
        </div>

        {overlap.sharedAddresses.length > 0 && (
          <Alert variant="warning" className="small py-2 mb-0" data-testid="network-segments-shared">
            <strong>
              {overlap.sharedAddresses.length} address{overlap.sharedAddresses.length === 1 ? ' is' : 'es are'} used on
              more than one of these networks:
            </strong>{' '}
            <span className="font-monospace">{overlap.sharedAddresses.join(', ')}</span>. Each is a different machine
            on each network, and TracePcap keeps them apart: one device per network, with its own node in the graph,
            its own classification and its own labels.
          </Alert>
        )}
      </div>
    </div>
  );
}

function Clients({ segment }: { segment: NetworkSegment }) {
  const [all, setAll] = useState(false);
  const shown = all ? segment.clients : segment.clients.slice(0, CLIENTS_SHOWN);
  return (
    <div>
      <div className="text-muted mb-1">
        {segment.clients.length} DHCP client{segment.clients.length === 1 ? '' : 's'}
      </div>
      <ul className="list-unstyled mb-0">
        {shown.map(c => (
          <li key={c.mac}>
            <span className="font-monospace">{c.ip}</span>
            {c.hostname && <> · {c.hostname}</>}
            <span className="text-muted font-monospace"> · {c.mac}</span>
          </li>
        ))}
      </ul>
      {segment.clients.length > CLIENTS_SHOWN && (
        <button type="button" className="btn btn-link btn-sm p-0" onClick={() => setAll(a => !a)}>
          {all ? 'Show fewer' : `Show all ${segment.clients.length}`}
        </button>
      )}
    </div>
  );
}
