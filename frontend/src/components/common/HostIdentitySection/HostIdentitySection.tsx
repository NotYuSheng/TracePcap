import { useEffect, useRef, useState } from 'react';
import { Modal } from '@govtechsg/sgds-react';
import { AdjudicationPanel } from '@components/common/AdjudicationPanel/AdjudicationPanel';
import {
  AXIS_ORDER,
  AXIS_META,
  detectAxisConflict,
  axisFacts,
  type AxisKey,
} from '@/features/network/classificationAxes';
import type { NodeData, NodeType } from '@/features/network/types';
import { DEVICE_TYPES, deviceTypeLabel } from '@/utils/deviceType';
import { conversationService } from '@/features/conversation/services/conversationService';
import type { DeviceType, HostIdentityEvidence } from '@/types';
import { Spinner } from '@components/common/Spinner/Spinner';

/** Predefined override/evidence label options for the Identity panel (matches NodeDetails). */
const DEVICE_LABELS = DEVICE_TYPES.filter(t => t !== 'UNKNOWN').map(deviceTypeLabel);

/**
 * The observed-service nodeType for the conflict check, derived from confirmed service roles. This is
 * deliberately the *service* signal (what the host served), NOT the identity verdict — the whole
 * point of the conflict banner is to notice when the two disagree (#499).
 */
function nodeTypeFromServiceRoles(roles: string[]): NodeType {
  if (roles.includes('dns')) return 'dns-server';
  if (roles.includes('web')) return 'web-server';
  if (roles.includes('api')) return 'web-server';
  return 'unknown';
}

/** ISO country code → flag emoji (regional indicators). */
function countryFlag(code: string): string {
  return code
    .toUpperCase()
    .split('')
    .map(c => String.fromCodePoint(0x1f1e6 + c.charCodeAt(0) - 65))
    .join('');
}

/** Which geo resolver answered — provenance the user can judge (online ipinfo vs bundled offline DB). */
const GEO_SOURCE_LABEL: Record<string, { label: string; title: string }> = {
  ipinfo: {
    label: 'ipinfo.io',
    title: 'Resolved online via the ipinfo.io API (cached locally). Includes ASN/org.',
  },
  mmdb: {
    label: 'Offline DB',
    title: 'Resolved from the bundled DB-IP Lite database (offline, or ipinfo unreachable). Accuracy may be lower, especially for cloud IPs.',
  },
};

/**
 * Geolocation block for external hosts — the country/flag, ASN, org and geo-source provenance the
 * conversation modal used to be the only place to see. Rendered only when the host has a geo record
 * (private/internal IPs never do, so the block is simply absent for them).
 */
function GeoBlock({ ev }: { ev: HostIdentityEvidence }) {
  if (!ev.countryCode && !ev.country && !ev.asn && !ev.org) return null;
  const src = ev.geoSource ? GEO_SOURCE_LABEL[ev.geoSource] : undefined;
  return (
    <div className="mb-4">
      <h6 className="border-bottom pb-1 mb-2">
        <span className="text-muted fw-normal" style={{ fontSize: '0.8rem' }}>Geolocation</span>
      </h6>
      <dl className="row mb-0" style={{ fontSize: '0.8rem' }}>
        <dt className="col-4 text-muted fw-normal">Country</dt>
        <dd className="col-8 mb-1">
          {ev.countryCode ? (
            <>
              {countryFlag(ev.countryCode)} {ev.country ?? ev.countryCode} ({ev.countryCode})
            </>
          ) : (
            <span className="text-muted fst-italic">Unknown</span>
          )}
          {src && (
            <span
              className="badge ms-2 align-middle"
              style={{ backgroundColor: ev.geoSource === 'ipinfo' ? '#198754' : '#6c757d', fontSize: '0.65rem' }}
              title={src.title}
            >
              {src.label}
            </span>
          )}
        </dd>
        {ev.asn && (
          <>
            <dt className="col-4 text-muted fw-normal">ASN</dt>
            <dd className="col-8 mb-1 font-monospace">{ev.asn}</dd>
          </>
        )}
        {ev.org && (
          <>
            <dt className="col-4 text-muted fw-normal">Organisation</dt>
            <dd className="col-8 mb-1">{ev.org}</dd>
          </>
        )}
      </dl>
      <p className="text-muted fst-italic mt-1 mb-0" style={{ fontSize: '0.68rem' }}>
        Inferred from a geo database — the address range’s registration, not the device’s true location.
      </p>
    </div>
  );
}

/**
 * Adapts the flat evidence DTO into the partial {@link NodeData} shape the axis helpers already read,
 * so `axisFacts` / `detectAxisConflict` stay a single tested implementation rather than being
 * duplicated for a second data source.
 */
function toNodeData(ev: HostIdentityEvidence): NodeData {
  return {
    ip: ev.ip,
    manufacturer: ev.manufacturer ?? undefined,
    ttl: ev.ttl ?? undefined,
    serviceRoles: ev.serviceRoles,
    nodeTypeEvidence: { ndpiApps: ev.ndpiApps },
    initiatedConversations: ev.initiatedConversations,
    answeredConversations: ev.answeredConversations,
    conversationCount: ev.conversationCount,
    peerCount: ev.peerCount,
    nodeType: nodeTypeFromServiceRoles(ev.serviceRoles),
    deviceType:
      ev.basis === 'HUMAN' ? undefined : (ev.primaryLabel as DeviceType | undefined),
    // Fields the axis helpers never read — filled to satisfy the type.
    packetsSent: 0,
    packetsReceived: 0,
    bytesSent: 0,
    bytesReceived: 0,
    totalBytes: 0,
    role: 'unknown',
    protocols: [],
    connections: 0,
  };
}

interface Props {
  fileId: string;
  ip: string;
  /** Z-index of a surrounding raised modal, so the add-evidence popup stacks above it. */
  zIndex?: number;
  /** Called after an override/evidence change, so a parent (e.g. the graph) can refresh its copy. */
  onChanged?: () => void;
}

/**
 * The shared "verdict, and why" host-classification block (#556 follow-up): the adjudicated Identity
 * (with override / evidence tools) plus the three measured evidence axes and the conflict banner.
 *
 * <p>This is the block that used to live only inside NodeDetails. Promoting it here — fed by a
 * fileId+ip evidence fetch — lets the conversation host click, the monitor drift panels, and the
 * graph node all render the same explainable classification, so users see how a verdict was derived
 * and can correct or append to it everywhere, not only in the graph.
 */
export function HostIdentitySection({ fileId, ip, zIndex, onChanged }: Props) {
  const [evidence, setEvidence] = useState<HostIdentityEvidence | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedAxis, setExpandedAxis] = useState<AxisKey | null>(null);
  const [evidenceInfoOpen, setEvidenceInfoOpen] = useState(false);

  // Guard against a slow response landing after the section has moved to another host.
  const currentIpRef = useRef(ip);
  currentIpRef.current = ip;

  const load = () => {
    setLoading(true);
    setError(null);
    conversationService
      .getHostIdentityEvidence(fileId, ip)
      .then(ev => {
        if (ip !== currentIpRef.current) return;
        setEvidence(ev);
      })
      .catch(() => {
        if (ip !== currentIpRef.current) return;
        setError('Could not load this host’s classification.');
      })
      .finally(() => {
        if (ip === currentIpRef.current) setLoading(false);
      });
  };

  useEffect(() => {
    setExpandedAxis(null);
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fileId, ip]);

  const handleChanged = () => {
    // Re-fetch our own copy so the verdict reflects the override, then let the parent refresh too.
    load();
    onChanged?.();
  };

  if (loading) {
    return (
      <div className="mb-4 text-muted small d-flex align-items-center gap-2">
        <Spinner size="sm" /> Loading classification…
      </div>
    );
  }
  if (error || !evidence) {
    return <p className="mb-4 text-muted small fst-italic">{error ?? 'No classification available.'}</p>;
  }

  const nodeData = toNodeData(evidence);

  return (
    <>
      {/* Adjudicated identity — verdict, override, evidence, "why". */}
      <AdjudicationPanel
        fileId={fileId}
        question="host-identity"
        entityKey={ip}
        title="Identity"
        labelOptions={DEVICE_LABELS}
        zIndex={zIndex}
        verdict={{
          label: evidence.primaryLabel ?? 'Unknown',
          basis: evidence.basis,
          confidence: evidence.confidence,
          contested: evidence.contested,
          candidates: evidence.candidates ?? undefined,
        }}
        onChanged={handleChanged}
      />

      {/* Evidence weighed — the independent measured signals behind the verdict. */}
      <div className="mb-4">
        <h6 className="border-bottom pb-1 mb-2 d-flex align-items-center">
          <span className="text-muted fw-normal" style={{ fontSize: '0.8rem' }}>
            Evidence weighed
          </span>
          <button
            type="button"
            aria-label="How Identity and this evidence relate"
            className="btn btn-link p-0 ms-1 text-muted"
            style={{ fontSize: '0.8rem', lineHeight: 1 }}
            onClick={e => {
              e.stopPropagation();
              setEvidenceInfoOpen(true);
            }}
          >
            <i className="bi bi-info-circle" aria-hidden="true" />
          </button>
        </h6>
        {AXIS_ORDER.map(key => {
          const meta = AXIS_META[key];
          const facts = axisFacts(nodeData, key);
          const expanded = expandedAxis === key;
          return (
            <div key={key} className="mb-1">
              <div
                role="button"
                tabIndex={0}
                aria-expanded={expanded}
                title={`Inspect ${meta.label} — ${meta.caption}`}
                className="d-flex align-items-center gap-2"
                style={{ fontSize: '0.8rem', cursor: 'pointer' }}
                onClick={e => {
                  e.stopPropagation();
                  setExpandedAxis(expanded ? null : key);
                }}
                onKeyDown={e => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    e.stopPropagation();
                    setExpandedAxis(expanded ? null : key);
                  }
                }}
              >
                <span className="text-muted" style={{ minWidth: '100px' }}>{meta.label}</span>
                {facts.length > 0 ? (
                  <span className="flex-grow-1">{facts.join(' · ')}</span>
                ) : (
                  <span className="text-muted fst-italic flex-grow-1">Nothing observed</span>
                )}
                <i className={`bi text-muted ${expanded ? 'bi-chevron-up' : 'bi-chevron-down'}`} aria-hidden="true" />
              </div>
              {expanded && (
                <div className="mt-2 ms-2 ps-2 border-start text-muted" style={{ fontSize: '0.72rem' }}>
                  {meta.derivation}
                </div>
              )}
            </div>
          );
        })}
        {(() => {
          const humanVerdict = evidence.basis === 'HUMAN';
          const { conflict, detail } = detectAxisConflict(
            humanVerdict ? { ...nodeData, deviceType: undefined } : nodeData,
          );
          return conflict ? (
            <div
              className="d-flex align-items-start gap-1 mt-2 text-warning-emphasis"
              style={{ fontSize: '0.72rem' }}
            >
              <i className="bi bi-exclamation-triangle-fill mt-1" aria-hidden="true" />
              <span>
                <strong>Evidence conflicts.</strong> {detail} Worth a look — if the service
                evidence is right, correct Identity with <em>“I disagree”</em>.
              </span>
            </div>
          ) : null;
        })()}
      </div>

      {/* Geolocation — external-host country/ASN/org, restored from the old conversation modal. */}
      <GeoBlock ev={evidence} />

      {/* Explainer modal — how Identity and the evidence axes relate (#499). */}
      <Modal show={evidenceInfoOpen} onHide={() => setEvidenceInfoOpen(false)} centered
        className={zIndex != null ? 'tp-nested-modal' : undefined}
        backdropClassName={zIndex != null ? 'tp-nested-modal-backdrop' : undefined}>
        <Modal.Header closeButton>
          <Modal.Title style={{ fontSize: '1rem' }}>How this host is classified</Modal.Title>
        </Modal.Header>
        <Modal.Body style={{ fontSize: '0.85rem' }}>
          <p>
            <strong>Identity</strong> is the one answer to “what is this host?” — the adjudicated
            verdict. Its confidence and the per-candidate score breakdown live in the Identity panel’s
            “Why”.
          </p>
          <p className="mb-0">
            The <strong>evidence axes</strong> in this panel are the independent measured facts the
            verdict weighed — <em>Hardware</em> (physical fingerprint), <em>Ports / Service</em> (what it did
            on the wire), and <em>Behaviour</em> (who opened the connections). They carry facts only;
            the scores belong to Identity. Disagree with the verdict? Use “I disagree” to set it, or
            add evidence to feed the vote.
          </p>
        </Modal.Body>
      </Modal>
    </>
  );
}
