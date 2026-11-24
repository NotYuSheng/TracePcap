import { RuleScopeTag } from '@/features/detectionRules/RuleScopeTag';
import { Fragment, useState, useMemo, useEffect, useRef, useCallback } from 'react';
import { SuricataRulesetNote } from '@components/common/SuricataRulesetNote';
import { Badge, Button, Card } from '@govtechsg/sgds-react';
import { createPortal } from 'react-dom';
import { useNavigate } from 'react-router-dom';
import type { Conversation, ConversationGeoInfo, HostClassification, HostIdentity, IdsAlert, TlsCertificate } from '@/types';
import { groupIdsAlerts } from './idsAlertGroups';
import { getExtractionsByConversation } from '@features/extractedFiles/services/extractedFilesService';
import { conversationService } from '@/features/conversation/services/conversationService';
import { formatBytes, formatTimestamp, formatIpPort } from '@/utils/formatters';
import {
  getAppColor,
  getTextColor,
  getSeverityColor,
  RISK_BADGE,
  IDS_BADGE,
} from '@/utils/appColors';
import { getProtocolColor } from '@/features/network/constants';
import { deviceTypeLabel, deviceTypeColor, deviceTypeIcon } from '@/utils/deviceType';
import { useEscapeLayer } from '@/utils/useEscapeLayer';
import { Pagination } from '@components/common/Pagination/Pagination';
import { HexViewer } from '../HexViewer/HexViewer';
import { SessionTab } from '../SessionTab/SessionTab';
import { HostDetailModal } from '@components/common/EntityDetailModal';
import { isPrivateIp } from '@/utils/ipClassification';
import type { DeviceType } from '@/types';
import './ConversationDetail.css';
import { CONNECTION_OUTCOME_WORDS } from '@/features/conversation/connectionOutcome';

interface ConversationDetailProps {
  conversation: Conversation;
  signatureSeverities?: Record<string, string>;
  /** Rule name → scope, shown in each badge (#925 phase 3). */
  signatureScopes?: Record<string, string>;
  hostClassMap?: Map<string, HostClassification>;
  fileId?: string;
  /** When set, the packet with this frame number is scrolled into view and briefly highlighted. */
  highlightPacketNumber?: number | null;
  /** Docked in a pane that already has its own frame and title: drop the outer card. */
  bare?: boolean;
}

function countryFlag(code: string): string {
  return code
    .toUpperCase()
    .split('')
    .map(c => String.fromCodePoint(0x1f1e6 + c.charCodeAt(0) - 65))
    .join('');
}

const GEO_SOURCE_INFO: Record<string, { label: string; title: string; description: string; bg: string }> = {
  ipinfo: {
    label: 'ipinfo.io',
    title: 'Geo source: ipinfo.io',
    description: 'Location was resolved by calling the ipinfo.io API, which this install has opted in to (GEO_FORCE_OFFLINE=false). Results are cached locally so repeat lookups do not require another API call.',
    bg: '#198754',
  },
  mmdb: {
    label: 'Offline DB',
    title: 'Geo source: Offline database',
    description: 'Location was resolved using the bundled DB-IP Lite database, the default: nothing leaves this machine. Accuracy may be lower, especially for cloud provider IPs.',
    bg: '#6c757d',
  },
};

const GEO_SOURCE_FALLBACK = GEO_SOURCE_INFO.mmdb;

function GeoSourceBadge({ source }: { source?: string }) {
  const [popoverPos, setPopoverPos] = useState<{ top: number; left: number } | null>(null);
  const popoverRef = useRef<HTMLDivElement>(null);
  const info = (source ? GEO_SOURCE_INFO[source] : undefined) ?? GEO_SOURCE_FALLBACK;

  useEscapeLayer(() => setPopoverPos(null), { enabled: popoverPos !== null, ref: popoverRef });

  const handleClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (popoverPos) { setPopoverPos(null); return; }
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
    const popW = 260;
    const popH = 120;
    const left = Math.min(rect.right - popW, window.innerWidth - popW - 8);
    const top = rect.bottom + 6 + popH > window.innerHeight
      ? rect.top - popH - 6
      : rect.bottom + 6;
    setPopoverPos({ top, left: Math.max(8, left) });
  };

  return (
    <>
      <Badge
        className="ms-2"
        style={{ backgroundColor: info.bg, color: '#fff', fontSize: '0.7em', cursor: 'pointer' }}
        onClick={handleClick}
      >
        {info.label}
      </Badge>
      {popoverPos && createPortal(
        <div
          ref={popoverRef}
          style={{
            position: 'fixed',
            top: popoverPos.top,
            left: popoverPos.left,
            zIndex: 9999,
            background: 'var(--tp-surface)',
            border: '1px solid var(--tp-border)',
            borderRadius: 6,
            boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
            padding: '10px 12px',
            width: 260,
            fontSize: 11,
            color: 'var(--tp-text)',
          }}
          onClick={e => e.stopPropagation()}
        >
          <div className="fw-semibold mb-1" style={{ fontSize: 12 }}>{info.title}</div>
          <div className="text-muted">{info.description}</div>
          <div className="text-end mt-2">
            <Button size="sm" variant="outline-secondary" style={{ fontSize: 10, padding: '1px 8px' }} onClick={() => setPopoverPos(null)}>Close</Button>
          </div>
        </div>,
        document.body
      )}
    </>
  );
}

function GeoInfoRows({ geo, label, ip }: { geo?: ConversationGeoInfo; label: string; ip: string }) {
  if (!geo?.countryCode) {
    if (!isPrivateIp(ip)) return null;
    return (
      <>
        <dt>{label}</dt>
        <dd><span className="text-muted">Internal (private)</span></dd>
      </>
    );
  }
  return (
    <>
      <dt>{label}</dt>
      <dd>
        {countryFlag(geo.countryCode)} {geo.country} ({geo.countryCode})
        {geo.asn && <small className="text-muted ms-2">{geo.asn}</small>}
        <GeoSourceBadge source={geo.geoSource} />
        {geo.org && <small className="text-muted d-block">{geo.org}</small>}
      </dd>
    </>
  );
}

const confidenceWord = (pct: number): string =>
  pct >= 75 ? 'Strong' : pct >= 50 ? 'Moderate' : pct >= 25 ? 'Low' : 'Uncertain';

/**
 * One host in the conversation flow header — its role in this conversation, address, and adjudicated
 * identity. The whole card is a button that opens the shared host-detail modal (identity + evidence
 * axes + adjudication), so the analyst sees how the classification was derived and can correct it —
 * the same panel the network graph uses, rather than a stripped-down popup (#556 follow-up).
 */
function HostFlowCard({
  ip,
  port,
  role,
  hostname,
  cls,
  identity,
  onOpen,
}: {
  ip: string;
  port: number | null;
  role: 'client' | 'server';
  hostname?: string;
  cls?: HostClassification;
  identity?: HostIdentity;
  /** Opens the full host-detail modal. Omitted when there is no fileId to load it — the card then
   *  renders non-interactive rather than as a button whose click silently does nothing. */
  onOpen?: () => void;
}) {
  // Prefer the adjudicated verdict; fall back to the raw device type when identities haven't loaded.
  // A machine verdict's primaryLabel is a DeviceType code ("LAPTOP_DESKTOP"): show it in words.
  const label = identity?.primaryLabel
    ? identity.basis === 'HUMAN'
      ? identity.primaryLabel
      : deviceTypeLabel(identity.primaryLabel as DeviceType)
    : cls
      ? deviceTypeLabel(cls.deviceType)
      : null;
  // primaryLabel is only a DeviceType code for MACHINE verdicts; a HUMAN label (e.g. "Bob's Laptop")
  // is free text, so it must not be cast to DeviceType or the icon/colour lookup gets garbage. Fall
  // back to the machine classification's deviceType for the icon in that case.
  const deviceType = (
    identity && identity.basis !== 'HUMAN' ? identity.primaryLabel : cls?.deviceType
  ) as DeviceType | undefined;
  const confidence = identity?.confidence ?? cls?.confidence;
  const contested = identity?.contested ?? false;
  const iconColor = deviceType ? deviceTypeColor(deviceType) : '#6b7280';

  const inner = (
    <>
      {confidence != null && !contested && identity?.basis !== 'HUMAN' && (
        <span className="cd-conf-pill">{confidence}% {confidenceWord(confidence)}</span>
      )}
      <span className={`cd-host-role cd-role-${role}`}>
        {role === 'client' ? 'Client · initiated' : 'Server · responded'}
      </span>
      <span className="cd-host-ip">{formatIpPort(ip, port ?? undefined)}</span>
      {hostname && <span className="cd-host-hostname">{hostname}</span>}
      {label && (
        <span className="cd-identity">
          <span className="cd-identity-ico" style={{ backgroundColor: iconColor }}>
            <i className={`bi ${deviceType ? deviceTypeIcon(deviceType) : 'bi-question-circle'}`} aria-hidden="true" />
          </span>
          <span className="cd-identity-who">
            <strong>{label}</strong>
            <small className="text-muted">
              {contested ? (
                <span className="cd-contested"><i className="bi bi-exclamation-triangle" aria-hidden="true" /> contested</span>
              ) : identity?.basis === 'HUMAN' ? 'Identity · confirmed' : 'Identity'}
            </small>
          </span>
        </span>
      )}
      {onOpen && <span className="cd-host-open">Open full host details →</span>}
    </>
  );

  // Interactive only when there is a modal to open (needs a fileId). Otherwise a plain, non-focusable
  // card so the click affordance is never a dead end.
  return onOpen ? (
    <button type="button" className="cd-host" onClick={onOpen} aria-label={`Open full details for ${ip}`}>
      {inner}
    </button>
  ) : (
    <div className="cd-host cd-host-static">{inner}</div>
  );
}

/** A collapsible group of conversation metadata rows — replaces the flat dt/dd wall. */
/**
 * The server certificate's own detail (#1235). The verdicts (weak key, weak signature, name not
 * covered) come from the backend; this only words them.
 */
function TlsCertificateRows({ cert }: { cert: TlsCertificate }) {
  const MAX_SHOWN = 6;
  return (
    <>
      {cert.keyType && (
        <>
          <dt>Key</dt>
          <dd data-testid="tls-cert-key">
            <small>
              {cert.keyType}
              {cert.keyBits ? ` ${cert.keyBits}-bit` : ''}
            </small>
            {cert.weakKey && <Badge bg="danger" className="ms-1">Weak key</Badge>}
          </dd>
        </>
      )}
      {cert.signatureAlgorithm && (
        <>
          <dt>Signature</dt>
          <dd>
            <small>{cert.signatureAlgorithm}</small>
            {cert.weakSignature && <Badge bg="danger" className="ms-1">SHA-1/MD5</Badge>}
          </dd>
        </>
      )}
      <dt>Signed by</dt>
      <dd data-testid="tls-cert-signer">
        {cert.selfSigned ? (
          <Badge bg="warning" text="dark">Self-signed</Badge>
        ) : (
          <small>
            A CA ({cert.chainLength} certificate{cert.chainLength === 1 ? '' : 's'} sent)
          </small>
        )}
      </dd>
      {cert.sans.length > 0 && (
        <>
          <dt>Names</dt>
          <dd data-testid="tls-cert-sans">
            <small className="text-break">
              {cert.sans.slice(0, MAX_SHOWN).join(', ')}
              {cert.sans.length > MAX_SHOWN && ` +${cert.sans.length - MAX_SHOWN} more`}
            </small>
            {cert.coversServerName === false && (
              <Badge bg="danger" className="ms-1">Doesn't cover the server name</Badge>
            )}
          </dd>
        </>
      )}
    </>
  );
}

/** The rule's own rating, as a chip colour; unknown ratings read as neutral. */
const SIGNATURE_SEVERITY_BG: Record<string, string> = {
  Critical: '#b02a37',
  Major: '#b35900',
  Minor: '#0a58ca',
  Informational: '#6c757d',
};

/** A small rating chip, matching the grade chips of the Investigation Summary. */
function RatingChip({ bg, children }: { bg?: string; children: React.ReactNode }) {
  return (
    <span
      style={{
        fontSize: 10,
        fontWeight: 600,
        whiteSpace: 'nowrap',
        borderRadius: 3,
        padding: '1px 6px',
        ...(bg
          ? { color: '#fff', background: bg }
          : { color: 'var(--bs-secondary-color, #6c757d)', border: '1px solid var(--bs-border-color, #dee2e6)' }),
      }}
    >
      {children}
    </span>
  );
}

/**
 * Each Suricata alert on the conversation as it fired (#1265): when, which side sent the packet,
 * the rule's own rating and confidence, and the HTTP request it fired on.
 */
function IdsAlertRows({ alerts, clientIp }: { alerts: IdsAlert[]; clientIp: string }) {
  const groups = groupIdsAlerts(alerts);
  return (
    <ul className="list-unstyled mb-0 d-flex flex-column gap-2" data-testid="ids-alerts">
      {groups.map((g, i) => {
        const a = g.first;
        const fromServer = a.srcIp != null && a.srcIp !== clientIp;
        return (
          <li key={i} className="border-bottom pb-2">
            <div className="d-flex align-items-start gap-2 flex-wrap">
              <small className="fw-semibold text-break flex-grow-1" style={{ minWidth: 0 }}>{a.signature}</small>
              {a.signatureSeverity && (
                <RatingChip bg={SIGNATURE_SEVERITY_BG[a.signatureSeverity] ?? '#6c757d'}>{a.signatureSeverity}</RatingChip>
              )}
              {a.confidence && <RatingChip>{a.confidence} confidence</RatingChip>}
            </div>
            <div className="text-muted" style={{ fontSize: '0.75rem' }}>
              {a.category && <span>{a.category} · </span>}
              <span>{fromServer ? 'on the server\'s reply' : 'on the client\'s request'}</span>
              <span> · sid {a.sid}</span>
              {g.from != null && (
                <span>
                  {' · '}
                  {g.count > 1
                    ? `${g.count}× from ${formatTimestamp(g.from)} to ${formatTimestamp(g.to!)}`
                    : formatTimestamp(g.from)}
                </span>
              )}
              {g.from == null && g.count > 1 && <span> · {g.count}×</span>}
            </div>
            {a.httpUrl && (
              <div style={{ fontSize: '0.75rem', overflowWrap: 'anywhere' }} data-testid="ids-alert-request">
                <code>
                  {a.httpMethod ? `${a.httpMethod} ` : ''}
                  {a.httpUrl}
                </code>
                {a.httpStatus != null && <span className="text-muted"> → {a.httpStatus}</span>}
              </div>
            )}
          </li>
        );
      })}
    </ul>
  );
}

function MetaGroup({
  title,
  note,
  defaultOpen = false,
  children,
}: {
  title: string;
  note?: string;
  defaultOpen?: boolean;
  children: React.ReactNode;
}) {
  return (
    <details className="cd-group" open={defaultOpen}>
      <summary>
        <span>{title}</span>
        {note && <span className="cd-group-note">{note}</span>}
        <i className="bi bi-chevron-right cd-group-chev" aria-hidden="true" />
      </summary>
      <div className="cd-group-body">{children}</div>
    </details>
  );
}

const PRINTABLE_ASCII_THRESHOLD = 0.3;

/** Returns true if more than 30% of the first 256 bytes are printable ASCII (0x20–0x7e). */
function hasReadableAscii(hex: string): boolean {
  if (!hex || hex.length < 4) return false;
  const sample = hex.slice(0, 512); // check at most 256 bytes
  let printable = 0;
  const total = sample.length / 2;
  for (let i = 0; i < sample.length; i += 2) {
    const byte = parseInt(sample.slice(i, i + 2), 16);
    if (byte >= 0x20 && byte <= 0x7e) printable++;
  }
  return printable / total > PRINTABLE_ASCII_THRESHOLD;
}

export const ConversationDetail = ({
  conversation,
  signatureSeverities = {},
  signatureScopes = {},
  hostClassMap,
  fileId,
  highlightPacketNumber,
  bare,
}: ConversationDetailProps) => {
  const navigate = useNavigate();
  const [source, destination] = conversation.endpoints;
  const srcClass = hostClassMap?.get(source.ip);
  const dstClass = hostClassMap?.get(destination.ip);
  const [activeTab, setActiveTab] = useState<'packets' | 'session'>('packets');
  const [extractedCount, setExtractedCount] = useState<number | null>(null);
  const [expandedPacketId, setExpandedPacketId] = useState<string | null>(null);
  // IP whose full host-detail modal (identity + axes + adjudication) is open, or null.
  const [hostModalIp, setHostModalIp] = useState<string | null>(null);
  // Adjudicated identity per host in this file — feeds the flow-header identity chip. The axes and
  // adjudication tools live in the click-through modal, so this is the only extra fetch we need.
  const [identityMap, setIdentityMap] = useState<Map<string, HostIdentity>>(new Map());
  const [packetPage, setPacketPage] = useState(1);
  const [packetPageSize, setPacketPageSize] = useState(50);
  const highlightRowRef = useRef<HTMLTableRowElement>(null);

  const allPackets = conversation.packets ?? [];
  const packetTotalPages = Math.ceil(allPackets.length / packetPageSize);
  const packetPageClamped = Math.min(packetPage, Math.max(1, packetTotalPages));
  const visiblePackets = allPackets.slice(
    (packetPageClamped - 1) * packetPageSize,
    packetPageClamped * packetPageSize,
  );

  // Switching conversations: reset the packet page and collapse any expanded hex row so the new
  // conversation starts at page 1. Declared before the highlight effect so a deep-link's page jump
  // still wins when both run on a conversation change.
  useEffect(() => {
    setPacketPage(1);
    setExpandedPacketId(null);
  }, [conversation.id]);

  // When deep-linked to a specific packet, switch to the Packets tab, jump to the page that
  // contains it, and scroll it into view.
  useEffect(() => {
    if (highlightPacketNumber == null) return;
    setActiveTab('packets');
    const idx = allPackets.findIndex(p => p.packetNumber === highlightPacketNumber);
    if (idx >= 0) setPacketPage(Math.floor(idx / packetPageSize) + 1);
    const t = setTimeout(() => {
      highlightRowRef.current?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }, 150);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [highlightPacketNumber, conversation.id, packetPageSize]);

  // Load adjudicated identities for the flow-header chips. Only the two endpoints are fetched, not
  // every host in the file (#576). Also re-run when the host-detail modal closes, so an in-modal
  // "I disagree" override is reflected in the chip without waiting for a remount.
  const sourceIp = source.ip;
  const destinationIp = destination.ip;
  const refreshIdentities = useCallback(() => {
    if (!fileId) return;
    conversationService
      .getHostIdentities(fileId, [sourceIp, destinationIp])
      .then(list => setIdentityMap(new Map(list.map(i => [i.ip, i]))))
      .catch(() => setIdentityMap(new Map()));
  }, [fileId, sourceIp, destinationIp]);

  useEffect(() => {
    refreshIdentities();
  }, [refreshIdentities]);

  useEffect(() => {
    if (!fileId) return;
    setExtractedCount(null);
    getExtractionsByConversation(fileId, conversation.id)
      .then(files => setExtractedCount(files.length))
      .catch(() => setExtractedCount(null));
  }, [fileId, conversation.id]);

  const asciiPacketIds = useMemo(() => {
    const ids = new Set<string>();
    for (const p of conversation.packets ?? []) {
      if (hasReadableAscii(p.payload)) ids.add(p.id);
    }
    return ids;
  }, [conversation.packets]);

  const togglePacket = (id: string) => setExpandedPacketId(prev => (prev === id ? null : id));

  return (
    <div className="conversation-detail">
      <Card className={bare ? 'mb-4 cd-bare' : 'mb-4'}>
        <Card.Header
          className={`d-flex align-items-center justify-content-between${bare && !(extractedCount && fileId) ? ' d-none' : ''}`}
        >
          <h5 className={bare ? 'visually-hidden' : 'mb-0'}>Conversation Details</h5>
          {extractedCount != null && extractedCount > 0 && fileId && (
            <Button
              size="sm"
              variant="outline-warning"
              onClick={() => navigate(`/analysis/${fileId}/extracted-files`)}
              title="Files extracted from this conversation's stream"
            >
              <i className="bi bi-file-earmark-arrow-down me-1"></i>
              {extractedCount} extracted file{extractedCount !== 1 ? 's' : ''}
            </Button>
          )}
        </Card.Header>
        <Card.Body>
          {/* Flow header — the two hosts facing each other across the connection. Each host opens
              the shared host-detail modal (identity + evidence axes + adjudication). */}
          <div className="cd-flow">
            <HostFlowCard
              ip={source.ip}
              port={source.port}
              role="client"
              cls={srcClass}
              identity={identityMap.get(source.ip)}
              onOpen={fileId ? () => setHostModalIp(source.ip) : undefined}
            />

            <div className="cd-connector">
              <span className="cd-conn-arrow" aria-hidden="true">→</span>
              {(() => {
                const bg = getProtocolColor(conversation.protocol.name);
                return (
                  <Badge style={{ backgroundColor: bg, color: getTextColor(bg) }}>
                    {conversation.protocol.name}
                    {conversation.tsharkProtocol && ` · ${conversation.tsharkProtocol}`}
                  </Badge>
                );
              })()}
              {conversation.appName && (
                <Badge style={{ backgroundColor: getAppColor(conversation.appName), color: getTextColor(getAppColor(conversation.appName)) }}>
                  {conversation.appName}
                </Badge>
              )}
              <span className="cd-conn-stats">
                {conversation.packetCount.toLocaleString()} pkts · {formatBytes(conversation.totalBytes)}
              </span>
            </div>

            <HostFlowCard
              ip={destination.ip}
              port={destination.port}
              role="server"
              hostname={conversation.hostname}
              cls={dstClass}
              identity={identityMap.get(destination.ip)}
              onOpen={fileId ? () => setHostModalIp(destination.ip) : undefined}
            />
          </div>

          {/* Security strip — flow risks / custom rules / IDS alerts, surfaced up top when present. */}
          {((conversation.flowRisks?.length ?? 0) > 0 ||
            (conversation.customSignatures?.length ?? 0) > 0 ||
            (conversation.suricataAlerts?.length ?? 0) > 0 ||
            (conversation.tlsNotAfter != null && conversation.tlsNotAfter < Date.now())) && (
            <div className="cd-sec-strip">
              <span className="cd-sec-lead"><i className="bi bi-exclamation-triangle-fill" /> Security signals</span>
              {conversation.flowRisks?.map(risk => (
                <span key={risk} className="cd-chip" style={{ backgroundColor: RISK_BADGE.bg, color: RISK_BADGE.text }}>{risk}</span>
              ))}
              {conversation.customSignatures?.map(rule => {
                const { bg, text } = getSeverityColor(signatureSeverities[rule]);
                return <span key={rule} className="cd-chip" style={{ backgroundColor: bg, color: text }}>{rule.replace(/_/g, ' ')}<RuleScopeTag scope={signatureScopes[rule]} /></span>;
              })}
              {conversation.suricataAlerts?.map(alert => (
                <span key={alert} className="cd-chip" style={{ backgroundColor: IDS_BADGE.bg, color: IDS_BADGE.text }}>{alert}</span>
              ))}
              {conversation.tlsNotAfter != null && conversation.tlsNotAfter < Date.now() && (
                <span className="cd-chip" style={{ backgroundColor: '#dc2626', color: '#fff' }}>Expired certificate</span>
              )}
              {(conversation.suricataAlerts?.length ?? 0) > 0 && <SuricataRulesetNote className="w-100 mt-1" />}
            </div>
          )}

          {/* Grouped metadata — scannable sections in place of the flat field wall. */}
          <div className="cd-groups">
            <MetaGroup title="Timing &amp; Volume" defaultOpen>
              <dl className="cd-kv">
                <dt>Packets</dt><dd>{conversation.packetCount.toLocaleString()}</dd>
                <dt>Bytes</dt><dd>{formatBytes(conversation.totalBytes)}</dd>
                {conversation.bytesSrcToDst != null && conversation.bytesDstToSrc != null && (
                  <>
                    {/* Which way the bytes went (#1260): a big download and an upload look
                        the same as a total, and only one of them is possible exfiltration. */}
                    <dt>Sent</dt>
                    <dd data-testid="bytes-src-to-dst">
                      {formatBytes(conversation.bytesSrcToDst)} <small className="text-muted">by {source.ip}</small>
                    </dd>
                    <dt>Received</dt>
                    <dd data-testid="bytes-dst-to-src">
                      {formatBytes(conversation.bytesDstToSrc)} <small className="text-muted">from {destination.ip}</small>
                    </dd>
                  </>
                )}
                <dt>Start</dt><dd>{formatTimestamp(conversation.startTime)}</dd>
                {conversation.connectionOutcome && (
                  <>
                    <dt>Connection</dt>
                    <dd data-testid="connection-outcome">
                      {CONNECTION_OUTCOME_WORDS[conversation.connectionOutcome] ?? conversation.connectionOutcome}
                    </dd>
                  </>
                )}
              </dl>
            </MetaGroup>

            {(conversation.idsAlerts?.length ?? 0) > 0 && (
              <div style={{ gridColumn: '1 / -1' }}>
                <MetaGroup
                  title="IDS alerts"
                  note={`${conversation.idsAlerts!.length} fired`}
                  defaultOpen
                >
                  <IdsAlertRows
                    alerts={conversation.idsAlerts!}
                    clientIp={conversation.initiatorIp ?? source.ip}
                  />
                </MetaGroup>
              </div>
            )}

            {(conversation.srcGeo?.countryCode || conversation.dstGeo?.countryCode ||
              isPrivateIp(source.ip) || isPrivateIp(destination.ip)) && (
              <MetaGroup title="Geolocation" defaultOpen>
                <dl className="cd-kv cd-kv-geo">
                  <GeoInfoRows geo={conversation.srcGeo} label="Src" ip={source.ip} />
                  <GeoInfoRows geo={conversation.dstGeo} label="Dst" ip={destination.ip} />
                </dl>
              </MetaGroup>
            )}

            {(conversation.httpUserAgents?.length ?? 0) > 0 && (
              <MetaGroup title="HTTP" defaultOpen>
                <dl className="cd-kv">
                  <dt>User-Agents</dt>
                  <dd>
                    <ul className="mb-0 ps-3">
                      {conversation.httpUserAgents!.map((ua, i) => (
                        <li key={i}><small className="text-break">{ua}</small></li>
                      ))}
                    </ul>
                  </dd>
                </dl>
              </MetaGroup>
            )}

            {(conversation.ja3Client || conversation.ja3Server || conversation.ja4Client ||
              conversation.tlsVersion || conversation.tlsIssuer ||
              conversation.tlsSubject || conversation.tlsNotBefore != null ||
              conversation.tlsNotAfter != null || conversation.tlsCertificate) && (
              <MetaGroup
                title="TLS"
                defaultOpen
                note={conversation.tlsNotAfter != null && conversation.tlsNotAfter < Date.now() ? 'expired' : undefined}
              >
                <dl className="cd-kv">
                  {conversation.tlsVersion && (
                    <>
                      <dt>Version</dt>
                      <dd>
                        <small>{conversation.tlsVersion}</small>
                        {/^(SSL|TLS 1\.[01]$)/.test(conversation.tlsVersion) && (
                          <Badge bg="warning" text="dark" className="ms-1">Legacy</Badge>
                        )}
                      </dd>
                    </>
                  )}
                  {conversation.tlsIssuer && (<><dt>Issuer</dt><dd><small>{conversation.tlsIssuer}</small></dd></>)}
                  {conversation.tlsSubject && (<><dt>Subject</dt><dd><small>{conversation.tlsSubject}</small></dd></>)}
                  {conversation.tlsNotBefore != null && (<><dt>Valid from</dt><dd><small>{formatTimestamp(conversation.tlsNotBefore)}</small></dd></>)}
                  {conversation.tlsNotAfter != null && (
                    <>
                      <dt>Valid to</dt>
                      <dd>
                        <small className={conversation.tlsNotAfter < Date.now() ? 'text-danger fw-semibold' : undefined}>
                          {formatTimestamp(conversation.tlsNotAfter)}
                          {conversation.tlsNotAfter < Date.now() && <Badge bg="danger" className="ms-1">Expired</Badge>}
                        </small>
                      </dd>
                    </>
                  )}
                  {conversation.tlsCertificate && (
                    <TlsCertificateRows cert={conversation.tlsCertificate} />
                  )}
                  {conversation.ja3Client && (<><dt>JA3</dt><dd><code className="small">{conversation.ja3Client}</code></dd></>)}
                  {conversation.ja3Server && (<><dt>JA3S</dt><dd><code className="small">{conversation.ja3Server}</code></dd></>)}
                  {conversation.ja4Client && (<><dt>JA4</dt><dd><code className="small">{conversation.ja4Client}</code></dd></>)}
                </dl>
              </MetaGroup>
            )}
          </div>
        </Card.Body>
      </Card>

      <div className="cd-packets">
        <div className="cd-tabs" role="tablist" aria-label="Conversation content">
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'packets'}
            className={`cd-tab${activeTab === 'packets' ? ' active' : ''}`}
            onClick={() => setActiveTab('packets')}
          >
            Packets <span className="cd-tab-count">{conversation.packets?.length || 0}</span>
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'session'}
            className={`cd-tab${activeTab === 'session' ? ' active' : ''}`}
            onClick={() => setActiveTab('session')}
          >
            Session
          </button>
          {activeTab === 'packets' && allPackets.some(p => p.payload) && (
            <span className="cd-tabs-hint">Click a packet to see its bytes</span>
          )}
        </div>

        {activeTab === 'packets' && (
          <div role="tabpanel">
            <div className="cd-packets-scroll">
              <table className="cd-packets-table">
                <thead>
                  <tr>
                    <th scope="col">#</th>
                    <th scope="col">
                      <span className="visually-hidden">Direction</span>
                    </th>
                    <th scope="col">Time</th>
                    <th scope="col" className="text-end">
                      Length
                    </th>
                    <th scope="col">Info</th>
                  </tr>
                </thead>
                <tbody>
                  {allPackets.length > 0 ? (
                    visiblePackets.map((packet, index) => {
                      const outgoing = packet.source.ip === source.ip;
                      return (
                        <Fragment key={packet.id}>
                          <tr
                            ref={packet.packetNumber === highlightPacketNumber ? highlightRowRef : undefined}
                            onClick={packet.payload ? () => togglePacket(packet.id) : undefined}
                            className={[
                              packet.payload ? 'cd-packet-clickable' : '',
                              packet.packetNumber === highlightPacketNumber ? 'packet-row-highlighted' : '',
                              expandedPacketId === packet.id ? 'cd-packet-open' : '',
                            ]
                              .filter(Boolean)
                              .join(' ') || undefined}
                          >
                            <td className="cd-packet-n">{(packetPageClamped - 1) * packetPageSize + index + 1}</td>
                            <td
                              className={outgoing ? 'cd-dir-out' : 'cd-dir-in'}
                              aria-label={outgoing ? 'client to server' : 'server to client'}
                            >
                              {outgoing ? '→' : '←'}
                            </td>
                            <td className="cd-packet-time">
                              {new Date(packet.timestamp).toLocaleTimeString('en-GB', {
                                hour: '2-digit',
                                minute: '2-digit',
                                second: '2-digit',
                                fractionalSecondDigits: 3,
                              } as Intl.DateTimeFormatOptions)}
                            </td>
                            <td className="text-end cd-packet-len">{packet.size} B</td>
                            <td className="cd-packet-info">
                              {packet.info ?? packet.protocol.name}
                              {packet.detectedFileType && (
                                <span className="cd-packet-tag">{packet.detectedFileType}</span>
                              )}
                              {asciiPacketIds.has(packet.id) && <span className="cd-packet-tag">ASCII</span>}
                            </td>
                          </tr>
                          {expandedPacketId === packet.id && (
                            <tr>
                              <td colSpan={5} className="cd-packet-hex">
                                {packet.payload ? (
                                  <HexViewer hex={packet.payload} truncated={packet.payload.length >= 2048} />
                                ) : (
                                  <p className="text-muted small mb-0">No payload in this packet.</p>
                                )}
                              </td>
                            </tr>
                          )}
                        </Fragment>
                      );
                    })
                  ) : (
                    <tr>
                      <td colSpan={5} className="text-center text-muted py-3">
                        No packet details available
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            {allPackets.length > 10 && (
              <div className="cd-packets-foot">
                <Pagination
                  currentPage={packetPageClamped}
                  totalPages={packetTotalPages}
                  totalItems={allPackets.length}
                  pageSize={packetPageSize}
                  onPageChange={setPacketPage}
                  onPageSizeChange={size => {
                    setPacketPageSize(size);
                    setPacketPage(1);
                  }}
                />
              </div>
            )}
          </div>
        )}

        {activeTab === 'session' && (
          <div role="tabpanel" className="cd-session">
            <SessionTab conversationId={conversation.id} protocol={conversation.protocol.name} />
          </div>
        )}
      </div>

      {hostModalIp && fileId && (
        <HostDetailModal
          fileId={fileId}
          ip={hostModalIp}
          onClose={() => { setHostModalIp(null); refreshIdentities(); }}
        />
      )}
    </div>
  );
};
