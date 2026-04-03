import { useState, useMemo, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import type { Conversation, ConversationGeoInfo, Packet, HostClassification } from '@/types';
import { getExtractionsByConversation } from '@features/extractedFiles/services/extractedFilesService';
import { formatBytes, formatTimestamp, formatIpPort } from '@/utils/formatters';
import {
  getAppColor,
  getL7ProtocolColor,
  getTextColor,
  getSeverityColor,
  RISK_BADGE,
} from '@/utils/appColors';
import { getProtocolColor } from '@/features/network/constants';
import { deviceTypeLabel, deviceTypeColor } from '@/utils/deviceType';
import { HexViewer } from '../HexViewer/HexViewer';
import { SessionTab } from '../SessionTab/SessionTab';
import { DeviceClassificationPopup } from '@components/common/DeviceClassificationPopup/DeviceClassificationPopup';
import type { DeviceClassificationInfo } from '@components/common/DeviceClassificationPopup/DeviceClassificationPopup';

interface ConversationDetailProps {
  conversation: Conversation;
  signatureSeverities?: Record<string, string>;
  hostClassMap?: Map<string, HostClassification>;
  fileId?: string;
}

function countryFlag(code: string): string {
  return code
    .toUpperCase()
    .split('')
    .map(c => String.fromCodePoint(0x1f1e6 + c.charCodeAt(0) - 65))
    .join('');
}

function isPrivateIp(ip: string): boolean {
  return /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|f[cd][0-9a-f]{2}:|fe80:)/i.test(ip);
}

function GeoInfoRows({ geo, label, ip }: { geo?: ConversationGeoInfo; label: string; ip: string }) {
  if (!geo?.countryCode) {
    if (!isPrivateIp(ip)) return null;
    return (
      <>
        <dt className="col-sm-4">{label} Country:</dt>
        <dd className="col-sm-8"><span className="text-muted">Internal</span></dd>
      </>
    );
  }
  return (
    <>
      <dt className="col-sm-4">{label} Country:</dt>
      <dd className="col-sm-8">
        {countryFlag(geo.countryCode)} {geo.country} ({geo.countryCode})
        {geo.asn && <small className="text-muted ms-2">{geo.asn}</small>}
        {geo.org && <small className="text-muted d-block">{geo.org}</small>}
      </dd>
    </>
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
  hostClassMap,
  fileId,
}: ConversationDetailProps) => {
  const navigate = useNavigate();
  const [source, destination] = conversation.endpoints;
  const srcClass = hostClassMap?.get(source.ip);
  const dstClass = hostClassMap?.get(destination.ip);
  const [activeTab, setActiveTab] = useState<'packets' | 'session'>('packets');
  const [extractedCount, setExtractedCount] = useState<number | null>(null);
  const [expandedPacketId, setExpandedPacketId] = useState<string | null>(null);
  const [devicePopup, setDevicePopup] = useState<DeviceClassificationInfo | null>(null);

  const openDevicePopup = (cls: HostClassification, ip: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setDevicePopup({
      ip,
      deviceType: cls.deviceType,
      confidence: cls.confidence,
      manufacturer: cls.manufacturer,
      ttl: cls.ttl,
    });
  };

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

  const thStyle: React.CSSProperties = {
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  };

  const getDirectionIndicator = (packet: Packet) => {
    if (packet.source.ip === source.ip) {
      return '→'; // Outgoing from source
    }
    return '←'; // Incoming to source
  };

  const getDirectionClass = (packet: Packet) => {
    if (packet.source.ip === source.ip) {
      return 'text-primary'; // Outgoing
    }
    return 'text-success'; // Incoming
  };

  return (
    <div className="conversation-detail">
      <div className="card mb-4">
        <div className="card-header d-flex align-items-center justify-content-between">
          <h5 className="mb-0">Conversation Details</h5>
          {extractedCount != null && extractedCount > 0 && fileId && (
            <button
              className="btn btn-sm btn-outline-warning"
              onClick={() =>
                navigate(`/analysis/${fileId}/extracted-files`)
              }
              title="Files extracted from this conversation's stream"
            >
              <i className="bi bi-file-earmark-arrow-down me-1"></i>
              {extractedCount} extracted file{extractedCount !== 1 ? 's' : ''}
            </button>
          )}
        </div>
        <div className="card-body">
          <div className="row">
            <div className="col-md-6">
              <dl className="row mb-0">
                <dt className="col-sm-4">Source:</dt>
                <dd className="col-sm-8">
                  {formatIpPort(source.ip, source.port)}
                  {srcClass && (
                    <span
                      className="ms-2 badge"
                      style={{ backgroundColor: deviceTypeColor(srcClass.deviceType), color: '#fff', fontSize: '0.7em', cursor: 'pointer' }}
                      title="Click for details"
                      onClick={e => openDevicePopup(srcClass, source.ip, e)}
                    >
                      {deviceTypeLabel(srcClass.deviceType)}
                    </span>
                  )}
                </dd>
                <dt className="col-sm-4">Destination:</dt>
                <dd className="col-sm-8">
                  {formatIpPort(destination.ip, destination.port)}
                  {dstClass && (
                    <span
                      className="ms-2 badge"
                      style={{ backgroundColor: deviceTypeColor(dstClass.deviceType), color: '#fff', fontSize: '0.7em', cursor: 'pointer' }}
                      title="Click for details"
                      onClick={e => openDevicePopup(dstClass, destination.ip, e)}
                    >
                      {deviceTypeLabel(dstClass.deviceType)}
                    </span>
                  )}
                  {conversation.hostname && (
                    <small className="text-info d-block">{conversation.hostname}</small>
                  )}
                </dd>
                <GeoInfoRows geo={conversation.srcGeo} label="Src" ip={source.ip} />
                <GeoInfoRows geo={conversation.dstGeo} label="Dst" ip={destination.ip} />
                <dt className="col-sm-4">L4 Protocol:</dt>
                <dd className="col-sm-8">
                  {(() => {
                    const bg = getProtocolColor(conversation.protocol.name);
                    return (
                      <span
                        className="badge"
                        style={{ backgroundColor: bg, color: getTextColor(bg) }}
                      >
                        {conversation.protocol.name}
                      </span>
                    );
                  })()}
                </dd>
                {conversation.tsharkProtocol && (
                  <>
                    <dt className="col-sm-4">L7 Protocol:</dt>
                    <dd className="col-sm-8">
                      {(() => {
                        const bg = getL7ProtocolColor(conversation.tsharkProtocol!);
                        return (
                          <span
                            className="badge"
                            style={{ backgroundColor: bg, color: getTextColor(bg) }}
                          >
                            {conversation.tsharkProtocol}
                          </span>
                        );
                      })()}
                    </dd>
                  </>
                )}
                {conversation.appName && (
                  <>
                    <dt className="col-sm-4">Application:</dt>
                    <dd className="col-sm-8">
                      {(() => {
                        const bg = getAppColor(conversation.appName!);
                        return (
                          <span
                            className="badge"
                            style={{ backgroundColor: bg, color: getTextColor(bg) }}
                          >
                            {conversation.appName}
                          </span>
                        );
                      })()}
                    </dd>
                  </>
                )}
                {conversation.flowRisks && conversation.flowRisks.length > 0 && (
                  <>
                    <dt className="col-sm-4">Security Flags:</dt>
                    <dd className="col-sm-8">
                      <div className="d-flex flex-wrap gap-1">
                        {conversation.flowRisks.map(risk => (
                          <span
                            key={risk}
                            className="badge"
                            style={{
                              backgroundColor: RISK_BADGE.bg,
                              color: RISK_BADGE.text,
                              whiteSpace: 'nowrap',
                            }}
                          >
                            {risk}
                          </span>
                        ))}
                      </div>
                    </dd>
                  </>
                )}
                {conversation.customSignatures && conversation.customSignatures.length > 0 && (
                  <>
                    <dt className="col-sm-4">Custom Rules:</dt>
                    <dd className="col-sm-8">
                      <div className="d-flex flex-wrap gap-1">
                        {conversation.customSignatures.map(rule => {
                          const { bg, text } = getSeverityColor(signatureSeverities[rule]);
                          return (
                            <span
                              key={rule}
                              className="badge"
                              style={{ backgroundColor: bg, color: text, whiteSpace: 'nowrap' }}
                            >
                              {rule.replace(/_/g, ' ')}
                            </span>
                          );
                        })}
                      </div>
                    </dd>
                  </>
                )}
                {conversation.httpUserAgents && conversation.httpUserAgents.length > 0 && (
                  <>
                    <dt className="col-sm-4">User-Agents:</dt>
                    <dd className="col-sm-8">
                      <ul className="mb-0 ps-3">
                        {conversation.httpUserAgents.map((ua, i) => (
                          <li key={i}>
                            <small className="text-break">{ua}</small>
                          </li>
                        ))}
                      </ul>
                    </dd>
                  </>
                )}
                {conversation.ja3Client && (
                  <>
                    <dt className="col-sm-4">JA3 Client:</dt>
                    <dd className="col-sm-8">
                      <code className="small">{conversation.ja3Client}</code>
                    </dd>
                  </>
                )}
                {conversation.ja3Server && (
                  <>
                    <dt className="col-sm-4">JA3S Server:</dt>
                    <dd className="col-sm-8">
                      <code className="small">{conversation.ja3Server}</code>
                    </dd>
                  </>
                )}
                {conversation.tlsIssuer && (
                  <>
                    <dt className="col-sm-4">TLS Issuer:</dt>
                    <dd className="col-sm-8">
                      <small>{conversation.tlsIssuer}</small>
                    </dd>
                  </>
                )}
                {conversation.tlsSubject && (
                  <>
                    <dt className="col-sm-4">TLS Subject:</dt>
                    <dd className="col-sm-8">
                      <small>{conversation.tlsSubject}</small>
                    </dd>
                  </>
                )}
                {conversation.tlsNotBefore != null && (
                  <>
                    <dt className="col-sm-4">Cert Valid From:</dt>
                    <dd className="col-sm-8">
                      <small>{formatTimestamp(conversation.tlsNotBefore)}</small>
                    </dd>
                  </>
                )}
                {conversation.tlsNotAfter != null && (
                  <>
                    <dt className="col-sm-4">Cert Valid To:</dt>
                    <dd className="col-sm-8">
                      <small
                        className={
                          conversation.tlsNotAfter < Date.now()
                            ? 'text-danger fw-semibold'
                            : undefined
                        }
                      >
                        {formatTimestamp(conversation.tlsNotAfter)}
                        {conversation.tlsNotAfter < Date.now() && (
                          <span className="ms-1 badge bg-danger">Expired</span>
                        )}
                      </small>
                    </dd>
                  </>
                )}
              </dl>
            </div>
            <div className="col-md-6">
              <dl className="row mb-0">
                <dt className="col-sm-4">Packets:</dt>
                <dd className="col-sm-8">{conversation.packetCount.toLocaleString()}</dd>
                <dt className="col-sm-4">Bytes:</dt>
                <dd className="col-sm-8">{formatBytes(conversation.totalBytes)}</dd>
                <dt className="col-sm-4">Start Time:</dt>
                <dd className="col-sm-8">
                  <small>{formatTimestamp(conversation.startTime)}</small>
                </dd>
              </dl>
            </div>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <ul className="nav nav-tabs card-header-tabs">
            <li className="nav-item">
              <button
                className={`nav-link${activeTab === 'packets' ? ' active' : ''}`}
                onClick={() => setActiveTab('packets')}
              >
                Packets
                <span className="badge bg-secondary ms-2" style={{ fontSize: '0.65rem' }}>
                  {conversation.packets?.length || 0}
                </span>
              </button>
            </li>
            <li className="nav-item">
              <button
                className={`nav-link${activeTab === 'session' ? ' active' : ''}`}
                onClick={() => setActiveTab('session')}
              >
                Session
              </button>
            </li>
          </ul>
        </div>

        {activeTab === 'packets' && (
          <div className="card-body p-0">
            <div className="px-3 py-2 border-bottom d-flex justify-content-end">
              <small className="text-muted">Click a row to view hex payload</small>
            </div>
            <div style={{ maxHeight: '500px', overflowY: 'auto' }}>
              <table
                className="table table-sm table-striped mb-0"
                style={{ tableLayout: 'fixed', width: '100%' }}
              >
                <colgroup>
                  <col style={{ width: '4%' }} /> {/* # */}
                  <col style={{ width: '3%' }} /> {/* direction */}
                  <col style={{ width: '14%' }} /> {/* timestamp */}
                  <col style={{ width: '16%' }} /> {/* source */}
                  <col style={{ width: '16%' }} /> {/* destination */}
                  <col style={{ width: '6%' }} /> {/* length */}
                  <col style={{ width: '8%' }} /> {/* file type */}
                  <col /> {/* info — takes remaining space */}
                </colgroup>
                <thead className="sticky-top bg-light">
                  <tr>
                    <th style={thStyle}>#</th>
                    <th></th>
                    <th style={thStyle}>Timestamp</th>
                    <th style={thStyle}>Source</th>
                    <th style={thStyle}>Destination</th>
                    <th style={thStyle}>Len</th>
                    <th style={thStyle}>File Type</th>
                    <th style={thStyle}>Info</th>
                  </tr>
                </thead>
                <tbody>
                  {conversation.packets && conversation.packets.length > 0 ? (
                    conversation.packets.map((packet, index) => (
                      <>
                        <tr
                          key={packet.id}
                          onClick={() => togglePacket(packet.id)}
                          style={{ cursor: packet.payload ? 'pointer' : 'default' }}
                          className={expandedPacketId === packet.id ? 'table-active' : undefined}
                        >
                          <td className="text-muted">{index + 1}</td>
                          <td className={getDirectionClass(packet)}>
                            <strong>{getDirectionIndicator(packet)}</strong>
                          </td>
                          <td
                            style={{
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                            }}
                          >
                            <small>{formatTimestamp(packet.timestamp)}</small>
                          </td>
                          <td
                            style={{
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                            }}
                            title={formatIpPort(packet.source.ip, packet.source.port)}
                          >
                            <small>{formatIpPort(packet.source.ip, packet.source.port)}</small>
                          </td>
                          <td
                            style={{
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                            }}
                            title={formatIpPort(packet.destination.ip, packet.destination.port)}
                          >
                            <small>
                              {formatIpPort(packet.destination.ip, packet.destination.port)}
                            </small>
                          </td>
                          <td style={{ whiteSpace: 'nowrap' }}>{packet.size} B</td>
                          <td>
                            {packet.detectedFileType ? (
                              <span
                                className="badge bg-info text-dark"
                                style={{ fontSize: '0.65rem' }}
                                title={`Magic bytes match: ${packet.detectedFileType}`}
                              >
                                {packet.detectedFileType}
                              </span>
                            ) : (
                              <span className="text-muted">—</span>
                            )}
                          </td>
                          <td>
                            <small className="text-muted">
                              {packet.info ?? packet.protocol.name}
                            </small>
                            {asciiPacketIds.has(packet.id) && (
                              <span
                                className="badge bg-warning text-dark ms-1"
                                style={{ fontSize: '0.65rem' }}
                              >
                                ASCII
                              </span>
                            )}
                          </td>
                        </tr>
                        {expandedPacketId === packet.id && (
                          <tr key={`${packet.id}-hex`}>
                            <td colSpan={8} className="p-2">
                              {packet.payload ? (
                                <HexViewer
                                  hex={packet.payload}
                                  truncated={packet.payload.length >= 2048}
                                />
                              ) : (
                                <p className="text-muted small mb-0">No payload data available.</p>
                              )}
                            </td>
                          </tr>
                        )}
                      </>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={8} className="text-center text-muted py-3">
                        No packet details available
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === 'session' && (
          <div className="card-body">
            <SessionTab
              conversationId={conversation.id}
              protocol={conversation.protocol.name}
            />
          </div>
        )}
      </div>

      {devicePopup && (
        <DeviceClassificationPopup info={devicePopup} onClose={() => setDevicePopup(null)} />
      )}
    </div>
  );
};
