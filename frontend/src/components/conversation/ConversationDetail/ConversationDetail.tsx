import { useState, useMemo } from 'react';
import type { Conversation, Packet } from '@/types';
import { formatBytes, formatTimestamp, formatIpPort } from '@/utils/formatters';
import { getAppColor, getTextColor, getSeverityColor, RISK_BADGE } from '@/utils/appColors';
import { getProtocolColor } from '@/features/network/constants';
import { HexViewer } from '../HexViewer/HexViewer';

interface ConversationDetailProps {
  conversation: Conversation;
  signatureSeverities?: Record<string, string>;
}

const PRINTABLE_ASCII_THRESHOLD = 0.3;

/** Normalise protocol name for mismatch comparison (strips TLS version suffixes, lowercases). */
const normaliseProto = (p: string) =>
  p.trim().replace(/^TLSv[\d.]+$/i, 'TLS').replace(/^SSLv[\d.]+$/i, 'SSL').toLowerCase();

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

export const ConversationDetail = ({ conversation, signatureSeverities = {} }: ConversationDetailProps) => {
  const [source, destination] = conversation.endpoints;
  const [expandedPacketId, setExpandedPacketId] = useState<string | null>(null);

  const asciiPacketIds = useMemo(() => {
    const ids = new Set<string>();
    for (const p of conversation.packets ?? []) {
      if (hasReadableAscii(p.payload)) ids.add(p.id);
    }
    return ids;
  }, [conversation.packets]);

  const togglePacket = (id: string) =>
    setExpandedPacketId(prev => (prev === id ? null : id));

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
        <div className="card-header">
          <h5 className="mb-0">Conversation Details</h5>
        </div>
        <div className="card-body">
          <div className="row">
            <div className="col-md-6">
              <dl className="row mb-0 align-items-start">
                <dt className="col-sm-4">Source:</dt>
                <dd className="col-sm-8">{formatIpPort(source.ip, source.port)}</dd>
                <dt className="col-sm-4">Destination:</dt>
                <dd className="col-sm-8">
                  {formatIpPort(destination.ip, destination.port)}
                  {conversation.hostname && (
                    <small className="text-info d-block">{conversation.hostname}</small>
                  )}
                </dd>
                <dt className="col-sm-4">Protocol:</dt>
                <dd className="col-sm-8">
                  {(() => { const bg = getProtocolColor(conversation.protocol.name); return (
                    <span className="badge" style={{ backgroundColor: bg, color: getTextColor(bg) }}>{conversation.protocol.name}</span>
                  ); })()}
                </dd>
                {(conversation.appName || conversation.tsharkProtocol || conversation.ndpiProtocol) && (
                  <>
                    <dt className="col-sm-4">Application:</dt>
                    <dd className="col-sm-8">
                      {conversation.appName && (() => {
                        const bg = getAppColor(conversation.appName!);
                        return <span className="badge" style={{ backgroundColor: bg, color: getTextColor(bg) }}>{conversation.appName}</span>;
                      })()}
                      {(conversation.tsharkProtocol || conversation.ndpiProtocol) && (
                        <div className="d-flex flex-column gap-1 mt-1">
                          {conversation.tsharkProtocol && (() => {
                            const hasMismatch = !!conversation.ndpiProtocol &&
                              normaliseProto(conversation.tsharkProtocol!) !== normaliseProto(conversation.ndpiProtocol!);
                            return (
                              <span className="text-muted small">
                                Wireshark: <strong>{conversation.tsharkProtocol}</strong>
                                {hasMismatch && (
                                  <span
                                    className="badge ms-1"
                                    style={{ backgroundColor: '#fd7e14', color: '#fff', fontSize: '0.7rem' }}
                                    title={`Wireshark: "${conversation.tsharkProtocol}" vs nDPI: "${conversation.ndpiProtocol}" — may indicate tunnelling or misclassification`}
                                  >
                                    mismatch
                                  </span>
                                )}
                              </span>
                            );
                          })()}
                          {conversation.ndpiProtocol && (
                            <span className="text-muted small">
                              nDPI: <strong>{conversation.ndpiProtocol}</strong>
                            </span>
                          )}
                        </div>
                      )}
                    </dd>
                  </>
                )}
                {conversation.flowRisks && conversation.flowRisks.length > 0 && (
                  <>
                    <dt className="col-sm-4">Security Flags:</dt>
                    <dd className="col-sm-8">
                      <div className="d-flex flex-wrap gap-1">
                        {conversation.flowRisks.map(risk => (
                          <span key={risk} className="badge" style={{ backgroundColor: RISK_BADGE.bg, color: RISK_BADGE.text }}>
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
                          <span key={rule} className="badge" style={{ backgroundColor: bg, color: text }}>
                            {rule.replace(/_/g, ' ')}
                          </span>
                          );
                        })}
                      </div>
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
                      <small className={conversation.tlsNotAfter < Date.now() ? 'text-danger fw-semibold' : undefined}>
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
        <div className="card-header d-flex justify-content-between align-items-center">
          <h6 className="mb-0">Packet Stream ({conversation.packets?.length || 0} packets)</h6>
          <small className="text-muted">Click a row to view hex payload</small>
        </div>
        <div className="card-body p-0">
          <div style={{ maxHeight: '500px', overflowY: 'auto' }}>
            <table className="table table-sm table-striped mb-0" style={{ tableLayout: 'fixed', width: '100%' }}>
              <colgroup>
                <col style={{ width: '4%' }} />   {/* # */}
                <col style={{ width: '3%' }} />   {/* direction */}
                <col style={{ width: '16%' }} />  {/* timestamp */}
                <col style={{ width: '18%' }} />  {/* source */}
                <col style={{ width: '18%' }} />  {/* destination */}
                <col style={{ width: '7%' }} />   {/* length */}
                <col />                           {/* info — takes remaining space */}
              </colgroup>
              <thead className="sticky-top bg-light">
                <tr>
                  <th>#</th>
                  <th></th>
                  <th>Timestamp</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Length</th>
                  <th>Info</th>
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
                        <td style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          <small>{formatTimestamp(packet.timestamp)}</small>
                        </td>
                        <td style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                            title={formatIpPort(packet.source.ip, packet.source.port)}>
                          <small>{formatIpPort(packet.source.ip, packet.source.port)}</small>
                        </td>
                        <td style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                            title={formatIpPort(packet.destination.ip, packet.destination.port)}>
                          <small>
                            {formatIpPort(packet.destination.ip, packet.destination.port)}
                          </small>
                        </td>
                        <td style={{ whiteSpace: 'nowrap' }}>{packet.size} B</td>
                        <td style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          <small className="text-muted">{packet.info ?? packet.protocol.name}</small>
                          {asciiPacketIds.has(packet.id) && (
                            <span className="badge bg-warning text-dark ms-1" style={{ fontSize: '0.65rem' }}>ASCII</span>
                          )}
                          {packet.detectedFileType && (
                            <span className="badge bg-info text-dark ms-1" style={{ fontSize: '0.65rem' }} title={`Magic bytes match: ${packet.detectedFileType}`}>{packet.detectedFileType}</span>
                          )}
                        </td>
                      </tr>
                      {expandedPacketId === packet.id && (
                        <tr key={`${packet.id}-hex`}>
                          <td colSpan={7} className="p-2">
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
                    <td colSpan={7} className="text-center text-muted py-3">
                      No packet details available
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
