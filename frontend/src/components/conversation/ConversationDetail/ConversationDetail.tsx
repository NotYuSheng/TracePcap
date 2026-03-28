import { useState } from 'react';
import type { Conversation, Packet } from '@/types';
import { formatBytes, formatTimestamp, formatIpPort } from '@/utils/formatters';
import { getAppColor } from '@/utils/appColors';
import { HexViewer } from '../HexViewer/HexViewer';

interface ConversationDetailProps {
  conversation: Conversation;
}

const PRINTABLE_ASCII_THRESHOLD = 0.3;

/** Returns true if more than 30% of the payload bytes are printable ASCII (0x20–0x7e). */
function hasReadableAscii(hex: string): boolean {
  if (!hex || hex.length < 4) return false;
  let printable = 0;
  const total = hex.length / 2;
  for (let i = 0; i < hex.length; i += 2) {
    const byte = parseInt(hex.slice(i, i + 2), 16);
    if (byte >= 0x20 && byte <= 0x7e) printable++;
  }
  return printable / total > PRINTABLE_ASCII_THRESHOLD;
}

export const ConversationDetail = ({ conversation }: ConversationDetailProps) => {
  const [source, destination] = conversation.endpoints;
  const [expandedPacketId, setExpandedPacketId] = useState<string | null>(null);

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
              <dl className="row mb-0">
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
                  <span className="badge bg-primary">{conversation.protocol.name}</span>
                </dd>
                {conversation.appName && (
                  <>
                    <dt className="col-sm-4">Application:</dt>
                    <dd className="col-sm-8">
                      <span className="badge" style={{ backgroundColor: getAppColor(conversation.appName!), color: '#fff' }}>
                        {conversation.appName}
                      </span>
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
          <div className="table-responsive" style={{ maxHeight: '500px', overflowY: 'auto' }}>
            <table className="table table-sm table-striped mb-0">
              <thead className="sticky-top bg-light">
                <tr>
                  <th style={{ width: '60px' }}>#</th>
                  <th style={{ width: '40px' }}></th>
                  <th style={{ width: '180px' }}>Timestamp</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th style={{ width: '100px' }}>Length</th>
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
                        <td>
                          <small>{formatTimestamp(packet.timestamp)}</small>
                        </td>
                        <td>
                          <small>{formatIpPort(packet.source.ip, packet.source.port)}</small>
                        </td>
                        <td>
                          <small>
                            {formatIpPort(packet.destination.ip, packet.destination.port)}
                          </small>
                        </td>
                        <td>{packet.size} B</td>
                        <td>
                          <small className="text-muted">{packet.info ?? packet.protocol.name}</small>
                          {hasReadableAscii(packet.payload) && (
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
