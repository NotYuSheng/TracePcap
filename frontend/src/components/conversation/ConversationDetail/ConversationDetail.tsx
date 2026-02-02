import type { Conversation, Packet } from '@/types';
import { formatBytes, formatTimestamp, formatIpPort } from '@/utils/formatters';

interface ConversationDetailProps {
  conversation: Conversation;
}

export const ConversationDetail = ({ conversation }: ConversationDetailProps) => {
  const [source, destination] = conversation.endpoints;

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
                <dd className="col-sm-8">{formatIpPort(destination.ip, destination.port)}</dd>
                <dt className="col-sm-4">Protocol:</dt>
                <dd className="col-sm-8">
                  <span className="badge bg-primary">{conversation.protocol.name}</span>
                </dd>
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
          <h6 className="mb-0">Packet Stream ({conversation.packets?.length || 0} packets)</h6>
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
                    <tr key={packet.id}>
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
                        <small className="text-muted">{packet.protocol.name}</small>
                      </td>
                    </tr>
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
