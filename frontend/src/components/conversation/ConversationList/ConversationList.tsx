import { useState } from 'react';
import type { Conversation } from '@/types';
import { formatBytes, formatDuration, formatTimestamp } from '@/utils/formatters';
import { getAppColor } from '@/utils/appColors';

interface ConversationListProps {
  conversations: Conversation[];
  onSelectConversation?: (conversation: Conversation) => void;
}

export const ConversationList = ({
  conversations,
  onSelectConversation,
}: ConversationListProps) => {
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const hasAppNames = conversations.some(c => c.appName);
  const hasCategories = conversations.some(c => c.category);

  const handleRowClick = (conversation: Conversation) => {
    setSelectedId(conversation.id);
    onSelectConversation?.(conversation);
  };

  const getProtocolBadgeClass = (protocol: string) => {
    const protocolMap: Record<string, string> = {
      TCP: 'primary',
      UDP: 'info',
      HTTP: 'success',
      HTTPS: 'success',
      DNS: 'warning',
      TLS: 'success',
      ICMP: 'secondary',
      ARP: 'secondary',
    };
    return protocolMap[protocol.toUpperCase()] || 'secondary';
  };

  return (
    <div className="conversation-list">
      <div className="table-responsive">
        <table className="table table-hover">
          <thead>
            <tr>
              <th>Source</th>
              <th>Destination</th>
              <th>Protocol</th>
              {hasAppNames && <th>Application</th>}
              {hasCategories && <th>Category</th>}
              <th>Packets</th>
              <th>Bytes</th>
              <th>Duration</th>
              <th>Start Time</th>
            </tr>
          </thead>
          <tbody>
            {conversations.map(conversation => {
              const [source, destination] = conversation.endpoints;
              const duration = conversation.endTime - conversation.startTime;

              return (
                <tr
                  key={conversation.id}
                  onClick={() => handleRowClick(conversation)}
                  className={selectedId === conversation.id ? 'table-active' : ''}
                  style={{ cursor: 'pointer' }}
                >
                  <td>
                    <div className="d-flex flex-column">
                      <div>
                        <span className="fw-semibold">{source.ip}</span>
                        {source.port && <small className="text-muted">:{source.port}</small>}
                      </div>
                    </div>
                  </td>
                  <td>
                    <div className="d-flex flex-column">
                      <div>
                        <span className="fw-semibold">{destination.ip}</span>
                        {destination.port && (
                          <small className="text-muted">:{destination.port}</small>
                        )}
                      </div>
                      {conversation.hostname && (
                        <small className="text-info">{conversation.hostname}</small>
                      )}
                    </div>
                  </td>
                  <td>
                    <span
                      className={`badge bg-${getProtocolBadgeClass(conversation.protocol.name)}`}
                    >
                      {conversation.protocol.name}
                    </span>
                  </td>
                  {hasAppNames && (
                    <td>
                      {conversation.appName ? (
                        <span
                          className="badge"
                          style={{
                            backgroundColor: getAppColor(conversation.appName!),
                            color: '#fff',
                          }}
                        >
                          {conversation.appName}
                        </span>
                      ) : (
                        <span className="text-muted">—</span>
                      )}
                    </td>
                  )}
                  {hasCategories && (
                    <td>
                      {conversation.category ? (
                        <span
                          className="badge"
                          style={{
                            backgroundColor: getAppColor(conversation.category),
                            color: '#fff',
                          }}
                        >
                          {conversation.category}
                        </span>
                      ) : (
                        <span className="text-muted">—</span>
                      )}
                    </td>
                  )}
                  <td>{conversation.packetCount.toLocaleString()}</td>
                  <td>{formatBytes(conversation.totalBytes)}</td>
                  <td>{formatDuration(duration)}</td>
                  <td>
                    <small>{formatTimestamp(conversation.startTime)}</small>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {conversations.length === 0 && (
        <div className="text-center py-5">
          <p className="text-muted">No conversations found</p>
        </div>
      )}
    </div>
  );
};
