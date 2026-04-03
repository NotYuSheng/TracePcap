import { useState } from 'react';
import { ScrollableTable } from '@components/common/ScrollableTable';
import type { Conversation, ConversationGeoInfo, HostClassification } from '@/types';
import type { SortField, SortDir } from '@/features/conversation/types';
import type { ColumnKey } from '@/features/conversation/constants';
import { formatBytes, formatDuration, formatTimestamp } from '@/utils/formatters';

/** Converts an ISO 3166-1 alpha-2 country code to a flag emoji. */
function countryFlag(code: string): string {
  return code
    .toUpperCase()
    .split('')
    .map(c => String.fromCodePoint(0x1f1e6 + c.charCodeAt(0) - 65))
    .join('');
}

function GeoCell({ geo }: { geo?: ConversationGeoInfo }) {
  if (!geo?.countryCode) return <span className="text-muted">—</span>;
  return (
    <span title={`${geo.country}${geo.org ? ` · ${geo.org}` : ''}${geo.asn ? ` (${geo.asn})` : ''}`}>
      {countryFlag(geo.countryCode)} {geo.countryCode}
    </span>
  );
}
import {
  getAppColor,
  getCategoryColor,
  getL7ProtocolColor,
  getTextColor,
  getSeverityColor,
  RISK_BADGE,
} from '@/utils/appColors';
import { getProtocolColor } from '@/features/network/constants';
import './ConversationList.css';

interface ConversationListProps {
  conversations: Conversation[];
  onSelectConversation?: (conversation: Conversation) => void;
  sortBy: SortField;
  sortDir: SortDir;
  onSort: (field: SortField) => void;
  onRiskFilterClick?: () => void;
  visibleColumns: Set<ColumnKey>;
  signatureSeverities?: Record<string, string>;
  hostClassMap?: Map<string, HostClassification>;
}

export const ConversationList = ({
  conversations,
  onSelectConversation,
  sortBy,
  sortDir,
  onSort,
  visibleColumns,
  signatureSeverities = {},
}: ConversationListProps) => {
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const col = (key: ColumnKey) => visibleColumns.has(key);

  const hasAppNames = conversations.some(c => c.appName);
  const hasL7Protocols = conversations.some(c => c.tsharkProtocol);
  const hasCategories = conversations.some(c => c.category);
  const hasRisks = conversations.some(c => c.flowRisks && c.flowRisks.length > 0);
  const hasCustomRules = conversations.some(
    c => c.customSignatures && c.customSignatures.length > 0
  );
  const hasFileTypes = conversations.some(c => c.detectedFileTypes && c.detectedFileTypes.length > 0);

  const handleRowClick = (conversation: Conversation) => {
    setSelectedId(conversation.id);
    onSelectConversation?.(conversation);
  };

  const SortableHeader = ({ field, label }: { field: SortField; label: string }) => {
    const isActive = sortBy === field;
    const icon = !isActive
      ? 'bi-arrow-down-up text-muted'
      : sortDir === 'asc'
        ? 'bi-sort-up'
        : 'bi-sort-down';
    const handleClick = () => {
      if (!isActive) onSort(field);
      else if (sortDir === 'asc') onSort(field);
      else onSort('' as SortField);
    };
    return (
      <th
        onClick={handleClick}
        style={{ cursor: 'pointer', userSelect: 'none', whiteSpace: 'nowrap' }}
      >
        {label} <i className={`bi ${icon} ms-1`}></i>
      </th>
    );
  };

  return (
    <div className="conversation-list">
      <ScrollableTable>
        <table className="table table-hover">
          <thead>
            <tr>
              {col('source') && <SortableHeader field="srcIp" label="Source" />}
              {col('destination') && <SortableHeader field="dstIp" label="Destination" />}
              {col('protocol') && <th style={{ whiteSpace: 'nowrap' }}>L4 Protocol</th>}
              {col('tsharkProtocol') && hasL7Protocols && (
                <th style={{ whiteSpace: 'nowrap' }}>L7 Protocol</th>
              )}
              {col('appName') && hasAppNames && <th>Application</th>}
              {col('category') && hasCategories && <th>Category</th>}
              {col('risks') && hasRisks && <th>Risks</th>}
              {col('customRules') && hasCustomRules && <th>Custom Rules</th>}
              {col('fileTypes') && hasFileTypes && <th style={{ whiteSpace: 'nowrap' }}>File Type</th>}
              {col('srcCountry') && <th style={{ whiteSpace: 'nowrap' }}>Src Country</th>}
              {col('dstCountry') && <th style={{ whiteSpace: 'nowrap' }}>Dst Country</th>}
              {col('packets') && <SortableHeader field="packets" label="Packets" />}
              {col('bytes') && <SortableHeader field="bytes" label="Bytes" />}
              {col('duration') && <SortableHeader field="duration" label="Duration" />}
              {col('startTime') && <SortableHeader field="startTime" label="Start Time" />}
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
                  {col('source') && (
                    <td>
                      <span className="fw-semibold">{source.ip}</span>
                      {source.port > 0 && <small className="text-muted">:{source.port}</small>}
                    </td>
                  )}
                  {col('destination') && (
                    <td>
                      <div>
                        <span className="fw-semibold">{destination.ip}</span>
                        {destination.port > 0 && (
                          <small className="text-muted">:{destination.port}</small>
                        )}
                      </div>
                      {conversation.hostname && (
                        <small className="text-info">{conversation.hostname}</small>
                      )}
                    </td>
                  )}
                  {col('protocol') && (
                    <td>
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
                    </td>
                  )}
                  {col('tsharkProtocol') && hasL7Protocols && (
                    <td>
                      {conversation.tsharkProtocol ? (
                        (() => {
                          const bg = getL7ProtocolColor(conversation.tsharkProtocol!);
                          return (
                            <span
                              className="badge"
                              style={{ backgroundColor: bg, color: getTextColor(bg) }}
                            >
                              {conversation.tsharkProtocol}
                            </span>
                          );
                        })()
                      ) : (
                        <span className="text-muted">—</span>
                      )}
                    </td>
                  )}
                  {col('appName') && hasAppNames && (
                    <td>
                      {conversation.appName ? (
                        (() => {
                          const bg = getAppColor(conversation.appName);
                          return (
                            <span
                              className="badge"
                              style={{ backgroundColor: bg, color: getTextColor(bg) }}
                            >
                              {conversation.appName}
                            </span>
                          );
                        })()
                      ) : (
                        <span className="text-muted">—</span>
                      )}
                    </td>
                  )}
                  {col('category') && hasCategories && (
                    <td>
                      {conversation.category ? (
                        (() => {
                          const bg = getCategoryColor(conversation.category);
                          return (
                            <span
                              className="badge"
                              style={{ backgroundColor: bg, color: getTextColor(bg) }}
                            >
                              {conversation.category}
                            </span>
                          );
                        })()
                      ) : (
                        <span className="text-muted">—</span>
                      )}
                    </td>
                  )}
                  {col('risks') && hasRisks && (
                    <td>
                      {conversation.flowRisks && conversation.flowRisks.length > 0 ? (
                        <div className="d-inline-flex flex-wrap gap-1">
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
                      ) : (
                        <span className="text-muted">—</span>
                      )}
                    </td>
                  )}
                  {col('customRules') && hasCustomRules && (
                    <td>
                      {conversation.customSignatures && conversation.customSignatures.length > 0 ? (
                        <div className="d-inline-flex flex-wrap gap-1">
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
                      ) : (
                        <span className="text-muted">—</span>
                      )}
                    </td>
                  )}
                  {col('fileTypes') && hasFileTypes && (
                    <td>
                      {conversation.detectedFileTypes && conversation.detectedFileTypes.length > 0 ? (
                        <div className="d-inline-flex flex-wrap gap-1">
                          {conversation.detectedFileTypes.map(ft => (
                            <span
                              key={ft}
                              className="badge bg-info text-dark"
                              style={{ whiteSpace: 'nowrap' }}
                            >
                              {ft}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="text-muted">—</span>
                      )}
                    </td>
                  )}
                  {col('srcCountry') && <td><GeoCell geo={conversation.srcGeo} /></td>}
                  {col('dstCountry') && <td><GeoCell geo={conversation.dstGeo} /></td>}
                  {col('packets') && <td>{conversation.packetCount.toLocaleString()}</td>}
                  {col('bytes') && <td>{formatBytes(conversation.totalBytes)}</td>}
                  {col('duration') && <td>{formatDuration(duration)}</td>}
                  {col('startTime') && (
                    <td>
                      <small>{formatTimestamp(conversation.startTime)}</small>
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </table>
      </ScrollableTable>

      {conversations.length === 0 && (
        <div className="text-center py-5">
          <p className="text-muted">No conversations found</p>
        </div>
      )}
    </div>
  );
};
