import { useState, useEffect, useRef, useCallback } from 'react';
import type { Conversation } from '@/types';
import type { SortField, SortDir } from '@/features/conversation/types';
import type { ColumnKey } from '@/features/conversation/constants';
import { formatBytes, formatDuration, formatTimestamp } from '@/utils/formatters';
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
  const [scrolledEnd, setScrolledEnd] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const topBarRef = useRef<HTMLDivElement>(null);
  const topInnerRef = useRef<HTMLDivElement>(null);
  const syncingRef = useRef(false);

  const col = (key: ColumnKey) => visibleColumns.has(key);

  const updateTopBarWidth = useCallback(() => {
    const table = scrollRef.current?.querySelector('table');
    if (topInnerRef.current && table) {
      topInnerRef.current.style.width = `${table.scrollWidth}px`;
    }
  }, []);

  const handleScroll = useCallback(() => {
    const el = scrollRef.current;
    if (!el) return;
    setScrolledEnd(el.scrollLeft + el.clientWidth >= el.scrollWidth - 4);
    if (!syncingRef.current && topBarRef.current) {
      syncingRef.current = true;
      topBarRef.current.scrollLeft = el.scrollLeft;
      syncingRef.current = false;
    }
    updateTopBarWidth();
  }, [updateTopBarWidth]);

  const handleTopScroll = useCallback(() => {
    if (!syncingRef.current && scrollRef.current && topBarRef.current) {
      syncingRef.current = true;
      scrollRef.current.scrollLeft = topBarRef.current.scrollLeft;
      syncingRef.current = false;
    }
  }, []);

  useEffect(() => {
    updateTopBarWidth();
  }, [conversations, visibleColumns, updateTopBarWidth]);

  // Pan state in refs — no re-renders, always current in the rAF loop
  const panActive = useRef(false);
  const panOrigin = useRef({ x: 0, y: 0 });
  const panMouse = useRef({ x: 0, y: 0 });
  const panRaf = useRef(0);
  const panDot = useRef<HTMLDivElement | null>(null);
  const panTick = useRef<() => void>(() => {});

  const stopPan = useCallback(() => {
    panActive.current = false;
    if (scrollRef.current) scrollRef.current.style.cursor = '';
    cancelAnimationFrame(panRaf.current);
    panDot.current?.remove();
    panDot.current = null;
  }, []);

  // Define the tick loop once and store in ref; window listeners use same ref
  useEffect(() => {
    const DEAD = 8,
      SPD = 0.1;
    panTick.current = () => {
      if (!panActive.current) return;
      const dx = panMouse.current.x - panOrigin.current.x;
      const dy = panMouse.current.y - panOrigin.current.y;
      if (scrollRef.current && Math.abs(dx) > DEAD) scrollRef.current.scrollLeft += dx * SPD;
      if (scrollRef.current && Math.abs(dy) > DEAD) scrollRef.current.scrollTop += dy * SPD;
      panRaf.current = requestAnimationFrame(panTick.current);
    };

    const onMove = (e: MouseEvent) => {
      panMouse.current = { x: e.clientX, y: e.clientY };
    };
    const onClick = (e: MouseEvent) => {
      if (panActive.current && e.button !== 1) stopPan();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') stopPan();
    };

    window.addEventListener('mousemove', onMove);
    window.addEventListener('mousedown', onClick);
    window.addEventListener('keydown', onKey);
    return () => {
      stopPan();
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mousedown', onClick);
      window.removeEventListener('keydown', onKey);
    };
  }, [stopPan]);

  const handleMiddleDown = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      if (e.button !== 1) return;
      e.preventDefault();
      if (panActive.current) {
        stopPan();
        return;
      }
      panActive.current = true;
      panOrigin.current = { x: e.clientX, y: e.clientY };
      panMouse.current = { x: e.clientX, y: e.clientY };
      if (scrollRef.current) scrollRef.current.style.cursor = 'all-scroll';
      const dot = document.createElement('div');
      dot.className = 'conv-pan-dot';
      dot.style.left = `${e.clientX}px`;
      dot.style.top = `${e.clientY}px`;
      document.body.appendChild(dot);
      panDot.current = dot;
      panRaf.current = requestAnimationFrame(panTick.current);
    },
    [stopPan]
  );

  const hasAppNames = conversations.some(c => c.appName);
  const hasL7Protocols = conversations.some(c => c.tsharkProtocol);
  const hasCategories = conversations.some(c => c.category);
  const hasRisks = conversations.some(c => c.flowRisks && c.flowRisks.length > 0);
  const hasCustomRules = conversations.some(
    c => c.customSignatures && c.customSignatures.length > 0
  );

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
      {/* Top phantom scrollbar */}
      <div ref={topBarRef} className="conv-top-scrollbar" onScroll={handleTopScroll}>
        <div ref={topInnerRef} className="conv-top-scrollbar-inner" />
      </div>

      <div
        ref={scrollRef}
        className={`conv-table-scroll${scrolledEnd ? ' scrolled-end' : ''}`}
        onScroll={handleScroll}
        onMouseDown={handleMiddleDown}
      >
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
      </div>

      {conversations.length === 0 && (
        <div className="text-center py-5">
          <p className="text-muted">No conversations found</p>
        </div>
      )}
    </div>
  );
};
