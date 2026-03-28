import { useState, useEffect, useRef, useCallback } from 'react';
import type { Conversation } from '@/types';
import type { SortField, SortDir } from '@/features/conversation/types';
import { formatBytes, formatDuration, formatTimestamp } from '@/utils/formatters';
import { getAppColor } from '@/utils/appColors';
import './ConversationList.css';

interface ConversationListProps {
  conversations: Conversation[];
  onSelectConversation?: (conversation: Conversation) => void;
  sortBy: SortField;
  sortDir: SortDir;
  onSort: (field: SortField) => void;
  onRiskFilterClick?: () => void;
}

export const ConversationList = ({
  conversations,
  onSelectConversation,
  sortBy,
  sortDir,
  onSort,
  onRiskFilterClick,
}: ConversationListProps) => {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [scrolledEnd, setScrolledEnd] = useState(false);
  const scrollRef    = useRef<HTMLDivElement>(null);
  const topBarRef    = useRef<HTMLDivElement>(null);
  const topInnerRef  = useRef<HTMLDivElement>(null);
  const syncingRef   = useRef(false); // prevent echo between the two scroll handlers

  // Keep the top phantom bar width in sync with the table's scroll width
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

  // Set top bar width once on mount and whenever conversations change
  useEffect(() => {
    updateTopBarWidth();
  }, [conversations, updateTopBarWidth]);

  // Middle-click auto-scroll (panning) on the table scroll container
  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;

    let isPanning = false;
    let originX = 0;
    let originY = 0;
    let rafId = 0;

    const onMouseDown = (e: MouseEvent) => {
      if (e.button !== 1) return;   // middle button only
      e.preventDefault();
      isPanning = true;
      originX = e.clientX;
      originY = e.clientY;
      el.style.cursor = 'all-scroll';
    };

    const onMouseMove = (e: MouseEvent) => {
      if (!isPanning) return;
      const dx = e.clientX - originX;
      const dy = e.clientY - originY;
      cancelAnimationFrame(rafId);
      rafId = requestAnimationFrame(() => {
        el.scrollLeft -= dx * 0.4;
        el.scrollTop  -= dy * 0.4;
        originX = e.clientX;
        originY = e.clientY;
      });
    };

    const stopPan = () => {
      if (!isPanning) return;
      isPanning = false;
      el.style.cursor = '';
      cancelAnimationFrame(rafId);
    };

    el.addEventListener('mousedown', onMouseDown);
    window.addEventListener('mousemove', onMouseMove);
    window.addEventListener('mouseup', stopPan);
    // Prevent the browser's native middle-click scroll indicator
    el.addEventListener('auxclick', (e) => { if (e.button === 1) e.preventDefault(); });

    return () => {
      el.removeEventListener('mousedown', onMouseDown);
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('mouseup', stopPan);
      cancelAnimationFrame(rafId);
    };
  }, []);

  const hasAppNames  = conversations.some(c => c.appName);
  const hasCategories = conversations.some(c => c.category);
  const hasRisks     = conversations.some(c => c.flowRisks && c.flowRisks.length > 0);

  const handleRowClick = (conversation: Conversation) => {
    setSelectedId(conversation.id);
    onSelectConversation?.(conversation);
  };

  const getProtocolBadgeClass = (protocol: string) => {
    const protocolMap: Record<string, string> = {
      TCP: 'primary', UDP: 'info', HTTP: 'success', HTTPS: 'success',
      DNS: 'warning', TLS: 'success', ICMP: 'secondary', ARP: 'secondary',
    };
    return protocolMap[protocol.toUpperCase()] || 'secondary';
  };

  const SortableHeader = ({ field, label }: { field: SortField; label: string }) => {
    const isActive = sortBy === field;
    const icon = !isActive
      ? 'bi-arrow-down-up text-muted'
      : sortDir === 'asc' ? 'bi-sort-up' : 'bi-sort-down';
    const nextDir: SortDir = isActive && sortDir === 'asc' ? 'desc' : 'asc';
    const handleClick = () => {
      // Cycle: inactive → asc, asc → desc, desc → clear
      if (!isActive) onSort(field);
      else if (sortDir === 'asc') onSort(field);   // triggers desc in parent via sortDir flip
      else onSort('' as SortField);                // clear
    };
    // Let parent manage direction; just toggle or clear
    void nextDir;
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
      {/* Top phantom scrollbar — mirrors the bottom scroll position */}
      <div ref={topBarRef} className="conv-top-scrollbar" onScroll={handleTopScroll}>
        <div ref={topInnerRef} className="conv-top-scrollbar-inner" />
      </div>
      <div
        ref={scrollRef}
        className={`conv-table-scroll${scrolledEnd ? ' scrolled-end' : ''}`}
        onScroll={handleScroll}
      >
        <table className="table table-hover">
          <thead>
            <tr>
              <SortableHeader field="srcIp"      label="Source" />
              <SortableHeader field="dstIp"      label="Destination" />
              <th>Protocol</th>
              {hasAppNames   && <th>Application</th>}
              {hasCategories && <th>Category</th>}
              {hasRisks      && <th>Risks</th>}
              <SortableHeader field="packets"    label="Packets" />
              <SortableHeader field="bytes"      label="Bytes" />
              <SortableHeader field="duration"   label="Duration" />
              <SortableHeader field="startTime"  label="Start Time" />
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
                    <span className="fw-semibold">{source.ip}</span>
                    {source.port > 0 && <small className="text-muted">:{source.port}</small>}
                  </td>
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
                  <td>
                    <span className={`badge bg-${getProtocolBadgeClass(conversation.protocol.name)}`}>
                      {conversation.protocol.name}
                    </span>
                  </td>
                  {hasAppNames && (
                    <td>
                      {conversation.appName ? (
                        <span
                          className="badge"
                          style={{ backgroundColor: getAppColor(conversation.appName), color: '#fff' }}
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
                          style={{ backgroundColor: getAppColor(conversation.category), color: '#fff' }}
                        >
                          {conversation.category}
                        </span>
                      ) : (
                        <span className="text-muted">—</span>
                      )}
                    </td>
                  )}
                  {hasRisks && (
                    <td>
                      {conversation.flowRisks && conversation.flowRisks.length > 0 ? (
                        <div className="d-flex flex-wrap gap-1">
                          {conversation.flowRisks.map(risk => (
                            <span
                              key={risk}
                              className="badge bg-warning text-dark"
                              style={{ cursor: 'pointer', fontSize: '0.7rem' }}
                              title="Click to filter by security risks"
                              onClick={e => { e.stopPropagation(); onRiskFilterClick?.(); }}
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
                  <td>{conversation.packetCount.toLocaleString()}</td>
                  <td>{formatBytes(conversation.totalBytes)}</td>
                  <td>{formatDuration(duration)}</td>
                  <td><small>{formatTimestamp(conversation.startTime)}</small></td>
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
