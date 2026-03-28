import { useState, useEffect, useRef, useCallback } from 'react';
import type { Conversation } from '@/types';
import type { SortField, SortDir } from '@/features/conversation/types';
import type { ColumnKey } from '@/features/conversation/constants';
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
  visibleColumns: Set<ColumnKey>;
}

export const ConversationList = ({
  conversations,
  onSelectConversation,
  sortBy,
  sortDir,
  onSort,
  onRiskFilterClick,
  visibleColumns,
}: ConversationListProps) => {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [scrolledEnd, setScrolledEnd] = useState(false);
  const scrollRef   = useRef<HTMLDivElement>(null);
  const topBarRef   = useRef<HTMLDivElement>(null);
  const topInnerRef = useRef<HTMLDivElement>(null);
  const syncingRef  = useRef(false);

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

  // Persistent middle-click auto-scroll — like native browser auto-scroll.
  // Middle-click once to enter pan mode; mouse position relative to the origin
  // point drives continuous scrolling (further = faster). Any click exits.
  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;

    let panMode = false;
    let originX = 0;
    let originY = 0;
    let currentX = 0;
    let currentY = 0;
    let rafId = 0;
    let indicator: HTMLDivElement | null = null;

    const DEAD_ZONE = 8;    // px from origin before scrolling starts
    const SPEED = 0.12;     // scroll px per animation frame per px of offset

    const showIndicator = (x: number, y: number) => {
      indicator = document.createElement('div');
      indicator.className = 'conv-pan-indicator';
      indicator.style.left = `${x}px`;
      indicator.style.top = `${y}px`;
      document.body.appendChild(indicator);
    };

    const hideIndicator = () => {
      indicator?.remove();
      indicator = null;
    };

    const animate = () => {
      if (!panMode) return;
      const dx = currentX - originX;
      const dy = currentY - originY;
      if (Math.abs(dx) > DEAD_ZONE || Math.abs(dy) > DEAD_ZONE) {
        el.scrollLeft += dx * SPEED;       // horizontal: table container
        window.scrollBy(0, dy * SPEED);    // vertical: page
      }
      rafId = requestAnimationFrame(animate);
    };

    const enterPan = (e: MouseEvent) => {
      if (e.button !== 1) return;
      e.preventDefault();
      if (panMode) { exitPan(); return; }   // second middle-click exits
      panMode = true;
      originX = currentX = e.clientX;
      originY = currentY = e.clientY;
      el.style.cursor = 'all-scroll';
      showIndicator(e.clientX, e.clientY);
      rafId = requestAnimationFrame(animate);
    };

    const onMouseMove = (e: MouseEvent) => {
      currentX = e.clientX;
      currentY = e.clientY;
    };

    const onAnyClick = (e: MouseEvent) => {
      // Middle mousedown handled by enterPan; left/right clicks exit pan mode
      if (panMode && e.button !== 1) exitPan();
    };

    const exitPan = () => {
      if (!panMode) return;
      panMode = false;
      el.style.cursor = '';
      cancelAnimationFrame(rafId);
      hideIndicator();
    };

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') exitPan();
    };

    // Suppress the browser's native auto-scroll indicator
    const onAuxClick = (e: MouseEvent) => { if (e.button === 1) e.preventDefault(); };

    el.addEventListener('mousedown', enterPan);
    el.addEventListener('mousedown', onAnyClick);
    el.addEventListener('auxclick', onAuxClick);
    window.addEventListener('mousemove', onMouseMove);
    window.addEventListener('keydown', onKeyDown);

    return () => {
      exitPan();
      el.removeEventListener('mousedown', enterPan);
      el.removeEventListener('mousedown', onAnyClick);
      el.removeEventListener('auxclick', onAuxClick);
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('keydown', onKeyDown);
    };
  }, []);

  const hasAppNames   = conversations.some(c => c.appName);
  const hasCategories = conversations.some(c => c.category);
  const hasRisks      = conversations.some(c => c.flowRisks && c.flowRisks.length > 0);

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
    const handleClick = () => {
      if (!isActive) onSort(field);
      else if (sortDir === 'asc') onSort(field);
      else onSort('' as SortField);
    };
    return (
      <th onClick={handleClick} style={{ cursor: 'pointer', userSelect: 'none', whiteSpace: 'nowrap' }}>
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
      >
        <table className="table table-hover">
          <thead>
            <tr>
              {col('source')      && <SortableHeader field="srcIp"     label="Source" />}
              {col('destination') && <SortableHeader field="dstIp"     label="Destination" />}
              {col('protocol')    && <th>Protocol</th>}
              {col('appName')  && hasAppNames   && <th>Application</th>}
              {col('category') && hasCategories && <th>Category</th>}
              {col('risks')    && hasRisks      && <th>Risks</th>}
              {col('packets')     && <SortableHeader field="packets"   label="Packets" />}
              {col('bytes')       && <SortableHeader field="bytes"     label="Bytes" />}
              {col('duration')    && <SortableHeader field="duration"  label="Duration" />}
              {col('startTime')   && <SortableHeader field="startTime" label="Start Time" />}
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
                        {destination.port > 0 && <small className="text-muted">:{destination.port}</small>}
                      </div>
                      {conversation.hostname && <small className="text-info">{conversation.hostname}</small>}
                    </td>
                  )}
                  {col('protocol') && (
                    <td>
                      <span className={`badge bg-${getProtocolBadgeClass(conversation.protocol.name)}`}>
                        {conversation.protocol.name}
                      </span>
                    </td>
                  )}
                  {col('appName') && hasAppNames && (
                    <td>
                      {conversation.appName
                        ? <span className="badge" style={{ backgroundColor: getAppColor(conversation.appName), color: '#fff' }}>{conversation.appName}</span>
                        : <span className="text-muted">—</span>}
                    </td>
                  )}
                  {col('category') && hasCategories && (
                    <td>
                      {conversation.category
                        ? <span className="badge" style={{ backgroundColor: getAppColor(conversation.category), color: '#fff' }}>{conversation.category}</span>
                        : <span className="text-muted">—</span>}
                    </td>
                  )}
                  {col('risks') && hasRisks && (
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
                      ) : <span className="text-muted">—</span>}
                    </td>
                  )}
                  {col('packets')   && <td>{conversation.packetCount.toLocaleString()}</td>}
                  {col('bytes')     && <td>{formatBytes(conversation.totalBytes)}</td>}
                  {col('duration')  && <td>{formatDuration(duration)}</td>}
                  {col('startTime') && <td><small>{formatTimestamp(conversation.startTime)}</small></td>}
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
