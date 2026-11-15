import { useState, useEffect, useCallback } from 'react';
import { Button, Form } from '@govtechsg/sgds-react';
import { useOutletContext, useSearchParams } from 'react-router-dom';
import type { AnalysisData, Conversation, HostClassification } from '@/types';
import type { SortField } from '@/features/conversation/types';
import { useConversationFilters } from '@/features/conversation/hooks/useConversationFilters';
import { conversationService } from '@/features/conversation/services/conversationService';
import { clusterApi } from '@/features/cluster/services/clusterApi';
import { ConversationListCompact } from '@components/conversation/ConversationListCompact';
import './ConversationPage.css';
import { ConversationDetail } from '@components/conversation/ConversationDetail';
import { ConversationTracerModal } from '@components/conversation/ConversationTracer/ConversationTracerModal';
import { ConversationFilterPanel } from '@components/conversation/ConversationFilterPanel';
import { LoadingSpinner } from '@components/common/LoadingSpinner';
import { ErrorMessage } from '@components/common/ErrorMessage';
import { Pagination } from '@components/common/Pagination';
import { formatIpPort } from '@/utils/formatters';

/** Produces a consistent export filename: tracepcap_<base>[_<ipSuffix>]_<timestamp>.<ext> */
function makeExportFilename(base: string, ext: string, ipSuffix?: string): string {
  const ts = new Date().toISOString().slice(0, 19).replace('T', '_').replace(/:/g, '-');
  return ipSuffix ? `tracepcap_${base}_${ipSuffix}_${ts}.${ext}` : `tracepcap_${base}_${ts}.${ext}`;
}

interface AnalysisOutletContext {
  data: AnalysisData;
  fileId: string;
}

export const ConversationPage = () => {
  const { fileId, data } = useOutletContext<AnalysisOutletContext>();
  const [searchParams, setSearchParams] = useSearchParams();
  const { filters, activeFilterCount, setFilters, clearAll } = useConversationFilters();

  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [selectedConversation, setSelectedConversation] = useState<Conversation | null>(null);
  const [selectedIndex, setSelectedIndex] = useState<number>(-1);
  const [detailLoading, setDetailLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [totalItems, setTotalItems] = useState(0);
  const [totalPages, setTotalPages] = useState(0);
  const [fileTypeOptions, setFileTypeOptions] = useState<string[]>([]);
  const [riskTypeOptions, setRiskTypeOptions] = useState<string[]>([]);
  const [customSignatureOptions, setCustomSignatureOptions] = useState<string[]>([]);
  const [suricataAlertOptions, setSuricataAlertOptions] = useState<string[]>([]);
  const [countryOptions, setCountryOptions] = useState<string[]>([]);
  const [signatureSeverities, setSignatureSeverities] = useState<Record<string, string>>({});
  const [signatureScopes, setSignatureScopes] = useState<Record<string, string>>({});
  const [hostClassMap, setHostClassMap] = useState<Map<string, HostClassification>>(new Map());
  const [tracerConversationId, setTracerConversationId] = useState<string | null>(null);
  const [highlightPacket, setHighlightPacket] = useState<number | null>(null);

  // Fetch available file types and risk types once per file
  useEffect(() => {
    if (!fileId) return;
    conversationService.getFileTypes(fileId).then(setFileTypeOptions).catch(console.error);
    conversationService.getRiskTypes(fileId).then(setRiskTypeOptions).catch(console.error);
    conversationService
      .getCustomSignatures(fileId, filters.networkId)
      .then(setCustomSignatureOptions)
      .catch(console.error);
    // Clear first so stale options from the previous file aren't shown while/if the fetch fails.
    setSuricataAlertOptions([]);
    conversationService
      .getSuricataAlerts(fileId)
      .then(setSuricataAlertOptions)
      .catch(err => {
        console.error(err);
        setSuricataAlertOptions([]);
      });
    conversationService
      .getSignatureRules(fileId, filters.networkId)
      .then(rules => {
        const map: Record<string, string> = {};
        const scopes: Record<string, string> = {};
        rules.forEach(r => {
          map[r.name] = r.severity;
          scopes[r.name] = r.scope;
        });
        setSignatureSeverities(map);
        setSignatureScopes(scopes);
      })
      .catch(console.error);
    conversationService
      .getHostClassifications(fileId)
      .then(list => setHostClassMap(new Map(list.map(c => [c.ip, c]))))
      .catch(console.error);
    conversationService.getCountries(fileId).then(setCountryOptions).catch(console.error);
  }, [fileId, filters.networkId]);

  // One-shot migration of legacy URL params from NodeDetails and Overview navigation
  useEffect(() => {
    const srcIp = searchParams.get('srcIp');
    const peerIp = searchParams.get('peerIp');
    const app = searchParams.get('app');
    if (srcIp || peerIp || app) {
      const next = new URLSearchParams(searchParams);
      if (srcIp || peerIp) {
        next.set('ip', srcIp ?? peerIp ?? '');
        next.delete('srcIp');
        next.delete('peerIp');
      }
      if (app) {
        next.set('apps', app);
        next.delete('app');
      }
      setSearchParams(next, { replace: true });
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-open conversation modal when navigated here with ?highlight=<conversationId>
  // (e.g. from the "View conversation" link on the Extracted Files page)
  useEffect(() => {
    const highlightId = searchParams.get('highlight');
    if (!highlightId) return;
    const next = new URLSearchParams(searchParams);
    next.delete('highlight');
    setSearchParams(next, { replace: true });
    setDetailLoading(true);
    conversationService
      .getConversationDetail(highlightId, filters.networkId)
      .then(conv => {
        setSelectedConversation(conv);
        setSelectedIndex(-1);
      })
      .catch(err => console.error('Failed to load highlighted conversation:', err))
      .finally(() => setDetailLoading(false));
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-open the conversation containing a specific packet when navigated with ?packet=<frameNumber>
  // (e.g. from a "view packet" link in the DNS / HTTP service tabs), then highlight that packet.
  useEffect(() => {
    const packetParam = searchParams.get('packet');
    if (!packetParam) return;
    const frame = Number(packetParam);
    const next = new URLSearchParams(searchParams);
    next.delete('packet');
    setSearchParams(next, { replace: true });
    if (!Number.isSafeInteger(frame) || frame <= 0) return;
    setDetailLoading(true);
    clusterApi
      .getPacketLocation(fileId, frame)
      .then(loc => {
        if (!loc) return undefined;
        return conversationService.getConversationDetail(loc.conversationId, filters.networkId).then(conv => {
          setSelectedConversation(conv);
          setSelectedIndex(-1);
          setHighlightPacket(frame);
        });
      })
      .catch(err => console.error('Failed to open packet:', err))
      .finally(() => setDetailLoading(false));
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Fetch conversations whenever filters change
  useEffect(() => {
    if (!fileId) return;
    let cancelled = false;
    setLoading(true);
    setError(null);
    conversationService
      .getConversations(fileId, filters)
      .then(r => {
        if (cancelled) return;
        setConversations(r.data);
        setTotalItems(r.total);
        setTotalPages(r.totalPages);
      })
      .catch(e => {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : 'Failed to load conversations');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [fileId, filters]);

  const openConversation = useCallback(async (conversation: Conversation, index: number) => {
    setSelectedIndex(index);
    setDetailLoading(true);
    try {
      if (conversation.packets && conversation.packets.length > 0) {
        setSelectedConversation(conversation);
      } else {
        const full = await conversationService.getConversationDetail(conversation.id, filters.networkId);
        setSelectedConversation(full);
      }
    } catch (err) {
      console.error('Failed to load conversation details:', err);
      setSelectedConversation(conversation);
    } finally {
      setDetailLoading(false);
    }
  }, [filters.networkId]);

  // List and detail: something is always shown. Pick the first conversation when nothing (or a
  // conversation no longer on this page) is selected, and keep the selected row in view.
  useEffect(() => {
    if (conversations.length === 0) return;
    if (!selectedConversation || !conversations.some(c => c.id === selectedConversation.id)) {
      if (selectedIndex === -1 && selectedConversation) return; // a deep link, kept as is
      openConversation(conversations[0], 0);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [conversations]);
  useEffect(() => {
    if (!selectedConversation) return;
    document
      .querySelector(`[data-conversation-id="${selectedConversation.id}"]`)
      ?.scrollIntoView({ block: 'nearest' });
  }, [selectedConversation]);


  const exportConversationCsv = useCallback((conversation: Conversation) => {
    const hexToAscii = (hex: string) => {
      if (!hex) return '';
      let out = '';
      for (let i = 0; i < hex.length; i += 2) {
        const byte = parseInt(hex.slice(i, i + 2), 16);
        out += byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : '.';
      }
      return out;
    };
    const esc = (v: unknown) => {
      const s = v == null ? '' : String(v);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const rows: string[] = [];
    // Summary header + row
    rows.push(
      'srcIp,srcPort,dstIp,dstPort,protocol,appName,category,hostname,packetCount,totalBytes,startTime,endTime,flowRisks,customSignatures'
    );
    rows.push(
      [
        esc(conversation.endpoints[0].ip),
        esc(conversation.endpoints[0].port),
        esc(conversation.endpoints[1].ip),
        esc(conversation.endpoints[1].port),
        esc(conversation.protocol.name),
        esc(conversation.appName),
        esc(conversation.category),
        esc(conversation.hostname),
        esc(conversation.packetCount),
        esc(conversation.totalBytes),
        esc(conversation.startTime),
        esc(conversation.endTime),
        esc((conversation.flowRisks ?? []).join('; ')),
        esc((conversation.customSignatures ?? []).join('; ')),
      ].join(',')
    );
    // Packets
    if (conversation.packets && conversation.packets.length > 0) {
      rows.push('');
      rows.push(
        'packetNumber,timestamp,srcIp,srcPort,dstIp,dstPort,protocol,size,info,hexPayload,asciiPayload'
      );
      conversation.packets.forEach((p, i) => {
        rows.push(
          [
            esc(i + 1),
            esc(p.timestamp),
            esc(p.source.ip),
            esc(p.source.port),
            esc(p.destination.ip),
            esc(p.destination.port),
            esc(p.protocol.name),
            esc(p.size),
            esc(p.info),
            esc(p.payload),
            esc(hexToAscii(p.payload)),
          ].join(',')
        );
      });
    }
    const blob = new Blob([rows.join('\n')], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const base = (data.fileName ?? 'conversations').replace(/\.[^.]+$/, '');
    const src = conversation.endpoints[0].ip.replace(/[^a-zA-Z0-9.]/g, '_');
    const dst = conversation.endpoints[1].ip.replace(/[^a-zA-Z0-9.]/g, '_');
    a.download = makeExportFilename(base, 'csv', `${src}-${dst}`);
    a.href = url;
    a.click();
    URL.revokeObjectURL(url);
  }, []);

  const handlePrev = useCallback(() => {
    if (selectedIndex > 0) openConversation(conversations[selectedIndex - 1], selectedIndex - 1);
  }, [selectedIndex, conversations, openConversation]);

  const handleNext = useCallback(() => {
    if (selectedIndex < conversations.length - 1)
      openConversation(conversations[selectedIndex + 1], selectedIndex + 1);
  }, [selectedIndex, conversations, openConversation]);

  // Escape is deliberately absent: the SGDS modal already closes itself through `onHide`, and a
  // second handler here would also fire for a layer stacked above it (the tracer overlay, a host
  // detail panel) and close the conversation out from under it (#535).
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (!selectedConversation) return;
      const t = e.target as HTMLElement | null;
      if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable)) return;
      const back = e.key === 'ArrowLeft' || e.key === 'ArrowUp';
      const fwd = e.key === 'ArrowRight' || e.key === 'ArrowDown';
      if (back || fwd) e.preventDefault();
      if (back) handlePrev();
      if (fwd) handleNext();
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [selectedConversation, handlePrev, handleNext]);



  // Filter options from the already-loaded analysis summary
  const protocolOptions = (data.protocolDistribution ?? []).map(p => ({
    protocol: p.protocol,
    count: p.count,
  }));
  const appOptions = (data.detectedApplications ?? []).map(a => ({ name: a.name }));
  const categoryOptions = (data.categoryDistribution ?? []).map(c => ({ category: c.category }));
  const presentDeviceTypes = [
    ...new Set(
      Array.from(hostClassMap.values())
        .map(h => h.deviceType)
        .filter(Boolean)
    ),
  ];

  // CSV export URL
  const exportUrl = conversationService.getExportUrl(fileId, filters);
  const pcapExportUrl = conversationService.getPcapExportUrl(fileId, filters);
  const exportBase = (data.fileName ?? 'conversations').replace(/\.[^.]+$/, '');
  const exportFilename = makeExportFilename(exportBase, 'csv');
  const pcapExportFilename = makeExportFilename(exportBase, 'pcap');

  const modalTitle = selectedConversation
    ? `${formatIpPort(selectedConversation.endpoints[0].ip, selectedConversation.endpoints[0].port)} ↔ ${formatIpPort(selectedConversation.endpoints[1].ip, selectedConversation.endpoints[1].port)}`
    : '';

  if (error) return <ErrorMessage title="Failed to Load Conversations" message={error} />;

  return (
    <div className="conversation-page">
      <div className="row mb-3">
        <div className="col-12">
          <div className="d-flex justify-content-between align-items-center mb-3">
            <h4 className="mb-0">
              Network Conversations
              <span className="text-muted fs-6 fw-normal ms-2">
                ({totalItems.toLocaleString()})
              </span>
            </h4>
            <div className="d-flex gap-2 align-items-center">
              <a
                href={exportUrl}
                download={exportFilename}
                className="btn btn-sm btn-outline-secondary"
                role="button"
                title="Export current filtered results as CSV"
              >
                <i className="bi bi-download me-1"></i>
                Export CSV
              </a>
              <a
                href={pcapExportUrl}
                download={pcapExportFilename}
                className="btn btn-sm btn-outline-secondary"
                role="button"
                title="Export current filtered results as PCAP"
              >
                <i className="bi bi-download me-1"></i>
                Export PCAP
              </a>
            </div>
          </div>

          <ConversationFilterPanel
            filters={filters}
            onFiltersChange={setFilters}
            onClearAll={clearAll}
            protocols={protocolOptions}
            l7Protocols={data.detectedL7Protocols ?? []}
            apps={appOptions}
            categories={categoryOptions}
            fileTypes={fileTypeOptions}
            riskTypes={riskTypeOptions}
            customSignatureOptions={customSignatureOptions}
            suricataAlertOptions={suricataAlertOptions}
            signatureSeverities={signatureSeverities}
            signatureScopes={signatureScopes}
            countryOptions={countryOptions}
            presentDeviceTypes={presentDeviceTypes}
            activeFilterCount={activeFilterCount}
          />
        </div>
      </div>

        <div className="conv-split">
          <section className="conv-list-card" aria-label="Conversation list">
            <div className="conv-list-head">
              <Form.Label htmlFor="conv-sort" className="mb-0 small text-muted">
                Sort
              </Form.Label>
              <Form.Select
                id="conv-sort"
                size="sm"
                className="conv-sort"
                value={`${filters.sortBy}:${filters.sortDir}`}
                onChange={e => {
                  const [sortBy, sortDir] = e.target.value.split(':') as [SortField, 'asc' | 'desc'];
                  setFilters({ sortBy, sortDir, page: 1 });
                }}
              >
                <option value=":asc">In capture order</option>
                <option value="startTime:desc">Newest first</option>
                <option value="bytes:desc">Most bytes</option>
                <option value="packets:desc">Most packets</option>
                <option value="duration:desc">Longest</option>
                <option value="srcIp:asc">Source address</option>
                <option value="dstIp:asc">Destination address</option>
              </Form.Select>
            </div>
            <div className="conv-list-scroll" style={{ opacity: loading ? 0.4 : 1 }}>
              {loading && conversations.length === 0 && (
                <LoadingSpinner size="medium" message="Loading conversations..." />
              )}
              {!loading && conversations.length === 0 && (
                <p className="text-muted small p-3 mb-0">No conversations match these filters.</p>
              )}
              <ConversationListCompact
                conversations={conversations}
                selectedId={selectedConversation?.id ?? null}
                onSelect={(c, i) => openConversation(c, i)}
              />
            </div>
            {totalPages > 1 && (
              <div className="conv-list-foot">
                <Pagination
                  currentPage={filters.page}
                  totalPages={totalPages}
                  onPageChange={page => setFilters({ page })}
                  pageSize={filters.pageSize}
                  totalItems={totalItems}
                  showPageSizeSelector
                  onPageSizeChange={pageSize => setFilters({ pageSize, page: 1 })}
                />
              </div>
            )}
          </section>
          <section className="conv-pane" aria-label="Conversation detail">
            {selectedConversation ? (
              <>
                <div className="conv-pane-head">
                  <h2 className="conv-pane-title">{modalTitle}</h2>
                  <div className="conv-pane-actions">
          <Button
            type="button"
            size="sm"
            variant="outline-info"
            className="ms-2"
            onClick={() => selectedConversation && setTracerConversationId(selectedConversation.id)}
            title="Step through packets with AI explanations"
          >
            <i className="bi bi-play-circle me-1"></i>Trace
          </Button>
          <Button
            type="button"
            size="sm"
            variant="outline-secondary"
            className="ms-2"
            onClick={() => selectedConversation && exportConversationCsv(selectedConversation)}
            title="Export this conversation as CSV"
          >
            <i className="bi bi-download me-1"></i>CSV
          </Button>
          {selectedConversation && (
            <a
              href={conversationService.getConversationPcapExportUrl(selectedConversation.id)}
              download={makeExportFilename(
                exportBase,
                'pcap',
                `${selectedConversation.endpoints[0].ip.replace(/[^a-zA-Z0-9.]/g, '_')}-${selectedConversation.endpoints[1].ip.replace(/[^a-zA-Z0-9.]/g, '_')}`
              )}
              className="btn btn-sm btn-outline-secondary ms-2"
              title="Export this conversation as PCAP"
            >
              <i className="bi bi-download me-1"></i>PCAP
            </a>
          )}
                  </div>
                </div>
                <div className="conv-pane-body">
          {detailLoading ? (
            <LoadingSpinner size="medium" message="Loading conversation..." />
          ) : (
            selectedConversation && (
              <ConversationDetail
                conversation={selectedConversation}
                signatureSeverities={signatureSeverities}
                signatureScopes={signatureScopes}
                hostClassMap={hostClassMap}
                fileId={fileId}
                highlightPacketNumber={highlightPacket}
                bare
              />
            )
          )}
                </div>
              </>
            ) : (
              <p className="text-muted small p-4 mb-0">Pick a conversation on the left to see it here.</p>
            )}
          </section>
        </div>

      {/* Conversation Tracer modal */}
      {tracerConversationId && (
        <ConversationTracerModal
          conversationId={tracerConversationId}
          onClose={() => setTracerConversationId(null)}
        />
      )}
    </div>
  );
};
