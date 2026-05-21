import { useState, useEffect, useMemo } from 'react';
import { Badge, Button, Form, Modal } from '@govtechsg/sgds-react';
import { Spinner } from '@components/common/Spinner/Spinner';
import { ChangeEventBadge } from '@/components/monitor/ChangeEventBadge/ChangeEventBadge';
import { NetworkInsightsPanel } from '@/components/monitor/NetworkInsightsPanel/NetworkInsightsPanel';
import { NetworkGraph } from '@/components/network/NetworkGraph';
import { NodeDetails } from '@/components/network/NodeDetails';
import { useNetworkData } from '@/features/network/hooks/useNetworkData';
import { insightsService } from '@/features/insights/services/insightsService';
import type { NetworkSnapshot, ChangeEvent } from '@/features/monitor/types/monitor.types';
import type { NetworkInsight, InsightOptions } from '@/features/insights/types/insights.types';
import type { GraphNode } from '@/features/network/types';
import type { NodeHighlight } from '@/components/network/NetworkGraph/NetworkGraph';
import { parseDateTime } from '@/utils/dateUtils';

type Tab = 'diagram' | 'changes' | 'context' | 'insights';

const HIGHLIGHT_COLORS: Record<string, string> = {
  CRITICAL: '#e74c3c',
  WARNING:  '#f39c12',
  INFO:     '#2ecc71',
};

function labelForChange(changeType: string, oldValue: Record<string, unknown> | null, newValue: Record<string, unknown> | null): string {
  switch (changeType) {
    case 'MAC_ADDED':      return 'New device';
    case 'IP_MAC_DRIFT':   return (oldValue?.['mac'] && newValue?.['mac'] && oldValue['mac'] !== newValue['mac']) ? 'Potential ARP spoof' : 'IP reassignment';
    case 'GATEWAY_CHANGE': return 'Gateway changed';
    case 'ASN_CHANGE':     return 'New ISP';
    case 'PROTOCOL_ADDED': return 'New protocol';
    case 'APP_ADDED':      return 'New app';
    case 'VPN_DRIFT':      return newValue?.['riskType'] ? 'VPN detected' : 'VPN stopped';
    default:               return changeType;
  }
}

function severityRank(s: string): number {
  return s === 'CRITICAL' ? 3 : s === 'WARNING' ? 2 : 1;
}

function buildHighlightMap(events: ChangeEvent[], toSnapshotId: string): Map<string, NodeHighlight> {
  const map = new Map<string, NodeHighlight>();
  for (const e of events.filter(ev => ev.toSnapshotId === toSnapshotId)) {
    const color = HIGHLIGHT_COLORS[e.severity] ?? HIGHLIGHT_COLORS.INFO;
    const label = labelForChange(e.changeType, e.oldValue, e.newValue);
    const addHl = (key: string, description?: string) => {
      const existing = map.get(key);
      if (!existing || severityRank(e.severity) > severityRank(existing.label)) {
        map.set(key, { color, label, description });
      }
    };
    switch (e.changeType) {
      case 'MAC_ADDED': {
        const ip = e.newValue?.['ip'] as string | undefined;
        addHl(e.entityKey, `New device appeared${ip ? ` at ${ip}` : ''}`);
        if (ip) addHl(ip, `New device with MAC ${e.entityKey}`);
        break;
      }
      case 'IP_MAC_DRIFT': {
        const oldMac = e.oldValue?.['mac'] as string | undefined;
        const newMac = e.newValue?.['mac'] as string | undefined;
        const oldIp  = e.oldValue?.['ip']  as string | undefined;
        const newIp  = e.newValue?.['ip']  as string | undefined;
        if (oldMac && newMac && oldMac !== newMac) {
          addHl(e.entityKey, `MAC changed from ${oldMac} to ${newMac}`);
          addHl(newMac, `Now claiming IP ${e.entityKey} (was ${oldMac})`);
        } else {
          addHl(e.entityKey, `IP changed from ${oldIp ?? '?'} to ${newIp ?? '?'}`);
          if (newIp) addHl(newIp, `MAC ${e.entityKey} moved here from ${oldIp ?? '?'}`);
        }
        break;
      }
      case 'GATEWAY_CHANGE': {
        const newIp = e.newValue?.['ip'] as string | undefined;
        const oldIp = e.oldValue?.['ip'] as string | undefined;
        if (newIp) addHl(newIp, `New gateway (was ${oldIp ?? '?'})`);
        if (oldIp) addHl(oldIp, `Previous gateway (replaced by ${newIp ?? '?'})`);
        break;
      }
      default: break;
    }
  }
  return map;
}

function formatSnapLabel(snap: NetworkSnapshot): string {
  if (snap.startTime) {
    const ms = parseDateTime(snap.startTime as unknown as string | number[]);
    return new Date(ms).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
  }
  return snap.fileName;
}

interface SnapshotDetailModalProps {
  snapshot: NetworkSnapshot;
  networkId: string;
  changeEvents: ChangeEvent[];
  snapshots: NetworkSnapshot[];
  initialTab?: Tab;
  onPatchChange: (eventId: string, patch: { reviewed?: boolean; notes?: string | null }) => Promise<void>;
  onSnapshotUpdated: (updated: NetworkSnapshot) => void;
  onHide: () => void;
}

export const SnapshotDetailModal = ({
  snapshot,
  networkId,
  changeEvents,
  snapshots,
  initialTab,
  onPatchChange,
  onSnapshotUpdated,
  onHide,
}: SnapshotDetailModalProps) => {
  const [activeTab, setActiveTab] = useState<Tab>(initialTab ?? 'diagram');

  // Diagram tab state
  const sorted = useMemo(() => [...snapshots].sort((a, b) => a.snapshotOrder - b.snapshotOrder), [snapshots]);
  const [diagramSnapshotId, setDiagramSnapshotId] = useState(snapshot.id);
  const [layoutType, setLayoutType] = useState<'circular' | 'hierarchicalTd'>('circular');
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  const diagramSnap = sorted.find(s => s.id === diagramSnapshotId) ?? snapshot;
  const diagramIndex = sorted.findIndex(s => s.id === diagramSnapshotId);
  const prevSnap = diagramIndex > 0 ? sorted[diagramIndex - 1] : null;

  const highlightedNodes = useMemo(
    () => buildHighlightMap(changeEvents, diagramSnap.id),
    [changeEvents, diagramSnap.id],
  );
  const legendItems = useMemo(() => {
    const seen = new Map<string, string>();
    for (const hl of highlightedNodes.values()) {
      if (!seen.has(hl.label)) seen.set(hl.label, hl.color);
    }
    return [...seen.entries()].map(([label, color]) => ({ label, color }));
  }, [highlightedNodes]);

  const { nodes, edges, loading: graphLoading } = useNetworkData(diagramSnap.fileId);

  // Keyboard left/right to navigate snapshots on diagram tab
  useEffect(() => {
    if (activeTab !== 'diagram') return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'ArrowLeft' && diagramIndex > 0) {
        setDiagramSnapshotId(sorted[diagramIndex - 1].id);
      } else if (e.key === 'ArrowRight' && diagramIndex < sorted.length - 1) {
        setDiagramSnapshotId(sorted[diagramIndex + 1].id);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [activeTab, diagramIndex, sorted]);

  // Context tab state
  const [contextDraft, setContextDraft] = useState(snapshot.context ?? '');
  const [notesDraft, setNotesDraft] = useState(snapshot.notes ?? '');
  const [savingContext, setSavingContext] = useState(false);
  const contextChanged = contextDraft !== (snapshot.context ?? '') || notesDraft !== (snapshot.notes ?? '');

  // Insights tab state
  const [insight, setInsight] = useState<NetworkInsight | null>(null);
  const [insightLoaded, setInsightLoaded] = useState(false);

  const snapshotEvents = changeEvents.filter(e => e.toSnapshotId === snapshot.id);

  // Load insight when Insights tab first opened
  useEffect(() => {
    if (activeTab !== 'insights' || insightLoaded) return;
    insightsService.getSnapshotInsight(networkId, snapshot.id).then(ins => {
      setInsight(ins);
      setInsightLoaded(true);
    });
  }, [activeTab, insightLoaded, networkId, snapshot.id]);

  const handleSaveContext = async () => {
    setSavingContext(true);
    try {
      const updated = await insightsService.patchSnapshot(networkId, snapshot.id, {
        context: contextDraft,
        notes: notesDraft,
      });
      onSnapshotUpdated(updated);
    } finally {
      setSavingContext(false);
    }
  };

  const handleGenerateInsight = async (options: InsightOptions) => {
    const ins = await insightsService.generateSnapshotInsight(networkId, snapshot.id, options);
    setInsight(ins);
  };

  return (
    <>
    <Modal show onHide={onHide} centered size="xl" scrollable>
      <Modal.Header closeButton>
        <Modal.Title>
          <i className="bi bi-camera-reels me-2" />
          {snapshot.fileName}
          {snapshot.hasInsights && (
            <Badge bg="primary" className="ms-2" style={{ fontSize: '0.65rem' }}>
              <i className="bi bi-stars me-1" />Insights
            </Badge>
          )}
        </Modal.Title>
      </Modal.Header>

      {/* Tabs */}
      <div className="modal-header py-2 border-bottom">
        <ul className="nav nav-pills gap-1">
          {(['diagram', 'changes', 'context', 'insights'] as Tab[]).map(tab => (
            <li key={tab} className="nav-item">
              <button
                className={`nav-link py-1 px-3${activeTab === tab ? ' active' : ''}`}
                style={{ fontSize: '0.875rem' }}
                onClick={() => setActiveTab(tab)}
              >
                {tab === 'diagram'  && <i className="bi bi-diagram-3 me-1" />}
                {tab === 'changes'  && <i className="bi bi-activity me-1" />}
                {tab === 'context'  && <i className="bi bi-pencil-square me-1" />}
                {tab === 'insights' && <i className="bi bi-stars me-1" />}
                {tab === 'diagram' && 'Network Diagram'}
                {tab === 'changes' && (
                  <>
                    Changes
                    {snapshotEvents.length > 0 && (
                      <span className="badge rounded-pill ms-1" style={{
                        fontSize: '0.6rem',
                        background: snapshotEvents.some(e => e.severity === 'CRITICAL') ? '#dc3545' : '#fd7e14',
                        color: '#fff',
                      }}>
                        {snapshotEvents.length}
                      </span>
                    )}
                  </>
                )}
                {tab === 'context'  && 'Context & Notes'}
                {tab === 'insights' && 'Insights'}
              </button>
            </li>
          ))}
        </ul>
      </div>

      <Modal.Body style={{ minHeight: '480px' }}>

        {/* ── Network Diagram tab ── */}
        {activeTab === 'diagram' && (
          <div>
            <div className="d-flex align-items-center gap-3 mb-3 flex-wrap">
              <div className="d-flex align-items-center gap-2">
                <Button size="sm" variant="outline-secondary"
                  disabled={diagramIndex <= 0}
                  onClick={() => sorted[diagramIndex - 1] && setDiagramSnapshotId(sorted[diagramIndex - 1].id)}
                  title="Previous snapshot"
                >
                  <i className="bi bi-chevron-left" />
                </Button>
                <Form.Select
                  size="sm"
                  style={{ width: 'auto', minWidth: 220 }}
                  value={diagramSnap.id}
                  onChange={e => setDiagramSnapshotId(e.target.value)}
                >
                  {sorted.map((snap, i) => (
                    <option key={snap.id} value={snap.id}>
                      {i + 1}. {formatSnapLabel(snap)} — {snap.fileName}
                    </option>
                  ))}
                </Form.Select>
                <Button size="sm" variant="outline-secondary"
                  disabled={diagramIndex >= sorted.length - 1}
                  onClick={() => sorted[diagramIndex + 1] && setDiagramSnapshotId(sorted[diagramIndex + 1].id)}
                  title="Next snapshot"
                >
                  <i className="bi bi-chevron-right" />
                </Button>
              </div>
              {prevSnap ? (
                <span className="text-muted small">
                  <i className="bi bi-arrow-left-right me-1" />
                  Changes vs <strong>{formatSnapLabel(prevSnap)}</strong>
                </span>
              ) : (
                <span className="text-muted small">Baseline — no previous snapshot to compare</span>
              )}
              {legendItems.length > 0 && (
                <div className="d-flex align-items-center gap-2 ms-auto flex-wrap">
                  {legendItems.map(item => (
                    <span key={item.label} className="d-flex align-items-center gap-1 small">
                      <span style={{ display: 'inline-block', width: 11, height: 11, borderRadius: '50%', background: item.color, flexShrink: 0 }} />
                      {item.label}
                    </span>
                  ))}
                </div>
              )}
            </div>
            <div className="monitor-diagram-graph" style={{ height: 460 }}>
              {graphLoading ? (
                <div className="d-flex align-items-center justify-content-center h-100 text-muted">
                  <Spinner animation="border" size="sm" className="me-2" />Loading graph…
                </div>
              ) : (
                <NetworkGraph
                  key={diagramSnap.id}
                  nodes={nodes}
                  edges={edges}
                  highlightedNodes={highlightedNodes}
                  layoutType={layoutType}
                  onLayoutChange={setLayoutType}
                  onNodeClick={node => setSelectedNode(node)}
                />
              )}
            </div>
            {highlightedNodes.size === 0 && !graphLoading && prevSnap && (
              <div className="text-center text-muted small mt-2">
                <i className="bi bi-check-circle me-1 text-success" />
                No node-level changes detected between these two snapshots.
              </div>
            )}
          </div>
        )}

        {/* ── Changes tab ── */}
        {activeTab === 'changes' && (
          <div>
            {snapshotEvents.length === 0 ? (
              <p className="text-muted mb-0">
                {snapshot.snapshotOrder === 0
                  ? 'This is the baseline snapshot — no changes are compared against it.'
                  : 'No change events detected for this snapshot.'}
              </p>
            ) : (
              snapshotEvents.map(event => (
                <ChangeEventBadge
                  key={event.id}
                  event={event}
                  snapshots={snapshots}
                  onPatch={onPatchChange}
                />
              ))
            )}
          </div>
        )}

        {/* ── Context & Notes tab ── */}
        {activeTab === 'context' && (
          <div>
            <p className="text-muted small mb-3">
              Provide context about this capture — what was happening at the time, what you were
              testing, or any operational notes. This is sent to the AI when generating insights
              for this snapshot.
            </p>
            <label className="form-label fw-semibold small">Context</label>
            <textarea
              className="form-control form-control-sm mb-3"
              rows={4}
              placeholder="e.g. Post-maintenance scan after PLC firmware update on 192.168.1.45. Expected MAC changes on floor 3."
              value={contextDraft}
              onChange={e => setContextDraft(e.target.value)}
            />
            <label className="form-label fw-semibold small">Notes</label>
            <textarea
              className="form-control form-control-sm mb-3"
              rows={3}
              placeholder="Any additional analyst notes…"
              value={notesDraft}
              onChange={e => setNotesDraft(e.target.value)}
            />
            <Button
              size="sm"
              variant="primary"
              onClick={handleSaveContext}
              disabled={savingContext || !contextChanged}
            >
              {savingContext
                ? <><Spinner animation="border" size="sm" className="me-1" />Saving…</>
                : <><i className="bi bi-floppy me-1" />Save</>
              }
            </Button>
          </div>
        )}

        {/* ── Insights tab ── */}
        {activeTab === 'insights' && (
          <div>
            {!insightLoaded ? (
              <div className="text-center py-4">
                <Spinner animation="border" className="text-primary" />
              </div>
            ) : (
              <NetworkInsightsPanel
                insight={insight}
                llmAvailable={true}
                onGenerate={handleGenerateInsight}
              />
            )}
          </div>
        )}
      </Modal.Body>
    </Modal>

    {selectedNode && (
      <NodeDetails
        node={selectedNode}
        edges={edges}
        fileId={diagramSnap.fileId}
        onClose={() => setSelectedNode(null)}
        changeHighlight={highlightedNodes.get(selectedNode.label ?? '') ?? highlightedNodes.get(selectedNode.data.ip ?? '') ?? highlightedNodes.get(selectedNode.data.mac ?? '')}
        zIndex={1070}
      />
    )}
    </>
  );
};
