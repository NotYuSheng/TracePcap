import { Spinner } from '@components/common/Spinner/Spinner';
import { useMemo, useState, useEffect } from 'react';
import { Button, Form, Modal } from '@govtechsg/sgds-react';
import type { NetworkSnapshot, ChangeEvent } from '@/features/monitor/types/monitor.types';
import type { NodeHighlight } from '@/components/network/NetworkGraph/NetworkGraph';
import { NetworkGraph } from '@/components/network/NetworkGraph';
import { NodeDetails } from '@/components/network/NodeDetails';
import type { GraphNode } from '@/features/network/types';
import { useNetworkData } from '@/features/network/hooks/useNetworkData';
import { parseDateTime } from '@/utils/dateUtils';

interface MonitorNetworkDiagramProps {
  show: boolean;
  onHide: () => void;
  initialSnapshotId: string;
  snapshots: NetworkSnapshot[];
  changeEvents: ChangeEvent[];
}

const HIGHLIGHT_COLORS: Record<string, string> = {
  CRITICAL: '#e74c3c',
  WARNING:  '#f39c12',
  INFO:     '#2ecc71',
};

function labelForChange(
  changeType: string,
  oldValue: Record<string, unknown> | null,
  newValue: Record<string, unknown> | null,
): string {
  switch (changeType) {
    case 'MAC_ADDED':      return 'New device';
    case 'IP_MAC_DRIFT':
      // ARP spoof: IP is entityKey, MAC changed (old.mac → new.mac)
      // DHCP drift: MAC is entityKey, IP changed (old.ip → new.ip)
      return (oldValue?.['mac'] && newValue?.['mac'] && oldValue['mac'] !== newValue['mac']) ? 'Potential ARP spoof' : 'IP reassignment';
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
        const oldIp = e.oldValue?.['ip'] as string | undefined;
        const newIp = e.newValue?.['ip'] as string | undefined;
        if (oldMac && newMac && oldMac !== newMac) {
          // ARP spoof: entityKey is the IP, MAC changed
          addHl(e.entityKey, `MAC changed from ${oldMac} to ${newMac}`);
          addHl(newMac, `Now claiming IP ${e.entityKey} (was ${oldMac})`);
        } else {
          // DHCP reassignment: entityKey is the MAC, IP changed
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
      default:
        break;
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

export const MonitorNetworkDiagram = ({
  show,
  onHide,
  initialSnapshotId,
  snapshots,
  changeEvents,
}: MonitorNetworkDiagramProps) => {
  const sorted = useMemo(
    () => [...snapshots].sort((a, b) => a.snapshotOrder - b.snapshotOrder),
    [snapshots],
  );

  const [selectedId, setSelectedId] = useState<string>(initialSnapshotId);
  const [layoutType, setLayoutType] = useState<'forceDirected2d' | 'hierarchicalTd'>('forceDirected2d');
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  // Sync to the clicked snapshot each time the modal opens
  useEffect(() => {
    if (show && initialSnapshotId) {
      setSelectedId(initialSnapshotId);
      setSelectedNode(null);
    }
  }, [show, initialSnapshotId]);

  const selectedIndex = sorted.findIndex(s => s.id === selectedId);

  // Arrow key navigation between snapshots (only when NodeDetails is not open)
  useEffect(() => {
    if (!show) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (selectedNode) return;
      if (e.key === 'ArrowLeft' && selectedIndex > 0) {
        e.preventDefault();
        setSelectedId(sorted[selectedIndex - 1].id);
      } else if (e.key === 'ArrowRight' && selectedIndex < sorted.length - 1) {
        e.preventDefault();
        setSelectedId(sorted[selectedIndex + 1].id);
      }
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [show, selectedIndex, sorted, selectedNode]);

  const selectedSnap = sorted[selectedIndex] ?? sorted[sorted.length - 1] ?? null;
  const prevSnap = selectedIndex > 0 ? sorted[selectedIndex - 1] : null;

  const highlightedNodes = useMemo(() => {
    if (!selectedSnap) return undefined;
    return buildHighlightMap(changeEvents, selectedSnap.id);
  }, [changeEvents, selectedSnap]);

  const { nodes, edges, loading } = useNetworkData(selectedSnap?.fileId ?? '');

  const legendItems = useMemo(() => {
    if (!highlightedNodes) return [];
    const seen = new Map<string, string>();
    for (const hl of highlightedNodes.values()) {
      if (!seen.has(hl.label)) seen.set(hl.label, hl.color);
    }
    return [...seen.entries()].map(([label, color]) => ({ label, color }));
  }, [highlightedNodes]);

  return (
    <>
    <Modal show={show} onHide={onHide} centered size="xl">
      <Modal.Header closeButton>
        <Modal.Title>
          <i className="bi bi-diagram-3 me-2"></i>
          Network Diagram — {selectedSnap?.fileName ?? ''}
        </Modal.Title>
      </Modal.Header>

      <Modal.Body style={{ padding: '1rem 1.25rem' }}>
        {/* Snapshot selector + comparison info */}
        <div className="d-flex align-items-center gap-3 mb-3 flex-wrap">
          <div className="d-flex align-items-center gap-2">
            <Button
              size="sm"
              variant="outline-secondary"
              disabled={selectedIndex <= 0}
              onClick={() => sorted[selectedIndex - 1] && setSelectedId(sorted[selectedIndex - 1].id)}
              title="Previous snapshot"
            >
              <i className="bi bi-chevron-left" />
            </Button>
            <Form.Select
              size="sm"
              style={{ width: 'auto', minWidth: 220 }}
              value={selectedSnap?.id ?? ''}
              onChange={e => setSelectedId(e.target.value)}
            >
              {sorted.map((snap, i) => (
                <option key={snap.id} value={snap.id}>
                  {i + 1}. {formatSnapLabel(snap)} — {snap.fileName}
                </option>
              ))}
            </Form.Select>
            <Button
              size="sm"
              variant="outline-secondary"
              disabled={selectedIndex >= sorted.length - 1}
              onClick={() => sorted[selectedIndex + 1] && setSelectedId(sorted[selectedIndex + 1].id)}
              title="Next snapshot"
            >
              <i className="bi bi-chevron-right" />
            </Button>
          </div>

          {prevSnap ? (
            <span className="text-muted small">
              <i className="bi bi-arrow-left-right me-1"></i>
              Changes vs <strong>{formatSnapLabel(prevSnap)}</strong>
            </span>
          ) : (
            <span className="text-muted small">Baseline — no previous snapshot to compare</span>
          )}

          {legendItems.length > 0 && (
            <div className="d-flex align-items-center gap-2 ms-auto flex-wrap">
              {legendItems.map(item => (
                <span key={item.label} className="d-flex align-items-center gap-1 small">
                  <span style={{
                    display: 'inline-block', width: 11, height: 11, borderRadius: '50%',
                    background: item.color, flexShrink: 0,
                  }} />
                  {item.label}
                </span>
              ))}
            </div>
          )}
        </div>

        {/* Graph — fixed height; network-graph-wrapper height overridden to 100% via class */}
        <div className="monitor-diagram-graph" style={{ height: 480 }}>
          {loading ? (
            <div className="d-flex align-items-center justify-content-center h-100 text-muted">
              <Spinner animation="border" size="sm" className="me-2" />
              Loading graph…
            </div>
          ) : (
            <NetworkGraph
              nodes={nodes}
              edges={edges}
              highlightedNodes={highlightedNodes}
              layoutType={layoutType}
              onLayoutChange={setLayoutType}
              onNodeClick={node => setSelectedNode(node)}
            />
          )}
        </div>

        {highlightedNodes && highlightedNodes.size === 0 && !loading && prevSnap && (
          <div className="text-center text-muted small mt-2">
            <i className="bi bi-check-circle me-1 text-success"></i>
            No node-level changes detected between these two snapshots.
          </div>
        )}
      </Modal.Body>
    </Modal>

    {selectedNode && selectedSnap && (
      <NodeDetails
        node={selectedNode}
        edges={edges}
        fileId={selectedSnap.fileId}
        onClose={() => setSelectedNode(null)}
        changeHighlight={highlightedNodes?.get(selectedNode.label ?? '') ?? highlightedNodes?.get(selectedNode.data.ip ?? '') ?? highlightedNodes?.get(selectedNode.data.mac ?? '')}
        zIndex={1070}
      />
    )}
    </>
  );
};
