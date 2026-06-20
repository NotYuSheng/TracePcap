import { useState, useEffect, useCallback, useMemo } from 'react';
import { Modal, Button, Form } from '@govtechsg/sgds-react';
import { Spinner } from '@components/common/Spinner/Spinner';
import { NetworkGraph } from '@/components/network/NetworkGraph';
import { EntityDetailModal } from '@components/common/EntityDetailModal';
import { apiClient } from '@/services/api/client';
import { networkService } from '@/features/network/services/networkService';
import { conversationService } from '@/features/conversation/services/conversationService';
import type { SubnetDefinition } from '@/features/subnets/types/subnet.types';
import type { NetworkSnapshot } from '@/features/monitor/types/monitor.types';
import type { GraphNode } from '@/features/network/types';
import type { ConversationFilters } from '@/features/conversation/types';
import type { Conversation } from '@/types';

interface SubnetDiagramModalProps {
  subnet: SubnetDefinition;
  snapshots: NetworkSnapshot[];
  onHide: () => void;
  defaultSnapId?: string;
}

interface HostClassification {
  ip: string | null;
  mac: string | null;
  manufacturer: string | null;
  deviceType: string | null;
  confidence: number | null;
  ttl: number | null;
}

function ipToInt(ip: string): number {
  const parts = ip.split('.').map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function ipInCidr(ip: string, cidr: string): boolean {
  try {
    const [base, bits] = cidr.split('/');
    const mask = bits ? (0xffffffff << (32 - parseInt(bits))) >>> 0 : 0xffffffff;
    return (ipToInt(ip) & mask) === (ipToInt(base) & mask);
  } catch {
    return false;
  }
}

export function SubnetDiagramModal({ subnet, snapshots, onHide, defaultSnapId }: SubnetDiagramModalProps) {
  const sorted = useMemo(() => [...snapshots].sort((a, b) => a.snapshotOrder - b.snapshotOrder), [snapshots]);
  const [selectedSnapId, setSelectedSnapId] = useState(defaultSnapId ?? sorted[sorted.length - 1]?.id ?? '');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<ReturnType<typeof networkService.buildNetworkGraph>['edges']>([]);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  const selectedSnap = sorted.find(s => s.id === selectedSnapId);

  const load = useCallback(async (snapId: string) => {
    const snap = sorted.find(s => s.id === snapId);
    if (!snap) return;
    setLoading(true);
    setError(null);
    setNodes([]);
    setEdges([]);
    try {
      const filters: ConversationFilters = {
        ip: '', port: '', payloadContains: '', protocols: [], l7Protocols: [],
        apps: [], categories: [], hasRisks: false, fileTypes: [], riskTypes: [],
        customSignatures: [], suricataAlerts: [], deviceTypes: [], countries: [],
        sortBy: 'startTime' as ConversationFilters['sortBy'],
        sortDir: 'desc' as ConversationFilters['sortDir'],
        page: 1, pageSize: 10000,
      };
      const [convResponse, hostClassifications] = await Promise.all([
        conversationService.getConversations(snap.fileId, filters),
        apiClient
          .get<HostClassification[]>(`/files/${snap.fileId}/host-classifications`)
          .then(r => r.data)
          .catch(() => [] as HostClassification[]),
      ]);

      // Filter conversations to those involving at least one IP in this subnet
      const allConvs = convResponse.data as Conversation[];
      const subnetConvs = allConvs.filter(
        c => ipInCidr(c.endpoints[0].ip, subnet.cidr) || ipInCidr(c.endpoints[1].ip, subnet.cidr)
      );

      if (subnetConvs.length === 0) {
        setLoading(false);
        return;
      }

      const graph = networkService.buildNetworkGraph(
        subnetConvs,
        undefined,
        10000,
        hostClassifications as Parameters<typeof networkService.buildNetworkGraph>[3],
        0, // no node limit
      );
      setNodes(graph.nodes);
      setEdges(graph.edges);
    } catch {
      setError('Failed to load subnet traffic data.');
    } finally {
      setLoading(false);
    }
  }, [sorted, subnet.cidr]);

  useEffect(() => {
    if (selectedSnapId) load(selectedSnapId);
  }, [selectedSnapId, load]);

  return (
    <>
      <Modal show onHide={onHide} size="xl" centered>
        <Modal.Header closeButton>
          <Modal.Title>
            <i className="bi bi-diagram-2 me-2" />
            {subnet.label ? (
              <>{subnet.label} <span className="font-monospace fw-normal text-muted" style={{ fontSize: '0.85em' }}>({subnet.cidr})</span></>
            ) : (
              <span className="font-monospace">{subnet.cidr}</span>
            )}
          </Modal.Title>
        </Modal.Header>

        <Modal.Body className="p-0" style={{ height: '75vh', display: 'flex', flexDirection: 'column' }}>
          {/* Snapshot selector */}
          <div className="d-flex align-items-center gap-2 px-3 py-2 border-bottom">
            <small className="text-muted fw-semibold">Snapshot:</small>
            <Form.Select
              size="sm"
              style={{ width: 'auto', minWidth: 240 }}
              value={selectedSnapId}
              onChange={e => setSelectedSnapId(e.target.value)}
            >
              {sorted.map((s, i) => (
                <option key={s.id} value={s.id}>
                  {i + 1}. {s.fileName}
                </option>
              ))}
            </Form.Select>
            {selectedSnap?.startTime && (
              <small className="text-muted">
                {new Date(selectedSnap.startTime as unknown as string).toLocaleDateString()}
              </small>
            )}
            <small className="text-muted ms-auto">
              {nodes.length} node{nodes.length !== 1 ? 's' : ''} · {edges.length} edge{edges.length !== 1 ? 's' : ''}
            </small>
          </div>

          {/* Graph area */}
          <div style={{ flex: 1, position: 'relative', minHeight: 0 }}>
            {loading && (
              <div className="d-flex align-items-center justify-content-center h-100">
                <Spinner animation="border" className="me-2" />
                <span className="text-muted">Loading subnet traffic…</span>
              </div>
            )}
            {error && (
              <div className="d-flex align-items-center justify-content-center h-100">
                <div className="text-danger small">{error}</div>
              </div>
            )}
            {!loading && !error && nodes.length === 0 && (
              <div className="d-flex align-items-center justify-content-center h-100 flex-column gap-2">
                <i className="bi bi-diagram-2 text-muted" style={{ fontSize: '2rem' }} />
                <span className="text-muted small">No traffic found in {subnet.cidr} for this snapshot.</span>
              </div>
            )}
            {!loading && !error && nodes.length > 0 && (
              <NetworkGraph
                key={`${subnet.cidr}-${selectedSnapId}`}
                nodes={nodes}
                edges={edges}
                onNodeClick={node => setSelectedNode(node)}
              />
            )}
          </div>
        </Modal.Body>

        <Modal.Footer className="py-2">
          {subnet.description && (
            <small className="text-muted me-auto">
              <i className="bi bi-info-circle me-1" />
              {subnet.description}
            </small>
          )}
          <Button variant="outline-secondary" size="sm" onClick={onHide}>Close</Button>
        </Modal.Footer>
      </Modal>

      {selectedNode && selectedSnap && (
        <EntityDetailModal
          entityType={selectedNode.data.isL2 ? 'DEVICE' : 'IP'}
          entityKey={selectedNode.data.isL2 ? (selectedNode.data.mac ?? selectedNode.data.ip) : selectedNode.data.ip}
          displayName={selectedNode.data.ip}
          fileId={selectedSnap.fileId}
          onClose={() => setSelectedNode(null)}
          zIndex={1065}
        />
      )}
    </>
  );
}
