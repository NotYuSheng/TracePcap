import { Spinner } from '@components/common/Spinner/Spinner';
import { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Alert, Badge, Button, Card, Container, Form, OverlayTrigger, Popover, Row, Col } from '@govtechsg/sgds-react';
import { monitorService } from '@/features/monitor/services/monitorService';
import { insightsService } from '@/features/insights/services/insightsService';
import { subnetService } from '@/features/subnets/services/subnetService';
import type { SubnetDefinition } from '@/features/subnets/types/subnet.types';
import type {
  Network,
  NetworkSnapshot,
  ChangeEvent,
  BaselineDefinition,
  BaselineEntryType,
  SubnetOverrideInput,
} from '@/features/monitor/types/monitor.types';
import type {
  NetworkExternalEvent,
  NetworkAnnotation,
  NetworkInsight,
} from '@/features/insights/types/insights.types';
import { SnapshotTimeline } from '@/components/monitor/SnapshotTimeline/SnapshotTimeline';
import { ChangeEventBadge } from '@/components/monitor/ChangeEventBadge/ChangeEventBadge';
import { DeviceDriftPanel } from '@/components/monitor/DeviceDriftPanel/DeviceDriftPanel';
import { ProtocolDriftPanel } from '@/components/monitor/ProtocolDriftPanel/ProtocolDriftPanel';
import { IpDriftPanel } from '@/components/monitor/IpDriftPanel/IpDriftPanel';
import { SubnetsPanel } from '@/components/monitor/SubnetsPanel/SubnetsPanel';
import { BaselineDefinitionPanel } from '@/components/monitor/BaselineDefinitionPanel/BaselineDefinitionPanel';
import { ExternalEventsPanel } from '@/components/monitor/ExternalEventsPanel/ExternalEventsPanel';
import { NetworkAnnotationsPanel } from '@/components/monitor/NetworkAnnotationsPanel/NetworkAnnotationsPanel';
import { NetworkInsightsPanel } from '@/components/monitor/NetworkInsightsPanel/NetworkInsightsPanel';
import { AddSnapshotModal } from '@/components/monitor/AddSnapshotModal/AddSnapshotModal';
import { SnapshotTrafficChart } from '@/components/monitor/SnapshotTrafficChart/SnapshotTrafficChart';
import { Pagination } from '@/components/common/Pagination';

type SeverityFilter = 'ALL' | 'CRITICAL' | 'WARNING' | 'INFO';

const SEVERITY_FILTERS: SeverityFilter[] = ['ALL', 'CRITICAL', 'WARNING', 'INFO'];

const MonitorInfoCard = () => {
  const [collapsed, setCollapsed] = useState(true);
  return (
    <Card className="mb-4" style={{ overflow: 'hidden' }}>
      <Card.Header
        className="d-flex align-items-center justify-content-between"
        style={{
          cursor: 'pointer',
          userSelect: 'none',
          borderBottom: collapsed ? 'none' : undefined,
        }}
        onClick={() => setCollapsed(c => !c)}
      >
        <h6 className="mb-0">
          <i className="bi bi-info-circle me-2"></i>
          How network monitoring works
        </h6>
        <i className={`bi bi-chevron-${collapsed ? 'down' : 'up'} text-muted`}></i>
      </Card.Header>
      {!collapsed && (
        <Card.Body className="small text-muted">
          <p className="mb-2">
            Each PCAP you add becomes a <strong>snapshot</strong> ordered by its capture time.
            After adding a second snapshot, the system automatically compares consecutive snapshots
            and emits <strong>change events</strong> across four signal categories:
          </p>
          <ul className="mb-3">
            <li>
              <strong>Device changes</strong> — new MAC addresses (<code>MAC_ADDED</code>) are flagged as
              WARNING. IP↔MAC rebinding is cross-checked: a MAC appearing at a new IP is flagged WARNING
              (DHCP drift), while an IP claimed by a new MAC is flagged CRITICAL (potential ARP spoofing — could also be a device swap).
            </li>
            <li>
              <strong>Gateway &amp; ISP changes</strong> — if the default gateway IP changes between
              snapshots, a CRITICAL <code>GATEWAY_CHANGE</code> event is raised. Shifts in the autonomous
              system (ASN) of top external peers are raised as INFO <code>ASN_CHANGE</code> events.
            </li>
            <li>
              <strong>Protocol &amp; application drift</strong> — newly seen layer-7 protocols or
              application names are raised as <code>PROTOCOL_ADDED</code> / <code>APP_ADDED</code> (INFO).
              Protocol names are normalised to uppercase so "Telnet" and "TELNET" are treated as the same.
            </li>
            <li>
              <strong>VPN drift</strong> — conversations tagged with VPN-related risk flags are tracked.
              A VPN appearing for the first time is INFO; one disappearing unexpectedly is also flagged.
            </li>
          </ul>
          <p className="mb-2">
            <strong>Severity guide:</strong>{' '}
            <Badge bg="danger" className="me-1">CRITICAL</Badge> security-relevant (potential ARP spoof, gateway hijack) ·{' '}
            <Badge bg="warning" text="dark" className="me-1">WARNING</Badge> notable change requiring review ·{' '}
            <Badge bg="info" text="dark">INFO</Badge> informational drift
          </p>
          <p className="mb-2">
            Click any row in the <strong>Capture Timeline</strong> to open the snapshot detail — including
            its network diagram, change events, context notes, and AI-generated snapshot insights.
            Changed nodes are highlighted by severity colour.
          </p>
          <p className="fw-semibold mb-1 text-dark">Additional features</p>
          <ul className="mb-0">
            <li>
              <strong>Subnet Definitions</strong> — manually define or auto-detect subnets (e.g. <code>10.0.1.0/24</code>).
              Defined subnets group IP addresses in the IP Addresses panel for easier navigation.
            </li>
            <li>
              <strong>Device &amp; IP roles</strong> — click any device or IP address badge to open its detail modal.
              Use <em>Suggest with AI</em> to have the LLM assign an operational role label (e.g. "SCADA Controller") based on traffic signals.
            </li>
            <li>
              <strong>Baseline Definitions</strong> — declare expected devices, IP↔MAC bindings, gateway IPs,
              protocols, and applications to suppress known-good change events.
            </li>
            <li>
              <strong>External Events</strong> — log real-world events (maintenance windows, firmware upgrades,
              scheduled tasks) with timestamps to correlate against network changes.
            </li>
            <li>
              <strong>Network Insights</strong> — click <em>Generate</em> in the Insights panel to have the LLM
              produce a structured narrative across all snapshots, correlating change events with device roles
              and external events.
            </li>
          </ul>
        </Card.Body>
      )}
    </Card>
  );
};


export const NetworkDetailPage = () => {
  const { networkId } = useParams<{ networkId: string }>();
  const navigate = useNavigate();

  const [network, setNetwork] = useState<Network | null>(null);
  const [snapshots, setSnapshots] = useState<NetworkSnapshot[]>([]);
  const [changeEvents, setChangeEvents] = useState<ChangeEvent[]>([]);
  const [definitions, setDefinitions] = useState<BaselineDefinition[]>([]);
  const [externalEvents, setExternalEvents] = useState<NetworkExternalEvent[]>([]);
  const [annotations, setAnnotations] = useState<NetworkAnnotation[]>([]);
  const [insight, setInsight] = useState<NetworkInsight | null>(null);
  const [subnets, setSubnets] = useState<SubnetDefinition[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showAddSnapshot, setShowAddSnapshot] = useState(false);
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('ALL');
  const [changeTypeFilter, setChangeTypeFilter] = useState<string>('ALL');
  const [reviewedFilter, setReviewedFilter] = useState<'ALL' | 'UNREVIEWED' | 'REVIEWED'>('UNREVIEWED');
  const [eventPage, setEventPage] = useState(1);
  const EVENT_PAGE_SIZE = 10;
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [pollInterval, setPollInterval] = useState(30); // seconds

  const loadAll = useCallback(async (showSpinner = false) => {
    if (!networkId) return;
    if (showSpinner) setLoading(true);
    try {
      const [net, snaps, events, defs, evts, annots, ins, subs] = await Promise.all([
        monitorService.getNetwork(networkId),
        monitorService.listSnapshots(networkId),
        monitorService.listChanges(networkId),
        monitorService.listDefinitions(networkId),
        insightsService.listExternalEvents(networkId),
        insightsService.listAnnotations(networkId),
        insightsService.getLatestInsight(networkId),
        subnetService.list(),
      ]);
      setNetwork(net);
      setSnapshots(snaps);
      setChangeEvents(events);
      setDefinitions(defs);
      setExternalEvents(evts);
      setAnnotations(annots);
      setInsight(ins);
      setSubnets(subs);
      setLastUpdated(new Date());
    } catch {
      setError('Failed to load network data.');
    } finally {
      if (showSpinner) setLoading(false);
    }
  }, [networkId]);

  useEffect(() => {
    loadAll(true);
    if (pollInterval === 0) return;
    const interval = setInterval(() => loadAll(false), pollInterval * 1000);
    return () => clearInterval(interval);
  }, [loadAll, pollInterval]);

  const handleAddSnapshot = async (fileId: string, subnetOverrides?: SubnetOverrideInput[]) => {
    if (!networkId) return;
    await monitorService.addSnapshot(networkId, fileId, subnetOverrides);
    await loadAll(false);
  };

  const handleRemoveSnapshot = async (snapshotId: string) => {
    if (!networkId) return;
    await monitorService.removeSnapshot(networkId, snapshotId);
    await loadAll(false);
  };

  const handleAddDefinition = async (
    entryType: BaselineEntryType,
    entityKey: string,
    entityValue?: string,
    notes?: string,
  ) => {
    if (!networkId) return;
    const def = await monitorService.createDefinition(networkId, entryType, entityKey, entityValue, notes);
    setDefinitions(prev => [...prev, def]);
  };

  const handleDeleteDefinition = async (id: string) => {
    if (!networkId) return;
    await monitorService.deleteDefinition(networkId, id);
    setDefinitions(prev => prev.filter(d => d.id !== id));
  };

  const handleAddExternalEvent = async (eventTime: string, title: string, description?: string) => {
    if (!networkId) return;
    const ev = await insightsService.createExternalEvent(networkId, eventTime, title, description);
    setExternalEvents(prev => [ev, ...prev]);
  };

  const handleDeleteExternalEvent = async (eventId: string) => {
    if (!networkId) return;
    await insightsService.deleteExternalEvent(networkId, eventId);
    setExternalEvents(prev => prev.filter(e => e.id !== eventId));
  };

  const handleAddAnnotation = async (body: string) => {
    if (!networkId) return;
    const a = await insightsService.createAnnotation(networkId, body);
    setAnnotations(prev => [a, ...prev]);
  };

  const handleUpdateAnnotation = async (annotationId: string, body: string) => {
    if (!networkId) return;
    const updated = await insightsService.updateAnnotation(networkId, annotationId, body);
    setAnnotations(prev => prev.map(a => a.id === updated.id ? updated : a));
  };

  const handleDeleteAnnotation = async (annotationId: string) => {
    if (!networkId) return;
    await insightsService.deleteAnnotation(networkId, annotationId);
    setAnnotations(prev => prev.filter(a => a.id !== annotationId));
  };

  const handleGenerateInsights = async (options: import('@/features/insights/types/insights.types').InsightOptions) => {
    if (!networkId) return;
    const ins = await insightsService.generateInsights(networkId, options);
    setInsight(ins);
  };

  const handleSubnetSaved = (subnet: SubnetDefinition) => {
    setSubnets(prev => {
      const idx = prev.findIndex(s => s.cidr === subnet.cidr);
      return idx >= 0 ? prev.map(s => s.cidr === subnet.cidr ? subnet : s) : [...prev, subnet];
    });
  };

  const handleSubnetDeleted = (id: number) => {
    setSubnets(prev => prev.filter(s => s.id !== id));
  };

  const handlePatchChange = async (eventId: string, patch: { reviewed?: boolean; notes?: string | null }) => {
    if (!networkId) return;
    try {
      const updated = await monitorService.patchChange(networkId, eventId, patch);
      setChangeEvents(prev => prev.map(e => e.id === updated.id ? updated : e));
    } catch (err) {
      console.error('Failed to patch change event:', err);
      throw err;
    }
  };

  const CHANGE_TYPES = ['ALL', ...Array.from(new Set(changeEvents.map(e => e.changeType)))];

  const filteredEvents = changeEvents.filter(e => {
    if (severityFilter !== 'ALL' && e.severity !== severityFilter) return false;
    if (changeTypeFilter !== 'ALL' && e.changeType !== changeTypeFilter) return false;
    if (reviewedFilter === 'UNREVIEWED' && e.reviewed) return false;
    if (reviewedFilter === 'REVIEWED' && !e.reviewed) return false;
    return true;
  });

  const totalEventPages = Math.max(1, Math.ceil(filteredEvents.length / EVENT_PAGE_SIZE));
  const pagedEvents = filteredEvents.slice((eventPage - 1) * EVENT_PAGE_SIZE, eventPage * EVENT_PAGE_SIZE);

  if (loading) {
    return (
      <Container className="py-5 text-center">
        <Spinner animation="border" className="text-primary" />
      </Container>
    );
  }

  if (error || !network) {
    return (
      <Container className="py-4">
        <Alert variant="danger">{error ?? 'Network not found.'}</Alert>
        <Button type="button" variant="secondary" onClick={() => navigate('/monitor')}>
          Back to Monitor
        </Button>
      </Container>
    );
  }

  return (
    <Container className="py-4">
      {/* Header */}
      <div className="mb-4">
        <Button
          type="button"
          size="sm"
          variant="outline-secondary"
          className="mb-2"
          onClick={() => navigate('/monitor')}
        >
          <i className="bi bi-arrow-left me-1"></i>All Networks
        </Button>
        <div className="d-flex align-items-start justify-content-between flex-wrap gap-2 mt-3">
          <div>
            <h3 className="mb-1">{network.name}</h3>
            {network.description && <p className="text-muted mb-0">{network.description}</p>}
          </div>
          <div className="d-flex align-items-center gap-2 flex-shrink-0">
            {lastUpdated && (
              <small className="text-muted">
                <i className="bi bi-clock me-1"></i>
                Updated {lastUpdated.toLocaleTimeString()}
              </small>
            )}
            <Button
              type="button"
              size="sm"
              variant="outline-secondary"
              onClick={() => loadAll(false)}
              title="Refresh now"
            >
              <i className="bi bi-arrow-clockwise"></i>
            </Button>
            <Form.Select
              size="sm"
              style={{ width: 'auto' }}
              value={pollInterval}
              onChange={e => setPollInterval(Number(e.target.value))}
              title="Auto-refresh interval"
            >
              <option value={10}>Every 10s</option>
              <option value={30}>Every 30s</option>
              <option value={60}>Every 1m</option>
              <option value={300}>Every 5m</option>
              <option value={0}>Manual only</option>
            </Form.Select>
          </div>
        </div>
      </div>

      <MonitorInfoCard />

      {/* Snapshots */}
      <Card className="mb-4">
        <Card.Body>
          <h5 className="card-title mb-3">
            <i className="bi bi-clock-history me-2"></i>Capture Timeline
          </h5>
          <SnapshotTimeline
            networkId={network.id}
            snapshots={snapshots}
            changeEvents={changeEvents}
            onRemove={handleRemoveSnapshot}
            onAddSnapshot={() => setShowAddSnapshot(true)}
            onPatchChange={handlePatchChange}
            onSnapshotUpdated={updated =>
              setSnapshots(prev => prev.map(s => s.id === updated.id ? updated : s))
            }
          />
        </Card.Body>
      </Card>

      {/* Traffic Overview Chart */}
      {snapshots.length >= 2 && (
        <Card className="mb-4">
          <Card.Header>
            <h6 className="mb-0">
              <i className="bi bi-bar-chart-line me-2"></i>Traffic Overview
            </h6>
          </Card.Header>
          <Card.Body>
            <SnapshotTrafficChart snapshots={snapshots} />
          </Card.Body>
        </Card>
      )}

      {/* Change Events */}
      <Card className="mb-4" style={{ overflow: 'hidden' }}>
        <Card.Header className="d-flex justify-content-between align-items-center">
          <h6 className="mb-0">
            <i className="bi bi-activity me-2"></i>Change Events
            {filteredEvents.length > 0 && (
              <Badge bg="secondary" className="ms-2">{filteredEvents.length}</Badge>
            )}
            <OverlayTrigger
              trigger="click"
              placement="right"
              rootClose
              overlay={
                <Popover id="change-events-info" style={{ maxWidth: 380 }}>
                  <Popover.Header>What's detected</Popover.Header>
                  <Popover.Body className="small">
                    <p className="mb-2 text-muted">Changes are compared against the immediately preceding snapshot by capture time. The first snapshot is the baseline and produces no events.</p>
                    <ul className="mb-0 ps-3">
                      <li className="mb-2">
                        <Badge bg="danger" className="me-1">CRITICAL</Badge>
                        <code>IP_MAC_DRIFT</code> — IP claimed by a different MAC (potential ARP spoofing)<br />
                        <code>GATEWAY_CHANGE</code> — default gateway IP changed
                      </li>
                      <li className="mb-2">
                        <Badge bg="warning" text="dark" className="me-1">WARNING</Badge>
                        <code>MAC_ADDED</code> — new device appeared<br />
                        <code>IP_MAC_DRIFT</code> — known MAC moved to a new IP (DHCP drift)
                      </li>
                      <li>
                        <Badge bg="info" text="dark" className="me-1">INFO</Badge>
                        <code>PROTOCOL_ADDED</code> / <code>APP_ADDED</code> — new layer-7 protocol or app<br />
                        <code>ASN_CHANGE</code> — top external peer shifted ISP / ASN<br />
                        <code>VPN_DRIFT</code> — VPN usage appeared or disappeared
                      </li>
                    </ul>
                  </Popover.Body>
                </Popover>
              }
            >
              <Button
                type="button"
                size="sm"
                variant="link"
                className="text-muted p-0 ms-2"
                style={{ fontSize: '0.85rem', verticalAlign: 'middle' }}
                title="What's detected"
              >
                <i className="bi bi-info-circle"></i>
              </Button>
            </OverlayTrigger>
          </h6>
          <div className="d-flex align-items-center gap-2 flex-wrap">
            {/* Severity pills */}
            <div className="d-flex gap-1">
              {SEVERITY_FILTERS.map(f => (
                <Button
                  key={f}
                  type="button"
                  size="sm"
                  variant={
                    severityFilter === f
                      ? f === 'CRITICAL' ? 'danger'
                        : f === 'WARNING' ? 'warning'
                        : f === 'INFO' ? 'info'
                        : 'primary'
                      : 'outline-secondary'
                  }
                  onClick={() => { setSeverityFilter(f); setEventPage(1); }}
                >
                  {f}
                </Button>
              ))}
            </div>
            {/* Change type select */}
            {CHANGE_TYPES.length > 2 && (
              <Form.Select
                size="sm"
                style={{ width: 'auto' }}
                value={changeTypeFilter}
                onChange={e => { setChangeTypeFilter(e.target.value); setEventPage(1); }}
              >
                {CHANGE_TYPES.map(t => (
                  <option key={t} value={t}>{t === 'ALL' ? 'All types' : t}</option>
                ))}
              </Form.Select>
            )}
            {/* Reviewed filter */}
            <div className="d-flex gap-1">
              {(['ALL', 'UNREVIEWED', 'REVIEWED'] as const).map(r => (
                <Button
                  key={r}
                  type="button"
                  size="sm"
                  variant={reviewedFilter === r ? 'secondary' : 'outline-secondary'}
                  onClick={() => { setReviewedFilter(r); setEventPage(1); }}
                >
                  {r === 'ALL' ? 'All' : r === 'UNREVIEWED' ? 'Unreviewed' : 'Reviewed'}
                </Button>
              ))}
            </div>
          </div>
        </Card.Header>


        <Card.Body className="p-0">
          {filteredEvents.length === 0 ? (
            <div className="text-muted text-center py-3">
              {changeEvents.length === 0
                ? 'No changes detected yet. Add more snapshots to start change detection.'
                : 'No events match the current filters.'}
            </div>
          ) : (
            <div className="px-3">
              {pagedEvents.map(event => (
                <ChangeEventBadge key={event.id} event={event} snapshots={snapshots} onPatch={handlePatchChange} />
              ))}
            </div>
          )}
          {filteredEvents.length > EVENT_PAGE_SIZE && (
            <div className="border-top pt-2 px-3 pb-2">
              <Pagination
                currentPage={eventPage}
                totalPages={totalEventPages}
                totalItems={filteredEvents.length}
                pageSize={EVENT_PAGE_SIZE}
                onPageChange={setEventPage}
              />
            </div>
          )}
        </Card.Body>
      </Card>

      {/* Drift Panels */}
      <Row className="mb-4">
        <Col xs={12} md={4} className="mb-3 mb-md-0">
          <Card className="h-100">
            <Card.Header>
              <h6 className="mb-0">
                <i className="bi bi-device-hdd me-2"></i>Devices
              </h6>
            </Card.Header>
            <Card.Body style={{ maxHeight: '380px', overflowY: 'auto' }}>
              <DeviceDriftPanel snapshots={snapshots} />
            </Card.Body>
          </Card>
        </Col>
        <Col xs={12} md={4} className="mb-3 mb-md-0">
          <Card className="h-100">
            <Card.Header>
              <h6 className="mb-0">
                <i className="bi bi-diagram-3 me-2"></i>Protocols &amp; Applications
              </h6>
            </Card.Header>
            <Card.Body style={{ maxHeight: '380px', overflowY: 'auto' }}>
              <ProtocolDriftPanel snapshots={snapshots} />
            </Card.Body>
          </Card>
        </Col>
        <Col xs={12} md={4}>
          <Card className="h-100">
            <Card.Header>
              <h6 className="mb-0">
                <i className="bi bi-globe me-2"></i>IP Addresses
              </h6>
            </Card.Header>
            <Card.Body style={{ maxHeight: '380px', overflowY: 'auto' }}>
              <IpDriftPanel snapshots={snapshots} subnets={subnets} />
            </Card.Body>
          </Card>
        </Col>
      </Row>

      {/* Baseline Definitions */}
      <Card>
        <Card.Body>
          <div className="d-flex align-items-center mb-3">
            <h5 className="card-title mb-0">
              <i className="bi bi-shield-check me-2"></i>Baseline Definitions
              <small className="text-muted fw-normal ms-2 fs-6">
                — manually define expected network state
              </small>
            </h5>
            <OverlayTrigger
              trigger="click"
              placement="right"
              rootClose
              overlay={
                <Popover id="baseline-definitions-info" style={{ maxWidth: 380 }}>
                  <Popover.Header>Baseline Definitions</Popover.Header>
                  <Popover.Body className="small">
                    <p className="mb-2 text-muted">
                      Manually declare what is <em>expected</em> on this network. Entries here
                      suppress false-positive change events for known-good devices, bindings, and services.
                    </p>
                    <ul className="mb-0 ps-3">
                      <li className="mb-1"><strong>Device (MAC)</strong> — a MAC address that is authorised on the network</li>
                      <li className="mb-1"><strong>IP ↔ MAC Binding</strong> — a fixed IP-to-MAC mapping (e.g. a static DHCP lease)</li>
                      <li className="mb-1"><strong>Gateway IP</strong> — the expected default gateway address</li>
                      <li className="mb-1"><strong>Protocol</strong> — a layer-7 protocol that is always expected</li>
                      <li className="mb-1"><strong>Application</strong> — an application name that is always expected</li>
                      <li><strong>VPN Fingerprint</strong> — a VPN risk type that is authorised on this network</li>
                    </ul>
                  </Popover.Body>
                </Popover>
              }
            >
              <Button
                type="button"
                size="sm"
                variant="link"
                className="text-muted p-0 ms-2"
                style={{ fontSize: '0.85rem' }}
                title="About baseline definitions"
              >
                <i className="bi bi-info-circle"></i>
              </Button>
            </OverlayTrigger>
          </div>
          <BaselineDefinitionPanel
            networkId={network.id}
            definitions={definitions}
            onAdd={handleAddDefinition}
            onDelete={handleDeleteDefinition}
          />
        </Card.Body>
      </Card>

      {/* Subnet Definitions */}
      <Card className="mt-4">
        <Card.Body>
          <div className="d-flex align-items-center mb-3">
            <h5 className="card-title mb-0">
              <i className="bi bi-diagram-2 me-2"></i>Subnet Definitions
              <small className="text-muted fw-normal ms-2 fs-6">
                — define or detect subnets to group IP addresses
              </small>
            </h5>
            <OverlayTrigger
              trigger="click"
              placement="right"
              rootClose
              overlay={
                <Popover id="subnet-definitions-info" style={{ maxWidth: 400 }}>
                  <Popover.Header>How Subnet Detection Works</Popover.Header>
                  <Popover.Body className="small">
                    <p className="mb-2">
                      The scanner collects all <strong>private IP addresses</strong> (RFC 1918:{' '}
                      <code>10.x</code>, <code>172.16–31.x</code>, <code>192.168.x</code>) seen in
                      the snapshot's host classifications. For each observed IP, candidate CIDRs at
                      every prefix length from /20 to /29 are generated and scored by{' '}
                      <strong>host density</strong> (observed hosts ÷ subnet capacity). A greedy
                      non-overlapping selection picks the highest-density candidates, preferring
                      tighter, more specific prefixes.
                    </p>
                    <p className="mb-2">
                      <strong>Scan All Snapshots</strong> runs detection across every snapshot and
                      adds a <strong>Consistency</strong> score — subnets seen in more snapshots
                      float to the top. Single-snapshot candidates are flagged in amber.
                    </p>
                    <p className="fw-semibold mb-1">Limitations</p>
                    <ul className="mb-0 ps-3">
                      <li className="mb-1"><strong>Prefix range /20–/29 only.</strong> Very large blocks or micro-segments (/30–/32) are outside the search range.</li>
                      <li className="mb-1"><strong>No routing topology awareness.</strong> Infers from observed host distribution only — no VLAN or gateway knowledge.</li>
                      <li className="mb-1"><strong>Small subnets are dropped.</strong> Segments with fewer than 3 classified hosts will not appear.</li>
                      <li className="mb-1"><strong>Only classified hosts count.</strong> Hosts with too little traffic to be fingerprinted are excluded.</li>
                      <li><strong>Tunnel &amp; VPN addresses.</strong> Private IPs in VPN overlays are treated the same as LAN hosts.</li>
                    </ul>
                  </Popover.Body>
                </Popover>
              }
            >
              <Button
                type="button"
                size="sm"
                variant="link"
                className="text-muted p-0 ms-2"
                style={{ fontSize: '0.85rem' }}
                title="How subnet detection works"
              >
                <i className="bi bi-info-circle"></i>
              </Button>
            </OverlayTrigger>
          </div>
          <SubnetsPanel
            networkId={networkId!}
            subnets={subnets}
            snapshots={snapshots}
            onSaved={handleSubnetSaved}
            onDeleted={handleSubnetDeleted}
          />
        </Card.Body>
      </Card>

      {/* External Events */}
      <Card className="mt-4">
        <Card.Body>
          <h5 className="card-title mb-3">
            <i className="bi bi-calendar-event me-2"></i>External Events
            <small className="text-muted fw-normal ms-2 fs-6">
              — real-world events to correlate with network changes
            </small>
          </h5>
          <ExternalEventsPanel
            events={externalEvents}
            onAdd={handleAddExternalEvent}
            onDelete={handleDeleteExternalEvent}
          />
        </Card.Body>
      </Card>

      {/* Analyst Annotations */}
      <Card className="mt-4">
        <Card.Body>
          <h5 className="card-title mb-3">
            <i className="bi bi-pencil-square me-2"></i>Analyst Annotations
            <small className="text-muted fw-normal ms-2 fs-6">
              — free-text notes fed to AI during insight generation
            </small>
          </h5>
          <NetworkAnnotationsPanel
            annotations={annotations}
            onAdd={handleAddAnnotation}
            onUpdate={handleUpdateAnnotation}
            onDelete={handleDeleteAnnotation}
          />
        </Card.Body>
      </Card>

      {/* Network Insights */}
      <Card className="mt-4 mb-4">
        <Card.Body>
          <div className="d-flex align-items-center mb-3">
            <h5 className="card-title mb-0">
              <i className="bi bi-stars me-2"></i>Network Insights
              <small className="text-muted fw-normal ms-2 fs-6">
                — AI-generated analysis of network behaviour
              </small>
            </h5>
            <OverlayTrigger
              trigger="click"
              placement="right"
              rootClose
              overlay={
                <Popover id="network-insights-info" style={{ maxWidth: 380 }}>
                  <Popover.Header>Network Insights</Popover.Header>
                  <Popover.Body className="small">
                    <p className="mb-2">
                      Clicking <strong>Generate</strong> sends your network's snapshots, change
                      events, device roles, external events, and analyst annotations to the
                      configured LLM. It returns a structured narrative explaining observed
                      behaviour in operational context.
                    </p>
                    <p className="fw-semibold mb-1">Output sections</p>
                    <ul className="mb-2 ps-3">
                      <li className="mb-1"><strong>Summary</strong> — one-paragraph overview of the period</li>
                      <li className="mb-1"><strong>Narrative</strong> — detailed section-by-section analysis</li>
                      <li className="mb-1"><strong>Anomalies</strong> — flagged deviations with severity</li>
                      <li className="mb-1"><strong>Correlations</strong> — links between external events and network changes</li>
                      <li><strong>Recommendations</strong> — suggested follow-up actions</li>
                    </ul>
                    <p className="mb-0 text-muted fst-italic">
                      Assign device roles and add external events first to get richer, more contextual insights.
                    </p>
                  </Popover.Body>
                </Popover>
              }
            >
              <Button
                type="button"
                size="sm"
                variant="link"
                className="text-muted p-0 ms-2"
                style={{ fontSize: '0.85rem' }}
                title="About network insights"
              >
                <i className="bi bi-info-circle"></i>
              </Button>
            </OverlayTrigger>
          </div>
          <NetworkInsightsPanel
            insight={insight}
            llmAvailable={true}
            onGenerate={handleGenerateInsights}
          />
        </Card.Body>
      </Card>

      <AddSnapshotModal
        show={showAddSnapshot}
        onHide={() => setShowAddSnapshot(false)}
        existingFileIds={snapshots.map(s => s.fileId)}
        onAdd={handleAddSnapshot}
      />

    </Container>
  );
};
