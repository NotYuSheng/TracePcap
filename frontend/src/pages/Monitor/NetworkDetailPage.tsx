import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Button, Card, Container, Form, Row, Col } from '@govtechsg/sgds-react';
import { Spinner } from '@components/common/Spinner/Spinner';
import { Alert } from '@components/common/Alert';
import { SnapshotTimeline } from '@/components/monitor/SnapshotTimeline/SnapshotTimeline';
import { DeviceDriftPanel } from '@/components/monitor/DeviceDriftPanel/DeviceDriftPanel';
import { ProtocolDriftPanel } from '@/components/monitor/ProtocolDriftPanel/ProtocolDriftPanel';
import { IpDriftPanel } from '@/components/monitor/IpDriftPanel/IpDriftPanel';
import { SubnetsPanel } from '@/components/monitor/SubnetsPanel/SubnetsPanel';
import { BaselineDefinitionPanel } from '@/components/monitor/BaselineDefinitionPanel/BaselineDefinitionPanel';
import { ExternalEventsPanel } from '@/components/monitor/ExternalEventsPanel/ExternalEventsPanel';
import { NetworkAnnotationsPanel } from '@/components/monitor/NetworkAnnotationsPanel/NetworkAnnotationsPanel';
import { NetworkInsightsPanel } from '@/components/monitor/NetworkInsightsPanel/NetworkInsightsPanel';
import { AddSnapshotModal } from '@/components/monitor/AddSnapshotModal/AddSnapshotModal';
import { ManagePcapsModal } from '@/components/monitor/ManagePcapsModal/ManagePcapsModal';
import { SnapshotTrafficChart } from '@/components/monitor/SnapshotTrafficChart/SnapshotTrafficChart';
import { useNetworkDetailData } from './hooks/useNetworkDetailData';
import { MonitorInfoCard } from './components/MonitorInfoCard';
import { SectionSideNav, type SectionDef } from './components/SectionSideNav';
import { ChangeEventsSection } from './components/ChangeEventsSection';
import { HelpPopover } from './components/HelpPopover';

export const NetworkDetailPage = () => {
  const { networkId } = useParams<{ networkId: string }>();
  const navigate = useNavigate();

  const data = useNetworkDetailData(networkId);
  const {
    network, snapshots, changeEvents, definitions, externalEvents, annotations,
    insight, subnets, loading, error, lastUpdated, pollInterval, setPollInterval, reload,
  } = data;

  const [showAddSnapshot, setShowAddSnapshot] = useState(false);
  const [showManage, setShowManage] = useState(false);

  const navSections: SectionDef[] = [
    { id: 'sec-timeline', label: 'Capture Timeline', icon: 'bi-clock-history' },
    ...(snapshots.length >= 2
      ? [{ id: 'sec-traffic', label: 'Traffic Overview', icon: 'bi-bar-chart-line' }]
      : []),
    { id: 'sec-changes', label: 'Change Events', icon: 'bi-activity' },
    { id: 'sec-drift', label: 'Drift Panels', icon: 'bi-hdd-network' },
    { id: 'sec-baseline', label: 'Baseline Definitions', icon: 'bi-shield-check' },
    { id: 'sec-subnets', label: 'Subnet Definitions', icon: 'bi-diagram-2' },
    { id: 'sec-external', label: 'External Events', icon: 'bi-calendar-event' },
    { id: 'sec-annotations', label: 'Analyst Annotations', icon: 'bi-pencil-square' },
    { id: 'sec-insights', label: 'Network Insights', icon: 'bi-stars' },
  ];

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
              onClick={() => reload(false)}
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

      <Row>
        <Col xs={12} lg={3} xl={2} className="d-none d-lg-block">
          <SectionSideNav sections={navSections} />
        </Col>
        <Col xs={12} lg={9} xl={10}>
          {/* Snapshots */}
          <Card id="sec-timeline" className="mb-4 tp-anchor">
            <Card.Body>
              <h5 className="card-title mb-3">
                <i className="bi bi-clock-history me-2"></i>Capture Timeline
              </h5>
              <SnapshotTimeline
                networkId={network.id}
                snapshots={snapshots}
                changeEvents={changeEvents}
                onManage={() => setShowManage(true)}
                onPatchChange={data.handlePatchChange}
                onSnapshotUpdated={data.handleSnapshotUpdated}
              />
            </Card.Body>
          </Card>

          {/* Traffic Overview Chart */}
          {snapshots.length >= 2 && (
            <Card id="sec-traffic" className="mb-4 tp-anchor">
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
          <ChangeEventsSection
            changeEvents={changeEvents}
            snapshots={snapshots}
            onPatchChange={data.handlePatchChange}
          />

          {/* Drift Panels */}
          <Row id="sec-drift" className="mb-4 tp-anchor">
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
          <Card id="sec-baseline" className="tp-anchor">
            <Card.Body>
              <div className="d-flex align-items-center mb-3">
                <h5 className="card-title mb-0">
                  <i className="bi bi-shield-check me-2"></i>Baseline Definitions
                  <small className="text-muted fw-normal ms-2 fs-6">
                    — manually define expected network state
                  </small>
                </h5>
                <HelpPopover id="baseline-definitions-info" title="Baseline Definitions" buttonTitle="About baseline definitions">
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
                </HelpPopover>
              </div>
              <BaselineDefinitionPanel
                networkId={network.id}
                definitions={definitions}
                onAdd={data.handleAddDefinition}
                onDelete={data.handleDeleteDefinition}
              />
            </Card.Body>
          </Card>

          {/* Subnet Definitions */}
          <Card id="sec-subnets" className="mt-4 tp-anchor">
            <Card.Body>
              <div className="d-flex align-items-center mb-3">
                <h5 className="card-title mb-0">
                  <i className="bi bi-diagram-2 me-2"></i>Subnet Definitions
                  <small className="text-muted fw-normal ms-2 fs-6">
                    — define or detect subnets to group IP addresses
                  </small>
                </h5>
                <HelpPopover id="subnet-definitions-info" title="How Subnet Detection Works" maxWidth={400} buttonTitle="How subnet detection works">
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
                  <p className="mb-2">
                    <strong>Per-snapshot overrides.</strong> Individual snapshots can carry their
                    own subnet list that shadows the global definitions for that snapshot's change
                    detection. Set overrides from the <em>Subnets</em> tab inside a snapshot's
                    detail view.
                  </p>
                  <p className="fw-semibold mb-1">Limitations</p>
                  <ul className="mb-0 ps-3">
                    <li className="mb-1"><strong>Prefix range /20–/29 only.</strong> Very large blocks or micro-segments (/30–/32) are outside the search range.</li>
                    <li className="mb-1"><strong>No routing topology awareness.</strong> Infers from observed host distribution only — no VLAN or gateway knowledge.</li>
                    <li className="mb-1"><strong>Small subnets are dropped.</strong> Segments with fewer than 3 classified hosts will not appear.</li>
                    <li className="mb-1"><strong>Only classified hosts count.</strong> Hosts with too little traffic to be fingerprinted are excluded.</li>
                    <li><strong>Tunnel &amp; VPN addresses.</strong> Private IPs in VPN overlays are treated the same as LAN hosts.</li>
                  </ul>
                </HelpPopover>
              </div>
              <SubnetsPanel
                networkId={networkId!}
                subnets={subnets}
                snapshots={snapshots}
                onSaved={data.handleSubnetSaved}
                onDeleted={data.handleSubnetDeleted}
              />
            </Card.Body>
          </Card>

          {/* External Events */}
          <Card id="sec-external" className="mt-4 tp-anchor">
            <Card.Body>
              <h5 className="card-title mb-3">
                <i className="bi bi-calendar-event me-2"></i>External Events
                <small className="text-muted fw-normal ms-2 fs-6">
                  — real-world events to correlate with network changes
                </small>
              </h5>
              <ExternalEventsPanel
                events={externalEvents}
                onAdd={data.handleAddExternalEvent}
                onUpdate={data.handleUpdateExternalEvent}
                onDelete={data.handleDeleteExternalEvent}
              />
            </Card.Body>
          </Card>

          {/* Analyst Annotations */}
          <Card id="sec-annotations" className="mt-4 tp-anchor">
            <Card.Body>
              <h5 className="card-title mb-3">
                <i className="bi bi-pencil-square me-2"></i>Analyst Annotations
                <small className="text-muted fw-normal ms-2 fs-6">
                  — free-text notes fed to AI during insight generation
                </small>
              </h5>
              <NetworkAnnotationsPanel
                annotations={annotations}
                onAdd={data.handleAddAnnotation}
                onUpdate={data.handleUpdateAnnotation}
                onDelete={data.handleDeleteAnnotation}
              />
            </Card.Body>
          </Card>

          {/* Network Insights */}
          <Card id="sec-insights" className="mt-4 mb-4 tp-anchor">
            <Card.Body>
              <div className="d-flex align-items-center mb-3">
                <h5 className="card-title mb-0">
                  <i className="bi bi-stars me-2"></i>Network Insights
                  <small className="text-muted fw-normal ms-2 fs-6">
                    — AI-generated analysis of network behaviour
                  </small>
                </h5>
                <HelpPopover id="network-insights-info" title="Network Insights" buttonTitle="About network insights">
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
                </HelpPopover>
              </div>
              <NetworkInsightsPanel
                insight={insight}
                llmAvailable={true}
                onGenerate={data.handleGenerateInsights}
              />
            </Card.Body>
          </Card>
        </Col>
      </Row>

      <ManagePcapsModal
        show={showManage}
        onHide={() => setShowManage(false)}
        snapshots={snapshots}
        onRemove={data.handleRemoveSnapshot}
        onAddSnapshot={() => { setShowManage(false); setShowAddSnapshot(true); }}
      />

      <AddSnapshotModal
        show={showAddSnapshot}
        onHide={() => setShowAddSnapshot(false)}
        existingFileIds={snapshots.map(s => s.fileId)}
        onAdd={data.handleAddSnapshot}
      />
    </Container>
  );
};
