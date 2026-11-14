import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { Button, Card, Container, Dropdown, Form } from '@govtechsg/sgds-react';
import { Spinner } from '@components/common/Spinner/Spinner';
import { Alert } from '@components/common/Alert';
import { SnapshotTimeline } from '@/components/monitor/SnapshotTimeline/SnapshotTimeline';
import { DeviceDriftPanel } from '@/components/monitor/DeviceDriftPanel/DeviceDriftPanel';
import { ProtocolDriftPanel } from '@/components/monitor/ProtocolDriftPanel/ProtocolDriftPanel';
import { IpDriftPanel } from '@/components/monitor/IpDriftPanel/IpDriftPanel';
import { monitorService } from '@/features/monitor/services/monitorService';
import { NetworkSettingsModal } from '@/components/monitor/NetworkSettingsModal/NetworkSettingsModal';
import { NetworkRulesModal } from '@/features/detectionRules/NetworkRulesModal';
import { NetworkAddressConfigModal } from '@/features/networkAddress/NetworkAddressConfigModal';
import { NetworkDevicesModal } from '@/features/networkDevices/NetworkDevicesModal';
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
import { AnalysisRail, type RailItem } from '@pages/Analysis/AnalysisRail';
import { ChangeEventBadge } from '@/components/monitor/ChangeEventBadge/ChangeEventBadge';
import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import './NetworkDetailPage.css';
import { ChangeEventsSection } from './components/ChangeEventsSection';
import { HelpPopover } from './components/HelpPopover';

export const NetworkDetailPage = () => {
  const { networkId } = useParams<{ networkId: string }>();
  const navigate = useNavigate();

  const data = useNetworkDetailData(networkId);
  const {
    network,
    snapshots,
    changeEvents,
    definitions,
    externalEvents,
    annotations,
    insight,
    subnets,
    loading,
    error,
    lastUpdated,
    pollInterval,
    setPollInterval,
    reload,
  } = data;

  // `?add=1` (from the networks table's "Add a capture") opens the add dialog straight away.
  const [showAddSnapshot, setShowAddSnapshot] = useState(
    () => new URLSearchParams(window.location.search).get('add') === '1'
  );
  const [showManage, setShowManage] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [showAddresses, setShowAddresses] = useState(false);
  const [showDevices, setShowDevices] = useState(false);
  const [showRules, setShowRules] = useState(false);

  const [params, setParams] = useSearchParams();
  const sectionParam = params.get('section');

  // Device totals for the overview.
  const [deviceCounts, setDeviceCounts] = useState<{
    all: number;
    irregular: number;
    privateMac: number;
  } | null>(null);
  const snapshotCount = snapshots.length;
  useEffect(() => {
    if (!networkId) return;
    let alive = true;
    apiClient
      .get<{ all: number; irregular: number; privateMac: number }>(
        API_ENDPOINTS.NETWORK_DEVICE_COUNTS(networkId)
      )
      .then(r => {
        if (alive) setDeviceCounts(r.data);
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, [networkId, snapshotCount]);

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

  const first = snapshots[0];
  const last = snapshots[snapshots.length - 1];
  const day = (sn?: { startTime: string | null; addedAt: string }) =>
    sn
      ? new Date(sn.startTime ?? sn.addedAt).toLocaleDateString(undefined, {
          day: 'numeric',
          month: 'short',
          year: 'numeric',
        })
      : '';
  const toReview = network.criticalChanges + network.warningChanges;
  const latestChanges = last
    ? changeEvents.filter(e => e.toSnapshotId === last.id && !e.reviewed)
    : [];

  const railItems: RailItem[] = [
    { key: 'overview', label: 'Overview', short: 'Overview', icon: 'bi-grid-1x2' },
    {
      key: 'changes',
      label: 'Changes',
      short: 'Changes',
      icon: 'bi-activity',
      badge: toReview || undefined,
    },
    { key: 'captures', label: 'Captures', short: 'Captures', icon: 'bi-clock-history' },
    { key: 'devices', label: 'Devices', short: 'Devices', icon: 'bi-pc-display' },
    { key: 'addresses', label: 'Addresses', short: 'Addresses', icon: 'bi-globe' },
    { key: 'apps', label: 'Apps and protocols', short: 'Apps', icon: 'bi-diagram-3' },
    { key: 'insights', label: 'Insights', short: 'Insights', icon: 'bi-stars' },
    {
      key: 'expected',
      label: 'Expected state',
      short: 'Expected',
      icon: 'bi-shield-check',
      group: 'Set up',
    },
    { key: 'subnets', label: 'Subnets', short: 'Subnets', icon: 'bi-diagram-2' },
    { key: 'events', label: 'Outside events', short: 'Events', icon: 'bi-calendar-event' },
    { key: 'notes', label: 'Notes', short: 'Notes', icon: 'bi-pencil-square' },
  ];
  const section = railItems.some(i => i.key === sectionParam) ? sectionParam! : 'overview';
  const pick = (key: string) =>
    setParams(key === 'overview' ? {} : { section: key }, { replace: true });

  const timeline = (
    <SnapshotTimeline
      networkId={network.id}
      snapshots={snapshots}
      changeEvents={changeEvents}
      onManage={() => setShowManage(true)}
      onPatchChange={data.handlePatchChange}
      onSnapshotUpdated={data.handleSnapshotUpdated}
    />
  );

  return (
    <div className="network-page">
      <div className="analysis-shell">
        <AnalysisRail
          items={railItems}
          active={section}
          onSelect={pick}
          label="Network sections"
          storageKey="tracepcap.networkRail.expanded"
        />
        <div className="analysis-main">
          {/* The capture bar: which network, its facts, and the page-wide actions. */}
          <header className="analysis-capture-bar">
            <div className="analysis-capture-id">
              <div className="analysis-capture-crumb">
                <Link to="/monitor">Monitor</Link> <span className="text-muted">/</span>
              </div>
              <h1 className="analysis-capture-name">{network.name}</h1>
              <div className="analysis-capture-facts">
                {snapshots.length === 0
                  ? 'No captures yet'
                  : `${snapshots.length} capture${snapshots.length === 1 ? '' : 's'} · ${day(first)}${snapshots.length > 1 ? ` to ${day(last)}` : ''}`}
                {network.description && <> · {network.description}</>}
              </div>
            </div>
            <div className="analysis-capture-actions">
              {toReview > 0 && (
                <button
                  type="button"
                  className="network-review-pill"
                  onClick={() => pick('changes')}
                >
                  {toReview} to review
                </button>
              )}
              {lastUpdated && (
                <small className="text-muted">Updated {lastUpdated.toLocaleTimeString()}</small>
              )}
              <Button
                type="button"
                size="sm"
                variant="outline-secondary"
                onClick={() => reload(false)}
                aria-label="Refresh now"
              >
                <i className="bi bi-arrow-clockwise" aria-hidden="true"></i>
              </Button>
              <Dropdown align="end">
                <Dropdown.Toggle variant="outline-secondary" size="sm" id="network-settings-menu">
                  <i className="bi bi-gear me-1" aria-hidden="true"></i>Settings
                </Dropdown.Toggle>
                <Dropdown.Menu>
                  <Dropdown.Item onClick={() => setShowSettings(true)}>
                    Inactivity rule
                  </Dropdown.Item>
                  <Dropdown.Item onClick={() => setShowRules(true)}>Detection rules</Dropdown.Item>
                  <Dropdown.Item onClick={() => setShowAddresses(true)}>
                    Address labels
                  </Dropdown.Item>
                  <Dropdown.Item onClick={() => setShowDevices(true)}>Device labels</Dropdown.Item>
                  <Dropdown.Divider />
                  <Dropdown.ItemText>
                    <Form.Label htmlFor="network-refresh" className="small text-muted mb-1">
                      Refresh
                    </Form.Label>
                    <Form.Select
                      id="network-refresh"
                      size="sm"
                      value={pollInterval}
                      onChange={e => setPollInterval(Number(e.target.value))}
                    >
                      <option value={10}>Every 10s</option>
                      <option value={30}>Every 30s</option>
                      <option value={60}>Every 1m</option>
                      <option value={300}>Every 5m</option>
                      <option value={0}>Manual only</option>
                    </Form.Select>
                  </Dropdown.ItemText>
                </Dropdown.Menu>
              </Dropdown>
              <Button
                type="button"
                size="sm"
                variant="primary"
                onClick={() => setShowAddSnapshot(true)}
              >
                <i className="bi bi-plus-lg me-1" aria-hidden="true"></i>Add a capture
              </Button>
            </div>
          </header>
          <main
            className="analysis-body"
            aria-label={railItems.find(i => i.key === section)?.label}
          >
            {section === 'overview' && (
              <div className="d-flex flex-column gap-4">
                <div className="network-stats">
                  <div className="network-stat">
                    <div className="network-stat-label">Captures</div>
                    <div className="network-stat-value">{snapshots.length}</div>
                    <div className="network-stat-sub">
                      {last ? `last: ${last.fileName}` : 'none yet'}
                    </div>
                  </div>
                  <div className="network-stat">
                    <div className="network-stat-label">Devices</div>
                    <div className="network-stat-value">{deviceCounts?.all ?? '…'}</div>
                    <div className="network-stat-sub">
                      {deviceCounts
                        ? `${deviceCounts.irregular} irregular · ${deviceCounts.privateMac} private MAC`
                        : ''}
                    </div>
                  </div>
                  <button
                    type="button"
                    className={`network-stat network-stat-button${toReview > 0 ? ' network-stat-warn' : ''}`}
                    onClick={() => pick('changes')}
                  >
                    <div className="network-stat-label">To review</div>
                    <div className="network-stat-value">{toReview}</div>
                    <div className="network-stat-sub">
                      {network.criticalChanges > 0
                        ? `${network.criticalChanges} critical`
                        : 'unreviewed changes'}
                    </div>
                  </button>
                </div>

                <Card>
                  <Card.Body>
                    <div className="d-flex align-items-baseline gap-2 flex-wrap mb-2">
                      <h2 className="h6 mb-0">What changed in the latest capture</h2>
                      {last && (
                        <span className="small text-muted">
                          {last.fileName} · {day(last)}
                        </span>
                      )}
                      <button
                        type="button"
                        className="btn btn-link btn-sm p-0 ms-auto"
                        onClick={() => pick('changes')}
                      >
                        All changes
                      </button>
                    </div>
                    {snapshots.length < 2 ? (
                      <p className="small text-muted mb-0">
                        {snapshots.length === 0
                          ? 'Add a capture of this network. The first one becomes the baseline.'
                          : 'This is the baseline. Add the next capture to see what changed.'}
                      </p>
                    ) : latestChanges.length === 0 ? (
                      <p className="small text-muted mb-0">
                        Nothing new to review from this capture.
                      </p>
                    ) : (
                      latestChanges.map(event => (
                        <ChangeEventBadge
                          key={event.id}
                          event={event}
                          snapshots={snapshots}
                          onPatch={data.handlePatchChange}
                        />
                      ))
                    )}
                  </Card.Body>
                </Card>

                <Card id="sec-timeline">
                  <Card.Body>
                    <h2 className="h6 mb-3">Captures</h2>
                    {timeline}
                  </Card.Body>
                </Card>

                {snapshots.length >= 2 && (
                  <Card>
                    <Card.Body>
                      <h2 className="h6 mb-3">Traffic</h2>
                      <SnapshotTrafficChart snapshots={snapshots} />
                    </Card.Body>
                  </Card>
                )}

                <MonitorInfoCard />
              </div>
            )}

            {section === 'changes' && (
              <ChangeEventsSection
                changeEvents={changeEvents}
                snapshots={snapshots}
                onPatchChange={data.handlePatchChange}
              />
            )}

            {section === 'captures' && (
              <Card id="sec-timeline">
                <Card.Body>
                  <h2 className="h5 mb-3">Captures</h2>
                  {timeline}
                </Card.Body>
              </Card>
            )}

            {section === 'devices' && (
              <Card>
                <Card.Body>
                  <h2 className="h5 mb-3">Devices</h2>
                  <DeviceDriftPanel snapshots={snapshots} settings={network.settings} />
                </Card.Body>
              </Card>
            )}

            {section === 'addresses' && (
              <Card>
                <Card.Body>
                  <h2 className="h5 mb-3">Addresses</h2>
                  <IpDriftPanel
                    networkId={networkId}
                    snapshots={snapshots}
                    subnets={subnets}
                    settings={network.settings}
                  />
                </Card.Body>
              </Card>
            )}

            {section === 'apps' && (
              <Card>
                <Card.Body>
                  <h2 className="h5 mb-3">Apps and protocols</h2>
                  <ProtocolDriftPanel snapshots={snapshots} settings={network.settings} />
                </Card.Body>
              </Card>
            )}

            {section === 'insights' && (
              <Card>
                <Card.Body>
                  <div className="d-flex align-items-center mb-3">
                    <h2 className="h5 mb-0">Insights</h2>
                    <HelpPopover
                      id="network-insights-info"
                      title="Network Insights"
                      buttonTitle="About network insights"
                    >
                      <p className="mb-2">
                        Clicking <strong>Generate</strong> sends your network's snapshots, change
                        events, device roles, external events, and analyst annotations to the
                        configured LLM. It returns a structured narrative explaining observed
                        behaviour in operational context.
                      </p>
                      <p className="fw-semibold mb-1">Output sections</p>
                      <ul className="mb-2 ps-3">
                        <li className="mb-1">
                          <strong>Summary</strong> — one-paragraph overview of the period
                        </li>
                        <li className="mb-1">
                          <strong>Narrative</strong> — detailed section-by-section analysis
                        </li>
                        <li className="mb-1">
                          <strong>Anomalies</strong> — flagged deviations with severity
                        </li>
                        <li className="mb-1">
                          <strong>Correlations</strong> — links between external events and network
                          changes
                        </li>
                        <li>
                          <strong>Recommendations</strong> — suggested follow-up actions
                        </li>
                      </ul>
                      <p className="mb-0 text-muted fst-italic">
                        Assign device roles and add external events first to get richer, more
                        contextual insights.
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
            )}

            {section === 'expected' && (
              <Card>
                <Card.Body>
                  <div className="d-flex align-items-center mb-3">
                    <h2 className="h5 mb-0">Expected state</h2>
                    <HelpPopover
                      id="baseline-definitions-info"
                      title="Baseline Definitions"
                      buttonTitle="About baseline definitions"
                    >
                      <p className="mb-2 text-muted">
                        Manually declare what is <em>expected</em> on this network. Entries here
                        suppress false-positive change events for known-good devices, bindings, and
                        services.
                      </p>
                      <ul className="mb-0 ps-3">
                        <li className="mb-1">
                          <strong>Device (MAC)</strong> — a MAC address that is authorised on the
                          network
                        </li>
                        <li className="mb-1">
                          <strong>IP ↔ MAC Binding</strong> — a fixed IP-to-MAC mapping (e.g. a
                          static DHCP lease)
                        </li>
                        <li className="mb-1">
                          <strong>Gateway IP</strong> — the expected default gateway address
                        </li>
                        <li className="mb-1">
                          <strong>Protocol</strong> — a layer-7 protocol that is always expected
                        </li>
                        <li className="mb-1">
                          <strong>Application</strong> — an application name that is always expected
                        </li>
                        <li>
                          <strong>VPN Fingerprint</strong> — a VPN risk type that is authorised on
                          this network
                        </li>
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
            )}

            {section === 'subnets' && (
              <Card>
                <Card.Body>
                  <div className="d-flex align-items-center mb-3">
                    <h2 className="h5 mb-0">Subnets</h2>
                    <HelpPopover
                      id="subnet-definitions-info"
                      title="How Subnet Detection Works"
                      maxWidth={400}
                      buttonTitle="How subnet detection works"
                    >
                      <p className="mb-2">
                        The scanner collects all <strong>private IP addresses</strong> (RFC 1918:{' '}
                        <code>10.x</code>, <code>172.16–31.x</code>, <code>192.168.x</code>) seen in
                        the snapshot's host classifications. For each observed IP, candidate CIDRs
                        at every prefix length from /20 to /29 are generated and scored by{' '}
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
                        <strong>Per-snapshot overrides.</strong> Individual snapshots can carry
                        their own subnet list that shadows the global definitions for that
                        snapshot's change detection. Set overrides from the <em>Subnets</em> tab
                        inside a snapshot's detail view.
                      </p>
                      <p className="fw-semibold mb-1">Limitations</p>
                      <ul className="mb-0 ps-3">
                        <li className="mb-1">
                          <strong>Prefix range /20–/29 only.</strong> Very large blocks or
                          micro-segments (/30–/32) are outside the search range.
                        </li>
                        <li className="mb-1">
                          <strong>No routing topology awareness.</strong> Infers from observed host
                          distribution only — no VLAN or gateway knowledge.
                        </li>
                        <li className="mb-1">
                          <strong>Small subnets are dropped.</strong> Segments with fewer than 3
                          classified hosts will not appear.
                        </li>
                        <li className="mb-1">
                          <strong>Only classified hosts count.</strong> Hosts with too little
                          traffic to be fingerprinted are excluded.
                        </li>
                        <li>
                          <strong>Tunnel &amp; VPN addresses.</strong> Private IPs in VPN overlays
                          are treated the same as LAN hosts.
                        </li>
                      </ul>
                    </HelpPopover>
                  </div>
                  <SubnetsPanel
                    networkId={networkId!}
                    subnets={subnets}
                    snapshots={snapshots}
                    onSaved={data.handleSubnetSaved}
                    onDeleted={data.handleSubnetDeleted}
                    onChanged={() => reload(false)}
                  />
                </Card.Body>
              </Card>
            )}

            {section === 'events' && (
              <Card>
                <Card.Body>
                  <h2 className="h5 mb-1">Outside events</h2>
                  <p className="small text-muted">
                    Real-world events (maintenance windows, incidents, policy changes) to line up
                    with what changed. Insights take them into account.
                  </p>
                  <ExternalEventsPanel
                    events={externalEvents}
                    onAdd={data.handleAddExternalEvent}
                    onUpdate={data.handleUpdateExternalEvent}
                    onDelete={data.handleDeleteExternalEvent}
                  />
                </Card.Body>
              </Card>
            )}

            {section === 'notes' && (
              <Card>
                <Card.Body>
                  <h2 className="h5 mb-1">Notes</h2>
                  <p className="small text-muted">
                    Free-text notes on this network. Insights read them as context.
                  </p>
                  <NetworkAnnotationsPanel
                    annotations={annotations}
                    onAdd={data.handleAddAnnotation}
                    onUpdate={data.handleUpdateAnnotation}
                    onDelete={data.handleDeleteAnnotation}
                  />
                </Card.Body>
              </Card>
            )}
          </main>
        </div>
      </div>

      <ManagePcapsModal
        show={showManage}
        onHide={() => setShowManage(false)}
        snapshots={snapshots}
        onRemove={data.handleRemoveSnapshot}
        onAddSnapshot={() => {
          setShowManage(false);
          setShowAddSnapshot(true);
        }}
      />

      <AddSnapshotModal
        show={showAddSnapshot}
        onHide={() => setShowAddSnapshot(false)}
        existingFileIds={snapshots.map(s => s.fileId)}
        networkId={networkId}
        onAdd={data.handleAddSnapshot}
      />
      {network && (
        <NetworkRulesModal
          show={showRules}
          networkId={network.id}
          networkName={network.name}
          onHide={() => setShowRules(false)}
        />
      )}
      {network && showDevices && (
        <NetworkDevicesModal
          show={showDevices}
          networkId={network.id}
          networkName={network.name}
          snapshots={snapshots}
          onHide={() => setShowDevices(false)}
        />
      )}
      {network && (
        <NetworkAddressConfigModal
          show={showAddresses}
          networkId={network.id}
          networkName={network.name}
          onHide={() => setShowAddresses(false)}
          onChanged={() => reload(false)}
        />
      )}
      <NetworkSettingsModal
        show={showSettings}
        onHide={() => setShowSettings(false)}
        initial={network.settings}
        onSave={async settings => {
          await monitorService.updateNetworkSettings(network.id, settings);
          reload(false);
        }}
      />
    </div>
  );
};
