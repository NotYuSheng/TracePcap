import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { Button, Card, Container, Form, Modal } from '@govtechsg/sgds-react';
import { PermissionLock } from '@components/common/PermissionLock';
import { usePermission } from '@/features/me/useMe';
import { Spinner } from '@components/common/Spinner/Spinner';
import { Alert } from '@components/common/Alert';
import { SnapshotMap } from '@/components/monitor/SnapshotMap';
import { SideDrawer } from '@components/common/SideDrawer';
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
import { ChangeList } from '@/components/monitor/ChangeList';
import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import './NetworkDetailPage.css';
import { NetworkTimeline } from './components/NetworkTimeline';
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
  const addCaptures = usePermission('NETWORK_CAPTURES');
  // Set up moved into the Settings drawer; its old links open it.
  const [showSettings, setShowSettings] = useState(() =>
    ['setup', 'expected', 'subnets'].includes(
      new URLSearchParams(window.location.search).get('section') ?? ''
    )
  );
  const [showAddresses, setShowAddresses] = useState(false);
  const [showDevices, setShowDevices] = useState(false);
  const [showRules, setShowRules] = useState(false);
  const [showInactivity, setShowInactivity] = useState(false);
  const [showNotes, setShowNotes] = useState(false);
  const [showEvents, setShowEvents] = useState(false);
  const [inventoryTab, setInventoryTab] = useState<'devices' | 'addresses' | 'apps'>('devices');

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
      key: 'timeline',
      label: 'Timeline: captures, changes, notes and events',
      short: 'Timeline',
      icon: 'bi-clock-history',
      badge: toReview || undefined,
    },
    {
      key: 'inventory',
      label: 'Devices, addresses and apps',
      short: 'Inventory',
      icon: 'bi-pc-display',
    },
  ];
  // Older links name sections that were folded together; send them to the tab that holds them.
  const FOLDED: Record<string, string> = {
    changes: 'timeline',
    captures: 'timeline',
    notes: 'timeline',
    events: 'timeline',
    insights: 'overview',
    devices: 'inventory',
    addresses: 'inventory',
    apps: 'inventory',
    setup: 'overview',
    expected: 'overview',
    subnets: 'overview',
  };
  const wanted = sectionParam ? (FOLDED[sectionParam] ?? sectionParam) : null;
  const section = railItems.some(i => i.key === wanted) ? wanted! : 'overview';
  const pick = (key: string) =>
    setParams(key === 'overview' ? {} : { section: key }, { replace: true });
  const ordered = [...snapshots].sort((a, b) => a.snapshotOrder - b.snapshotOrder);
  const latest = ordered[ordered.length - 1] ?? null;
  const beforeLatest = ordered.length > 1 ? ordered[ordered.length - 2] : null;

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
                  onClick={() => pick('timeline')}
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
              <Button
                type="button"
                size="sm"
                variant="outline-secondary"
                onClick={() => setShowSettings(true)}
              >
                <i className="bi bi-gear me-1" aria-hidden="true"></i>Settings
              </Button>
              <Button
                type="button"
                size="sm"
                variant="primary"
                onClick={() => setShowAddSnapshot(true)}
                disabled={!addCaptures.allowed}
              >
                <i className="bi bi-plus-lg me-1" aria-hidden="true"></i>Add a capture
              </Button>
              <PermissionLock action="NETWORK_CAPTURES" className="align-self-center" />
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
                    onClick={() => pick('timeline')}
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
                        onClick={() => pick('timeline')}
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
                      <ChangeList
                        events={latestChanges}
                        snapshots={snapshots}
                        onPatch={data.handlePatchChange}
                        reviewFilter={false}
                      />
                    )}
                  </Card.Body>
                </Card>

                {latest && (
                  <div className="network-overview-grid">
                    <Card>
                      <Card.Body>
                        <div className="d-flex align-items-baseline gap-2 flex-wrap mb-2">
                          <h2 className="h6 mb-0">Network map · latest capture</h2>
                          <span className="small text-muted">
                            {latest.fileName} · {day(latest)}
                          </span>
                          <button
                            type="button"
                            className="btn btn-link btn-sm p-0 ms-auto"
                            onClick={() => pick('timeline')}
                          >
                            Open in Timeline
                          </button>
                        </div>
                        <SnapshotMap
                          key={latest.id}
                          networkId={network.id}
                          snapshot={latest}
                          previous={beforeLatest}
                          changeEvents={changeEvents}
                          height={380}
                        />
                      </Card.Body>
                    </Card>
                    <Card>
                      <Card.Body>
                        <div className="d-flex align-items-center mb-2">
                          <h2 className="h6 mb-0">Insights</h2>
                          <HelpPopover
                            id="network-insights-info"
                            title="Network Insights"
                            buttonTitle="About network insights"
                          >
                            <p className="mb-2">
                              Clicking <strong>Generate</strong> sends your network's snapshots,
                              change events, device roles, external events, and analyst annotations
                              to the configured LLM. It returns a structured narrative explaining
                              observed behaviour in operational context.
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
                                <strong>Correlations</strong> — links between external events and
                                network changes
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
                          job={data.insightJob}
                          onCancelJob={data.cancelInsightJob}
                        />
                      </Card.Body>
                    </Card>
                  </div>
                )}

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

            {section === 'timeline' && (
              <NetworkTimeline
                networkId={network.id}
                snapshots={snapshots}
                changeEvents={changeEvents}
                externalEvents={externalEvents}
                annotations={annotations}
                onPatchChange={data.handlePatchChange}
                onSnapshotUpdated={data.handleSnapshotUpdated}
                onAddNote={() => setShowNotes(true)}
                onAddEvent={() => setShowEvents(true)}
                onManage={() => setShowManage(true)}
              />
            )}

            {section === 'inventory' && (
              <Card className="network-inventory">
                <div className="network-inventory-tabs" role="tablist" aria-label="Inventory">
                  {(
                    [
                      ['devices', 'Devices', deviceCounts?.all],
                      ['addresses', 'Addresses', undefined],
                      ['apps', 'Apps and protocols', undefined],
                    ] as const
                  ).map(([key, label, count]) => (
                    <button
                      key={key}
                      type="button"
                      role="tab"
                      aria-selected={inventoryTab === key}
                      className={`network-inventory-tab${inventoryTab === key ? ' active' : ''}`}
                      onClick={() => setInventoryTab(key)}
                    >
                      {label}
                      {count !== undefined && (
                        <span className="network-inventory-count">{count}</span>
                      )}
                    </button>
                  ))}
                </div>
                <Card.Body role="tabpanel">
                  {inventoryTab === 'devices' && (
                    <DeviceDriftPanel snapshots={snapshots} settings={network.settings} />
                  )}
                  {inventoryTab === 'addresses' && (
                    <IpDriftPanel
                      networkId={networkId}
                      snapshots={snapshots}
                      subnets={subnets}
                      settings={network.settings}
                    />
                  )}
                  {inventoryTab === 'apps' && (
                    <ProtocolDriftPanel snapshots={snapshots} settings={network.settings} />
                  )}
                </Card.Body>
              </Card>
            )}
          </main>
        </div>
      </div>

      <SideDrawer
        show={showSettings}
        onHide={() => setShowSettings(false)}
        title="Network settings"
        titleId="network-settings-title"
        className="network-settings-drawer"
      >
        <section className="network-settings-section">
          <div className="d-flex align-items-center mb-2">
            <h3 className="h6 mb-0">Expected state</h3>
            <HelpPopover
              id="baseline-definitions-info"
              title="Baseline Definitions"
              buttonTitle="About baseline definitions"
            >
              <p className="mb-2 text-muted">
                Manually declare what is <em>expected</em> on this network. Entries here suppress
                false-positive change events for known-good devices, bindings, and services.
              </p>
              <ul className="mb-0 ps-3">
                <li className="mb-1">
                  <strong>Device (MAC)</strong> — a MAC address that is authorised on the network
                </li>
                <li className="mb-1">
                  <strong>IP ↔ MAC Binding</strong> — a fixed IP-to-MAC mapping (e.g. a static DHCP
                  lease)
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
                  <strong>VPN Fingerprint</strong> — a VPN risk type that is authorised on this
                  network
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
        </section>
        <section className="network-settings-section">
          <div className="d-flex align-items-center mb-2">
            <h3 className="h6 mb-0">Subnets</h3>
            <HelpPopover
              id="subnet-definitions-info"
              title="How Subnet Detection Works"
              maxWidth={400}
              buttonTitle="How subnet detection works"
            >
              <p className="mb-2">
                The scanner collects all <strong>private IP addresses</strong> (RFC 1918:{' '}
                <code>10.x</code>, <code>172.16–31.x</code>, <code>192.168.x</code>) seen in the
                snapshot's host classifications. For each observed IP, candidate CIDRs at every
                prefix length from /20 to /29 are generated and scored by{' '}
                <strong>host density</strong> (observed hosts ÷ subnet capacity). A greedy
                non-overlapping selection picks the highest-density candidates, preferring tighter,
                more specific prefixes.
              </p>
              <p className="mb-2">
                <strong>Scan All Snapshots</strong> runs detection across every snapshot and adds a{' '}
                <strong>Consistency</strong> score — subnets seen in more snapshots float to the
                top. Single-snapshot candidates are flagged in amber.
              </p>
              <p className="mb-2">
                <strong>Per-snapshot overrides.</strong> Individual snapshots can carry their own
                subnet list that shadows the global definitions for that snapshot's change
                detection. Set them from a capture's <em>Subnets</em> tab in the Timeline.
              </p>
              <p className="fw-semibold mb-1">Limitations</p>
              <ul className="mb-0 ps-3">
                <li className="mb-1">
                  <strong>Prefix range /20–/29 only.</strong> Very large blocks or micro-segments
                  (/30–/32) are outside the search range.
                </li>
                <li className="mb-1">
                  <strong>No routing topology awareness.</strong> Infers from observed host
                  distribution only — no VLAN or gateway knowledge.
                </li>
                <li className="mb-1">
                  <strong>Small subnets are dropped.</strong> Segments with fewer than 3 classified
                  hosts will not appear.
                </li>
                <li className="mb-1">
                  <strong>Only classified hosts count.</strong> Hosts with too little traffic to be
                  fingerprinted are excluded.
                </li>
                <li>
                  <strong>Tunnel &amp; VPN addresses.</strong> Private IPs in VPN overlays are
                  treated the same as LAN hosts.
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
        </section>
        <section className="network-settings-section">
          <h3 className="h6 mb-2">More</h3>
          <div className="network-settings-links">
            <Button variant="outline-secondary" size="sm" onClick={() => setShowInactivity(true)}>
              When a device counts as gone
            </Button>
            <Button variant="outline-secondary" size="sm" onClick={() => setShowRules(true)}>
              Detection rules
            </Button>
            <Button variant="outline-secondary" size="sm" onClick={() => setShowAddresses(true)}>
              Address labels
            </Button>
            <Button variant="outline-secondary" size="sm" onClick={() => setShowDevices(true)}>
              Device labels
            </Button>
          </div>
          <Form.Label htmlFor="network-refresh" className="small text-muted mt-3 mb-1">
            Refresh this page
          </Form.Label>
          <Form.Select
            id="network-refresh"
            size="sm"
            value={pollInterval}
            onChange={e => setPollInterval(Number(e.target.value))}
            style={{ maxWidth: 200 }}
          >
            <option value={10}>Every 10s</option>
            <option value={30}>Every 30s</option>
            <option value={60}>Every 1m</option>
            <option value={300}>Every 5m</option>
            <option value={0}>Manual only</option>
          </Form.Select>
        </section>
      </SideDrawer>

      <Modal show={showNotes} onHide={() => setShowNotes(false)} size="lg" scrollable>
        <Modal.Header closeButton>
          <Modal.Title>Notes</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <p className="small text-muted">
            Free-text notes on this network. Insights read them as context.
          </p>
          <NetworkAnnotationsPanel
            annotations={annotations}
            onAdd={data.handleAddAnnotation}
            onUpdate={data.handleUpdateAnnotation}
            onDelete={data.handleDeleteAnnotation}
          />
        </Modal.Body>
      </Modal>

      <Modal show={showEvents} onHide={() => setShowEvents(false)} size="lg" scrollable>
        <Modal.Header closeButton>
          <Modal.Title>Outside events</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <p className="small text-muted">
            Real-world events (maintenance windows, incidents, policy changes) to line up with what
            changed. Insights take them into account.
          </p>
          <ExternalEventsPanel
            events={externalEvents}
            onAdd={data.handleAddExternalEvent}
            onUpdate={data.handleUpdateExternalEvent}
            onDelete={data.handleDeleteExternalEvent}
          />
        </Modal.Body>
      </Modal>

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
        show={showAddSnapshot && addCaptures.allowed}
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
        show={showInactivity}
        onHide={() => setShowInactivity(false)}
        initial={network.settings}
        onSave={async settings => {
          await monitorService.updateNetworkSettings(network.id, settings);
          reload(false);
        }}
      />
    </div>
  );
};
