import { useState } from 'react';
import { Badge, Card } from '@govtechsg/sgds-react';

/** Collapsible "How network monitoring works" explainer shown atop the detail page. */
export const MonitorInfoCard = () => {
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
