import { useState, useEffect } from 'react';
import { useOutletContext, useNavigate } from 'react-router-dom';
import type { AnalysisData } from '@/types';
import { AnalysisSummary } from '@components/analysis/AnalysisSummary';
import { ProtocolBreakdownChart } from '@components/analysis/ProtocolBreakdown';
import { CategoryBreakdownChart } from '@components/analysis/CategoryBreakdown';
import { getAppColor, getTextColor, getSeverityColor, RISK_BADGE } from '@/utils/appColors';
import { getProtocolColor } from '@/features/network/constants';
import { OverlayTrigger, Popover } from '@govtechsg/sgds-react';
import { conversationService } from '@/features/conversation/services/conversationService';

interface AnalysisOutletContext {
  data: AnalysisData;
  fileId: string;
}

const ndpiPopover = (
  <Popover id="ndpi-app-info" style={{ maxWidth: '320px' }}>
    <Popover.Header>About application detection</Popover.Header>
    <Popover.Body>
      <p className="mb-2">
        Application labels are identified by{' '}
        <a
          href="https://www.ntop.org/products/deep-packet-inspection/ndpi/"
          target="_blank"
          rel="noopener noreferrer"
        >
          nDPI
        </a>{' '}
        deep packet inspection, which recognises services such as YouTube, WhatsApp, and Zoom by
        traffic signatures and metadata.
      </p>
      <p className="mb-2">
        Encrypted flows (TLS/QUIC) are identified by metadata such as SNI and JA3 fingerprints, not
        payload content.
      </p>
      <p className="mb-0">
        Treat labels as strong indicators, not definitive classifications. Cross-reference the
        destination IP/port and packet payload if a label looks unexpected.
      </p>
    </Popover.Body>
  </Popover>
);

const l7Popover = (
  <Popover id="l7-info" style={{ maxWidth: '320px' }}>
    <Popover.Header>About L7 protocols</Popover.Header>
    <Popover.Body>
      <p className="mb-2">
        Layer 7 protocols are identified by{' '}
        <a href="https://www.wireshark.org/" target="_blank" rel="noopener noreferrer">
          Wireshark
        </a>{' '}
        (tshark) deterministic dissectors — e.g. TLS, HTTP, DNS, QUIC. These reflect the
        application-layer protocol in use, independent of the service generating the traffic.
      </p>
      <p className="mb-0">
        Click any badge to filter the Conversations tab to flows using that protocol.
      </p>
    </Popover.Body>
  </Popover>
);

const riskPopover = (
  <Popover id="risk-info" style={{ maxWidth: '320px' }}>
    <Popover.Header>About nDPI risk flags</Popover.Header>
    <Popover.Body>
      <p className="mb-2">
        Risk flags are raised by{' '}
        <a
          href="https://www.ntop.org/products/deep-packet-inspection/ndpi/"
          target="_blank"
          rel="noopener noreferrer"
        >
          nDPI
        </a>{' '}
        based on built-in heuristics — for example, clear-text credentials, unsafe protocols,
        known-malicious TLS fingerprints, or unexpected port usage.
      </p>
      <p className="mb-0">
        Click any badge to filter the Conversations tab to flows carrying that risk flag.
      </p>
    </Popover.Body>
  </Popover>
);

const customRulesPopover = (
  <Popover id="custom-rules-info" style={{ maxWidth: '320px' }}>
    <Popover.Header>About custom security alerts</Popover.Header>
    <Popover.Body>
      <p className="mb-2">
        These rules are defined in <code>signatures.yml</code> and matched against each conversation
        after nDPI analysis. Matches are based on IP, CIDR, port, JA3 fingerprint, SNI hostname,
        application name, or transport protocol.
      </p>
      <p className="mb-0">
        Badge colours reflect severity: <strong style={{ color: '#dc3545' }}>critical</strong>,{' '}
        <strong style={{ color: '#fd7e14' }}>high</strong>,{' '}
        <strong style={{ color: '#e67e22' }}>medium</strong>,{' '}
        <strong style={{ color: '#6f42c1' }}>low</strong>. Click any badge to filter conversations
        by that rule.
      </p>
    </Popover.Body>
  </Popover>
);

export const AnalysisOverview = () => {
  const { data, fileId } = useOutletContext<AnalysisOutletContext>();
  const navigate = useNavigate();
  const [signatureSeverities, setSignatureSeverities] = useState<Record<string, string>>({});
  const [riskTypes, setRiskTypes] = useState<string[]>([]);

  useEffect(() => {
    conversationService
      .getSignatureRules()
      .then(rules => {
        const map: Record<string, string> = {};
        rules.forEach(r => {
          map[r.name] = r.severity;
        });
        setSignatureSeverities(map);
      })
      .catch(console.error);

    conversationService.getRiskTypes(fileId).then(setRiskTypes).catch(console.error);
  }, [fileId]);

  const detectedApps = data.detectedApplications ?? [];

  return (
    <div className="analysis-overview">
      <AnalysisSummary summary={data} />

      {detectedApps.length > 0 && (
        <div className="mt-4">
          <h5 className="mb-3 d-flex align-items-center gap-2">
            <i className="bi bi-app-indicator me-2"></i>
            Applications Detected
            {data.detectedApplicationsTruncated && (
              <span className="text-muted fs-6 fw-normal ms-2">
                (showing top {detectedApps.length})
              </span>
            )}
            <OverlayTrigger trigger="click" placement="right" overlay={ndpiPopover} rootClose>
              <button
                type="button"
                className="btn btn-link p-0 text-muted"
                style={{ lineHeight: 1 }}
                aria-label="About application detection accuracy"
              >
                <i className="bi bi-info-circle fs-6"></i>
              </button>
            </OverlayTrigger>
          </h5>
          <div className="d-flex flex-wrap gap-2">
            {detectedApps.map(app => {
              const appColor = getAppColor(app.name);
              return (
                <button
                  key={app.name}
                  className="badge rounded-pill px-3 py-2 fs-6 border-0"
                  style={{
                    backgroundColor: appColor,
                    color: getTextColor(appColor),
                    cursor: 'pointer',
                  }}
                  title={`${(app.packetCount ?? 0).toLocaleString()} packets · ${((app.bytes ?? 0) / 1024).toFixed(1)} KB — click to filter conversations`}
                  onClick={() =>
                    navigate(
                      `/analysis/${fileId}/conversations?app=${encodeURIComponent(app.name)}`
                    )
                  }
                >
                  {app.name}
                </button>
              );
            })}
          </div>
        </div>
      )}

      {data.detectedL7Protocols && data.detectedL7Protocols.length > 0 && (
        <div className="mt-4">
          <h5 className="mb-3 d-flex align-items-center gap-2">
            <i className="bi bi-layers me-2"></i>
            L7 Protocols Detected
            <OverlayTrigger trigger="click" placement="right" overlay={l7Popover} rootClose>
              <button
                type="button"
                className="btn btn-link p-0 text-muted"
                style={{ lineHeight: 1 }}
                aria-label="About L7 protocol detection"
              >
                <i className="bi bi-info-circle fs-6"></i>
              </button>
            </OverlayTrigger>
          </h5>
          <div className="d-flex flex-wrap gap-2">
            {data.detectedL7Protocols.map(proto => {
              const bg = getProtocolColor(proto);
              return (
                <button
                  key={proto}
                  className="badge rounded-pill px-3 py-2 fs-6 border-0"
                  style={{ backgroundColor: bg, color: getTextColor(bg), cursor: 'pointer' }}
                  title="Click to filter conversations by this protocol"
                  onClick={() =>
                    navigate(
                      `/analysis/${fileId}/conversations?l7Protocols=${encodeURIComponent(proto)}`
                    )
                  }
                >
                  {proto}
                </button>
              );
            })}
          </div>
        </div>
      )}

      {riskTypes.length > 0 && (
        <div className="mt-4">
          <h5 className="mb-3 d-flex align-items-center gap-2">
            <i className="bi bi-shield-exclamation me-2 text-warning"></i>
            Risk Alerts
            <OverlayTrigger trigger="click" placement="right" overlay={riskPopover} rootClose>
              <button
                type="button"
                className="btn btn-link p-0 text-muted"
                style={{ lineHeight: 1 }}
                aria-label="About nDPI risk flags"
              >
                <i className="bi bi-info-circle fs-6"></i>
              </button>
            </OverlayTrigger>
          </h5>
          <div className="d-flex flex-wrap gap-2">
            {riskTypes.map(risk => (
              <button
                key={risk}
                className="badge rounded-pill px-3 py-2 fs-6 border-0"
                style={{
                  backgroundColor: RISK_BADGE.bg,
                  color: RISK_BADGE.text,
                  cursor: 'pointer',
                }}
                title="Click to filter conversations by this risk flag"
                onClick={() =>
                  navigate(
                    `/analysis/${fileId}/conversations?riskTypes=${encodeURIComponent(risk)}`
                  )
                }
              >
                {risk}
              </button>
            ))}
          </div>
        </div>
      )}

      {data.triggeredCustomRules && data.triggeredCustomRules.length > 0 && (
        <div className="mt-4">
          <h5 className="mb-3 d-flex align-items-center gap-2">
            <i className="bi bi-shield-lock me-2" style={{ color: '#6f42c1' }}></i>
            Custom Security Alerts
            <OverlayTrigger
              trigger="click"
              placement="right"
              overlay={customRulesPopover}
              rootClose
            >
              <button
                type="button"
                className="btn btn-link p-0 text-muted"
                style={{ lineHeight: 1 }}
                aria-label="About custom security alerts"
              >
                <i className="bi bi-info-circle fs-6"></i>
              </button>
            </OverlayTrigger>
          </h5>
          <div className="d-flex flex-wrap gap-2">
            {data.triggeredCustomRules.map(rule => {
              const { bg, text } = getSeverityColor(signatureSeverities[rule]);
              return (
                <button
                  key={rule}
                  className="badge rounded-pill px-3 py-2 fs-6 border-0"
                  style={{ backgroundColor: bg, color: text, cursor: 'pointer' }}
                  title="Click to filter conversations by this rule"
                  onClick={() =>
                    navigate(
                      `/analysis/${fileId}/conversations?customSignatures=${encodeURIComponent(rule)}`
                    )
                  }
                >
                  {rule.replace(/_/g, ' ')}
                </button>
              );
            })}
          </div>
        </div>
      )}

      {data.protocolDistribution && data.protocolDistribution.length > 0 && (
        <div className="mt-4">
          <ProtocolBreakdownChart protocolStats={data.protocolDistribution} />
        </div>
      )}

      {data.categoryDistribution && data.categoryDistribution.length > 0 && (
        <div className="mt-4">
          <CategoryBreakdownChart categoryStats={data.categoryDistribution} />
        </div>
      )}
    </div>
  );
};
