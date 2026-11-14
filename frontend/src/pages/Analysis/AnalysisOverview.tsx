import { useNetworkContext } from '@/features/detectionRules/useNetworkContext';
import { RuleScopeTag } from '@/features/detectionRules/RuleScopeTag';
import { RuleSyncBanner } from '@/features/detectionRules/RuleSyncBanner';
import { NetworkSegmentsPanel } from '@/features/networkSegments/NetworkSegmentsPanel';
import { usePermission } from '@/features/me/useMe';
import { useState, useEffect } from 'react';
import { useOutletContext, useNavigate } from 'react-router-dom';
import type { AnalysisData, TimelineDataPoint } from '@/types';
import { SourceTag } from '@components/analysis/Overview/SourceTag';
import { MixBar, type MixRow } from '@components/analysis/Overview/MixBar';
import '@components/analysis/Overview/Overview.css';
import { getProtocolColor } from '@/features/network/constants';
import { timelineService } from '@/features/timeline/services/timelineService';
import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import { formatBytes } from '@/utils/formatters';
import {
  getAppColor,
  getCategoryColor,
  getL7ProtocolColor,
  getTextColor,
  getSeverityColor,
  RISK_BADGE,
} from '@/utils/appColors';
import { conversationService } from '@/features/conversation/services/conversationService';
import { storyService } from '@/features/story/services/storyService';
import { getExtractedFiles } from '@features/extractedFiles/services/extractedFilesService';
import { EntityDetailModal } from '@components/common/EntityDetailModal';
import { ConfirmedFindingsPanel } from '@components/story/ConfirmedFindingsPanel/ConfirmedFindingsPanel';
import type { Answer } from '@/types';

interface AnalysisOutletContext {
  data: AnalysisData;
  fileId: string;
  refreshSummary?: () => void;
}

const ndpiPopoverBody = (
  <>
    <p className="mb-2">
      Application labels are identified by{' '}
      <a href="/ndpi-reference.html" target="_blank" rel="noopener noreferrer">
        nDPI
      </a>{' '}
      deep packet inspection, which recognises services such as YouTube, WhatsApp, and Zoom by
      traffic signatures and metadata.
    </p>
    <p className="mb-2">
      Encrypted flows (TLS/QUIC) are identified by metadata such as SNI and JA3 fingerprints, not
      payload content.
    </p>
    <p className="mb-2">
      Treat labels as strong indicators, not definitive classifications. Cross-reference the
      destination IP/port and packet payload if a label looks unexpected.
    </p>
    <a href="/ndpi-reference.html" target="_blank" rel="noopener noreferrer" className="small">
      View protocol reference →
    </a>
  </>
);

const l7PopoverBody = (
  <>
    <p className="mb-2">
      Determined by{' '}
      <a href="https://www.wireshark.org/" target="_blank" rel="noopener noreferrer">
        Wireshark
      </a>
      's tshark, which inspects each flow's payload using built-in deterministic dissectors and
      reports the deepest protocol it can decode — e.g. TLS, HTTP, DNS, QUIC.
    </p>
    <p className="mb-0">
      Click any badge to filter the Conversations tab to flows using that protocol.
    </p>
  </>
);

export const AnalysisOverview = () => {
  const { data, fileId } = useOutletContext<AnalysisOutletContext>();
  // Viewed in a network (#925 phase 3): its own rules' matches count as triggered too.
  const [networkContext] = useNetworkContext();
  const [networkTriggered, setNetworkTriggered] = useState<string[]>([]);
  const ctxQuery = networkContext ? `&networkId=${encodeURIComponent(networkContext)}` : '';
  const rulesPermission = usePermission('DETECTION_RULES_GLOBAL');
  const navigate = useNavigate();
  const [signatureSeverities, setSignatureSeverities] = useState<Record<string, string>>({});
  const [signatureScopes, setSignatureScopes] = useState<Record<string, string>>({});
  const [riskTypes, setRiskTypes] = useState<string[]>([]);
  const [extractedFilesCount, setExtractedFilesCount] = useState<number | undefined>(undefined);
  const [answers, setAnswers] = useState<Answer[]>([]);
  const [activity, setActivity] = useState<TimelineDataPoint[]>([]);
  const [flagged, setFlagged] = useState({ total: 0, risks: 0, suricata: 0, custom: 0 });

  // Packets over time for the activity chart, and how the flagged conversations were flagged.
  useEffect(() => {
    let alive = true;
    timelineService
      .getTimelineData(fileId, undefined, 60)
      .then(points => {
        if (alive) setActivity(points);
      })
      .catch(() => {});
    apiClient
      .get<{ flowRisks?: string[]; suricataAlerts?: unknown[]; customSignatures?: string[] }[]>(
        API_ENDPOINTS.SECURITY_ALERTS(fileId)
      )
      .then(r => {
        if (!alive) return;
        const rows = r.data ?? [];
        setFlagged({
          total: rows.length,
          risks: rows.filter(x => (x.flowRisks?.length ?? 0) > 0).length,
          suricata: rows.filter(x => (x.suricataAlerts?.length ?? 0) > 0).length,
          custom: rows.filter(x => (x.customSignatures?.length ?? 0) > 0).length,
        });
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, [fileId]);
  const [unknowns, setUnknowns] = useState<string[]>([]);

  // Entity detail modal
  type EntityModalState = { type: 'PROTOCOL' | 'APPLICATION'; key: string; name: string } | null;
  const [entityModal, setEntityModal] = useState<EntityModalState>(null);

  useEffect(() => {
    conversationService
      .getSignatureRules(fileId, networkContext)
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

    conversationService.getRiskTypes(fileId).then(setRiskTypes).catch(console.error);

    getExtractedFiles(fileId)
      .then(files => setExtractedFilesCount(files.length))
      .catch(() => setExtractedFilesCount(undefined));

    storyService
      .getInvestigation(fileId)
      .then(s => {
        setAnswers(s.answers);
        setUnknowns(s.unknowns);
      })
      .catch(() => {
        setAnswers([]);
        setUnknowns([]);
      });
    if (networkContext) {
      conversationService
        .getCustomSignatures(fileId, networkContext)
        .then(setNetworkTriggered)
        .catch(() => setNetworkTriggered([]));
    }
  }, [fileId, networkContext]);

  // In a network, the network-aware list: stored matches minus the global rules it switched off,
  // plus its own rules' matches (#925 phases 3-4).
  const triggeredRules = networkContext ? networkTriggered : (data.triggeredCustomRules ?? []);

  const detectedApps = data.detectedApplications ?? [];

  const durationText = (() => {
    const ms = data.timeRange ? data.timeRange[1] - data.timeRange[0] : 0;
    const m = Math.floor(ms / 60000);
    const sec = Math.round((ms % 60000) / 1000);
    return m > 0 ? `${m}m ${sec}s` : `${sec}s`;
  })();
  const protoRows: MixRow[] = (data.protocolDistribution ?? []).map(p => ({
    name: p.protocol,
    packets: p.count,
    bytes: p.bytes,
    percentage: p.percentage,
    color: getProtocolColor(p.protocol),
  }));
  const catRows: MixRow[] = (data.categoryDistribution ?? []).map(c => ({
    name: c.category,
    packets: c.count,
    bytes: c.bytes,
    percentage: c.percentage,
    color: getCategoryColor(c.category),
  }));
  const maxBin = Math.max(1, ...activity.map(a => a.packetCount));
  const topConvs = (data.topConversations ?? []).slice(0, 5);
  // The summary sends srcIp/dstIp here, not the endpoints pair the type declares.
  const ends = (c: (typeof topConvs)[number]) => {
    const raw = c as unknown as { srcIp?: string; dstIp?: string };
    const a = c.endpoints?.[0]?.ip ?? raw.srcIp ?? '?';
    const b = c.endpoints?.[1]?.ip ?? raw.dstIp ?? '?';
    return `${a} ↔ ${b}`;
  };
  const maxConv = Math.max(1, ...topConvs.map(c => c.totalBytes));

  return (
    <div className="analysis-overview">
      {/* Out of date with the detection rules? Says which, and offers Re-apply (#925 phase 2). */}
      <RuleSyncBanner
        fileId={fileId}
        canReapply={rulesPermission.allowed}
        reason={rulesPermission.reason}
      />

      {/* Two networks on one range in this capture (#462): shown only when there are. */}
      <NetworkSegmentsPanel fileId={fileId} />

      <div className="ov-grid">
        {/* Left: the traffic. */}
        <div className="ov-col">
          <section className="ov-card ov-totals" aria-label="Totals">
            <div>
              <b>{Array.isArray(data.uniqueHosts) ? data.uniqueHosts.length.toLocaleString() : (data.uniqueHosts ?? '—')}</b>
              <span>hosts</span>
            </div>
            <div>
              <b>{data.totalConversations.toLocaleString()}</b>
              <span>conversations</span>
            </div>
            <div>
              <b>{data.totalPackets.toLocaleString()}</b>
              <span>packets</span>
            </div>
            <div>
              <b>{durationText}</b>
              <span>captured</span>
            </div>
          </section>

          {activity.length > 1 && (
            <section className="ov-card" aria-labelledby="ov-activity">
              <div className="ov-head">
                <h2 id="ov-activity">Activity over time</h2>
                <SourceTag id="src-activity" source="tshark" title="How activity is worked out">
                  <p className="mb-0">
                    Every packet's timestamp, as tshark read it from the capture, counted into equal
                    time slices. Each bar is the packets in one slice; hover it for the count.
                  </p>
                </SourceTag>
              </div>
              <div
                className="ov-activity"
                role="img"
                aria-label={`Packets over time, peak ${maxBin} in one slice`}
              >
                {activity.map(a => (
                  <span
                    key={a.timestamp}
                    style={{ height: `${Math.max(4, (a.packetCount / maxBin) * 100)}%` }}
                    title={`${new Date(a.timestamp).toLocaleTimeString()}: ${a.packetCount} packets`}
                  />
                ))}
              </div>
              <div className="ov-activity-axis">
                <span>{new Date(activity[0].timestamp).toLocaleTimeString()}</span>
                <span>
                  {new Date(activity[activity.length - 1].timestamp).toLocaleTimeString()}
                </span>
              </div>
            </section>
          )}

          {(protoRows.length > 0 || catRows.length > 0) && (
            <section className="ov-card" aria-labelledby="ov-mix">
              <div className="ov-head">
                <h2 id="ov-mix">Traffic mix</h2>
                <SourceTag
                  id="src-mix"
                  source="tshark and nDPI"
                  title="How the traffic mix is worked out"
                >
                  <p className="mb-2">
                    <strong>Protocols</strong>: tshark dissects every packet and reports the
                    highest-layer protocol it recognises. Shares are of packets.
                  </p>
                  <p className="mb-0">
                    <strong>Categories</strong>: nDPI puts each conversation's application into a
                    category (Web, Media, System…), and its packets count towards it.
                  </p>
                </SourceTag>
              </div>
              {protoRows.length > 0 && <MixBar title="Protocols" column="Protocol" rows={protoRows} />}
              {catRows.length > 0 && <MixBar title="Categories" column="Category" rows={catRows} />}
            </section>
          )}

          {topConvs.length > 0 && (
            <section className="ov-card" aria-labelledby="ov-busiest">
              <div className="ov-head">
                <h2 id="ov-busiest">Busiest conversations</h2>
                <SourceTag
                  id="src-busiest"
                  source="tshark"
                  title="How conversations are worked out"
                >
                  <p className="mb-0">
                    tshark groups packets into conversations by their two endpoints and ports, both
                    directions together. These are the ones that carried the most bytes.
                  </p>
                </SourceTag>
                <button
                  type="button"
                  className="btn btn-link btn-sm p-0 ms-auto"
                  onClick={() => navigate(`/analysis/${fileId}/conversations`)}
                >
                  All conversations
                </button>
              </div>
              <ol className="ov-busiest">
                {topConvs.map((c, i) => (
                  <li key={c.id ?? i}>
                    <span className="ov-busiest-hosts">
                      {ends(c)}
                    </span>
                    <span className="ov-busiest-app">{c.appName ?? (typeof c.protocol === 'string' ? c.protocol : c.protocol?.name)}</span>
                    <span className="ov-bar" aria-hidden="true">
                      <span style={{ width: `${Math.max(2, (c.totalBytes / maxConv) * 100)}%` }} />
                    </span>
                    <span className="ov-busiest-bytes">{formatBytes(c.totalBytes)}</span>
                  </li>
                ))}
              </ol>
            </section>
          )}
        </div>

        {/* Right: what to look at. */}
        <div className="ov-col">
          <section
            className={`ov-card${flagged.total > 0 ? ' ov-card-warn' : ''}`}
            aria-labelledby="ov-look"
          >
            <div className="ov-head">
              <h2 id="ov-look">Needs a look</h2>
              <SourceTag
                id="src-look"
                source="nDPI, Suricata and your rules"
                title="How conversations are flagged"
              >
                <p className="mb-2">A conversation is flagged when any of these mark it:</p>
                <ul className="mb-2 ps-3">
                  <li>
                    <strong>nDPI risks</strong>: built-in heuristics, e.g. clear-text credentials or
                    a known-malicious TLS fingerprint.
                  </li>
                  <li>
                    <strong>Suricata</strong>: the Emerging Threats Open signatures, when Suricata
                    was on for this capture.
                  </li>
                  <li>
                    <strong>Custom rules</strong>: your detection rules (Settings › Detection rules,
                    and this capture's own).
                  </li>
                </ul>
                <a href="/ndpi-reference.html" target="_blank" rel="noopener noreferrer">
                  nDPI risk reference →
                </a>
              </SourceTag>
            </div>
            {flagged.total === 0 ? (
              <p className="small text-muted mb-0">Nothing flagged in this capture.</p>
            ) : (
              <>
                <button
                  type="button"
                  className="ov-flagged"
                  onClick={() => navigate(`/analysis/${fileId}/conversations?hasRisks=true`)}
                >
                  <b>{flagged.total}</b>
                  <span>
                    flagged conversation{flagged.total === 1 ? '' : 's'}
                    <small>
                      {flagged.risks} by nDPI risks · {flagged.suricata} by Suricata ·{' '}
                      {flagged.custom} by custom rules
                    </small>
                  </span>
                </button>
                {riskTypes.length > 0 && (
                  <div className="ov-sub">
                    <h3>nDPI risks</h3>
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
                {triggeredRules.length > 0 && (
                  <div className="ov-sub">
                    <h3>Custom rules matched</h3>
                    <div className="d-flex flex-wrap gap-2">
                      {triggeredRules.map(rule => {
                        const { bg, text } = getSeverityColor(signatureSeverities[rule]);
                        return (
                          <button
                            key={rule}
                            className="badge rounded-pill px-3 py-2 fs-6 border-0"
                            style={{ backgroundColor: bg, color: text, cursor: 'pointer' }}
                            title="Click to filter conversations by this rule"
                            onClick={() =>
                              navigate(
                                `/analysis/${fileId}/conversations?customSignatures=${encodeURIComponent(rule)}${ctxQuery}`
                              )
                            }
                          >
                            {rule.replace(/_/g, ' ')}
                            <RuleScopeTag scope={signatureScopes[rule]} />
                          </button>
                        );
                      })}
                    </div>
                  </div>
                )}
              </>
            )}
            {extractedFilesCount != null && extractedFilesCount > 0 && (
              <button
                type="button"
                className="btn btn-link btn-sm p-0 mt-2"
                onClick={() => navigate(`/analysis/${fileId}/extracted-files`)}
              >
                {extractedFilesCount} file{extractedFilesCount === 1 ? '' : 's'} found in the
                traffic
              </button>
            )}
          </section>

          {/* Investigation Summary — deterministic answers surfaced at a glance (#813 slice 4). */}
          {answers.length > 0 && <ConfirmedFindingsPanel answers={answers} unknowns={unknowns} />}

          {(detectedApps.length > 0 || (data.detectedL7Protocols?.length ?? 0) > 0) && (
            <section className="ov-card" aria-labelledby="ov-apps">
              {detectedApps.length > 0 && (
                <div className="ov-sub ov-sub-first">
                  <div className="ov-head">
                    <h2 id="ov-apps">Applications detected</h2>
                    <SourceTag id="src-apps" source="nDPI" title="How applications are detected">
                      {ndpiPopoverBody}
                    </SourceTag>
                  </div>
                  {data.detectedApplicationsTruncated && (
                    <p className="small text-muted mb-2">Showing the top {detectedApps.length}.</p>
                  )}
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
                          title={`${(app.packetCount ?? 0).toLocaleString()} packets · ${((app.bytes ?? 0) / 1024).toFixed(1)} KB — click for details`}
                          onClick={() =>
                            setEntityModal({ type: 'APPLICATION', key: app.name, name: app.name })
                          }
                        >
                          {app.name}
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}
              {(data.detectedL7Protocols?.length ?? 0) > 0 && (
                <div className="ov-sub">
                  <div className="ov-head">
                    <h3>Dissected protocols</h3>
                    <SourceTag id="src-l7" source="tshark" title="How protocols are dissected">
                      {l7PopoverBody}
                    </SourceTag>
                  </div>
                  <div className="d-flex flex-wrap gap-2">
                    {(data.detectedL7Protocols ?? []).map(proto => {
                      const bg = getL7ProtocolColor(proto);
                      return (
                        <button
                          key={proto}
                          className="badge rounded-pill px-3 py-2 fs-6 border-0"
                          style={{
                            backgroundColor: bg,
                            color: getTextColor(bg),
                            cursor: 'pointer',
                          }}
                          title="Click for details"
                          onClick={() =>
                            setEntityModal({ type: 'PROTOCOL', key: proto, name: proto })
                          }
                        >
                          {proto}
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}
            </section>
          )}
        </div>
      </div>

      {entityModal && (
        <EntityDetailModal
          entityType={entityModal.type}
          entityKey={entityModal.key}
          displayName={entityModal.name}
          fileId={fileId}
          badge={
            entityModal.type === 'APPLICATION' ? (
              <span
                className="badge rounded-pill"
                style={{
                  backgroundColor: getAppColor(entityModal.name),
                  color: getTextColor(getAppColor(entityModal.name)),
                  fontSize: '0.75rem',
                }}
              >
                App
              </span>
            ) : (
              <span
                className="badge rounded-pill"
                style={{
                  backgroundColor: getL7ProtocolColor(entityModal.name),
                  color: getTextColor(getL7ProtocolColor(entityModal.name)),
                  fontSize: '0.75rem',
                }}
              >
                Protocol
              </span>
            )
          }
          onViewConversations={
            entityModal.type === 'APPLICATION'
              ? () =>
                  navigate(
                    `/analysis/${fileId}/conversations?app=${encodeURIComponent(entityModal.key)}`
                  )
              : () =>
                  navigate(
                    `/analysis/${fileId}/conversations?l7Protocols=${encodeURIComponent(entityModal.key)}`
                  )
          }
          onClose={() => setEntityModal(null)}
        />
      )}
    </div>
  );
};
