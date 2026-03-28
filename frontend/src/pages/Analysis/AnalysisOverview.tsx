import { useOutletContext, useNavigate } from 'react-router-dom';
import type { AnalysisData } from '@/types';
import { AnalysisSummary } from '@components/analysis/AnalysisSummary';
import { ProtocolBreakdownChart } from '@components/analysis/ProtocolBreakdown';
import { CategoryBreakdownChart } from '@components/analysis/CategoryBreakdown';
import { getAppColor, getTextColor } from '@/utils/appColors';
import { OverlayTrigger, Popover } from '@govtechsg/sgds-react';

interface AnalysisOutletContext {
  data: AnalysisData;
  fileId: string;
}

const ndpiPopover = (
  <Popover id="ndpi-app-info" style={{ maxWidth: '320px' }}>
    <Popover.Header>About application detection</Popover.Header>
    <Popover.Body>
      <p className="mb-2">
        Application labels are detected by{' '}
        <a href="https://www.ntop.org/products/deep-packet-inspection/ndpi/" target="_blank" rel="noreferrer">nDPI</a>{' '}
        using deep packet inspection (DPI) heuristics.
      </p>
      <p className="mb-2">
        DPI is <strong>probabilistic</strong> — binary payloads can occasionally match the wrong
        protocol's signatures (e.g. a file transfer triggering peer-to-peer heuristics).
        Encrypted flows (TLS/QUIC) are identified by metadata such as SNI and JA3 fingerprints,
        not payload content.
      </p>
      <p className="mb-0">
        Treat labels as strong indicators, not definitive classifications. Cross-reference the
        destination IP/port and raw packet payload if a label looks unexpected.
      </p>
    </Popover.Body>
  </Popover>
);


export const AnalysisOverview = () => {
  const { data, fileId } = useOutletContext<AnalysisOutletContext>();
  const navigate = useNavigate();

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
              <span className="text-muted fs-6 fw-normal ms-2">(showing top {detectedApps.length})</span>
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
            {detectedApps.map(app => (
              <button
                key={app.name}
                className="badge rounded-pill px-3 py-2 fs-6 border-0"
                style={{
                  backgroundColor: getAppColor(app.name),
                  color: getTextColor(getAppColor(app.name)),
                  cursor: 'pointer',
                }}
                title={`${(app.packetCount ?? 0).toLocaleString()} packets · ${((app.bytes ?? 0) / 1024).toFixed(1)} KB — click to filter conversations`}
                onClick={() => navigate(`/analysis/${fileId}/conversations?app=${encodeURIComponent(app.name)}`)}
              >
                {app.name}
              </button>
            ))}
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
