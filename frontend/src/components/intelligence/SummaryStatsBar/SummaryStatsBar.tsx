import { Card } from '@govtechsg/sgds-react';
import type { AnalysisData } from '@/types';
import { formatBytes } from '@/utils/formatters';

interface SummaryStatsBarProps {
  data: AnalysisData;
}

export const SummaryStatsBar = ({ data }: SummaryStatsBarProps) => {
  const totalHosts = data.uniqueHosts?.length ?? 0;
  const totalConversations = data.totalConversations ?? 0;
  const totalBytes = (data.topConversations ?? []).reduce((sum, c) => sum + (c.totalBytes ?? 0), 0);
  const riskCount = data.securityAlertCount ?? 0;

  const stats = [
    {
      icon: 'bi-pc-display',
      label: 'Total Hosts',
      value: totalHosts.toLocaleString(),
      color: '#0072c6',
    },
    {
      icon: 'bi-arrow-left-right',
      label: 'Conversations',
      value: totalConversations.toLocaleString(),
      color: '#107c10',
    },
    {
      icon: 'bi-hdd-stack',
      label: 'Top Traffic',
      value: formatBytes(totalBytes),
      color: '#5c2d91',
    },
    {
      icon: 'bi-shield-exclamation',
      label: 'Risk Alerts',
      value: riskCount.toLocaleString(),
      color: riskCount > 0 ? '#d83b01' : '#767676',
    },
  ];

  return (
    <div className="row g-3 mb-4">
      {stats.map(s => (
        <div key={s.label} className="col-6 col-md-3">
          <Card
            className="h-100"
            style={{ borderLeft: `4px solid ${s.color}` }}
          >
            <Card.Body className="py-3">
              <div className="d-flex align-items-center gap-2 mb-1">
                <i className={`bi ${s.icon}`} style={{ color: s.color, fontSize: '1.1rem' }} />
                <small className="text-muted">{s.label}</small>
              </div>
              <div className="fw-bold fs-5">{s.value}</div>
            </Card.Body>
          </Card>
        </div>
      ))}
    </div>
  );
};
