import type { NarrativeSection } from '@/types';
import { Card } from '@govtechsg/sgds-react';

interface NarrativeViewProps {
  sections: NarrativeSection[];
}

export const NarrativeView = ({ sections }: NarrativeViewProps) => {
  const getSectionIcon = (type: string) => {
    const icons: Record<string, string> = {
      summary: 'bi-file-text',
      detail: 'bi-info-circle',
      anomaly: 'bi-exclamation-triangle',
      conclusion: 'bi-check-circle',
    };
    return icons[type] || 'bi-file-text';
  };

  const getSectionClass = (type: string) => {
    const classes: Record<string, string> = {
      summary: 'border-primary',
      detail: 'border-info',
      anomaly: 'border-warning',
      conclusion: 'border-success',
    };
    return classes[type] || 'border-secondary';
  };

  return (
    <div className="narrative-view">
      {sections.map((section, index) => (
        <Card key={index} className={`mb-3 overflow-hidden ${getSectionClass(section.type)}`}>
          <Card.Header className="bg-white rounded-top">
            <h5 className="mb-0 d-flex align-items-center">
              <i className={`bi ${getSectionIcon(section.type)} me-2`}></i>
              {section.title}
            </h5>
          </Card.Header>
          <Card.Body>
            <div className="narrative-content" style={{ whiteSpace: 'pre-line' }}>
              {section.content}
            </div>

            {section.relatedData && Object.keys(section.relatedData).length > 0 && (
              <div className="mt-3 pt-3 border-top">
                <small className="text-muted">
                  <strong>Related Data:</strong>
                  {section.relatedData.hosts && (
                    <span className="ms-2">Hosts: {section.relatedData.hosts.join(', ')}</span>
                  )}
                  {section.relatedData.conversations && (
                    <span className="ms-2">
                      Conversations: {section.relatedData.conversations.length}
                    </span>
                  )}
                  {section.relatedData.packets && (
                    <span className="ms-2">Packets: {section.relatedData.packets.length}</span>
                  )}
                </small>
              </div>
            )}
          </Card.Body>
        </Card>
      ))}
    </div>
  );
};
