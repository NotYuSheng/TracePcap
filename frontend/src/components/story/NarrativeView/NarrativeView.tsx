import type { ReactNode } from 'react';
import type { NarrativeSection } from '@/types';
import { Card } from '@govtechsg/sgds-react';

interface NarrativeViewProps {
  sections: NarrativeSection[];
}

/** Inline **bold** → <strong>, safely (no HTML injection). */
function renderInline(text: string, keyBase: string): ReactNode[] {
  return text.split(/(\*\*[^*]+\*\*)/g).map((part, i) => {
    const m = /^\*\*([^*]+)\*\*$/.exec(part);
    return m ? <strong key={`${keyBase}-${i}`}>{m[1]}</strong> : <span key={`${keyBase}-${i}`}>{part}</span>;
  });
}

/**
 * Renders the LLM's section content as light Markdown so it reads as structured prose, not one wall
 * of text: blank-line-separated paragraphs, `- ` bullet lists, `##`–`####` sub-headings, and
 * **bold**. Built in (no dependency) and injection-safe — no dangerouslySetInnerHTML.
 */
function renderNarrative(content: string): ReactNode {
  const blocks = content.trim().split(/\n\s*\n/);
  return blocks.map((block, bi) => {
    const lines = block.split('\n').map(l => l.trim()).filter(Boolean);
    if (lines.length === 0) return null;

    const isList = lines.every(l => /^([-*•])\s+/.test(l));
    if (isList) {
      return (
        <ul key={bi} className="mb-2 ps-3">
          {lines.map((l, li) => (
            <li key={li}>{renderInline(l.replace(/^([-*•])\s+/, ''), `${bi}-${li}`)}</li>
          ))}
        </ul>
      );
    }

    const heading = /^#{2,4}\s+(.*)$/.exec(lines[0]);
    if (heading && lines.length === 1) {
      return (
        <h6 key={bi} className="fw-semibold mt-3 mb-1">
          {renderInline(heading[1], `${bi}-h`)}
        </h6>
      );
    }

    // A paragraph: join soft-wrapped lines with spaces.
    return (
      <p key={bi} className="mb-2">
        {renderInline(lines.join(' '), `${bi}`)}
      </p>
    );
  });
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
            <div className="narrative-content">{renderNarrative(section.content)}</div>

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
