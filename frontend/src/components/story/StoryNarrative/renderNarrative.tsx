import type { ReactNode } from 'react';

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
export function renderNarrative(content: string): ReactNode {
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
