import { useState } from 'react';
import { Button } from '@govtechsg/sgds-react';
import type { CheckedFilter } from '@/features/chat/chatService';
import { FilterPacketsDrawer } from './FilterPacketsDrawer';

/** A display filter the chat checked against this capture: Copy, and Show packets (#1161). */
export function FilterCard({ fileId, filter }: { fileId: string; filter: CheckedFilter }) {
  const [copied, setCopied] = useState(false);
  const [show, setShow] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(filter.expression);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  };
  const n = filter.matches ?? 0;
  return (
    <div className="chat-filter">
      <code className="chat-filter-expr">{filter.expression}</code>
      <div className="chat-filter-foot">
        <span className="text-muted small">
          <i className="bi bi-check-circle me-1" aria-hidden="true" />
          Valid · {n.toLocaleString()} {n === 1 ? 'packet matches' : 'packets match'}
        </span>
        <Button size="sm" variant="outline-secondary" onClick={copy}>
          {copied ? 'Copied' : 'Copy'}
        </Button>
        <Button size="sm" variant="outline-secondary" onClick={() => setShow(true)} disabled={n === 0}>
          Show packets
        </Button>
      </div>
      {show && <FilterPacketsDrawer fileId={fileId} filter={filter.expression} onHide={() => setShow(false)} />}
    </div>
  );
}
