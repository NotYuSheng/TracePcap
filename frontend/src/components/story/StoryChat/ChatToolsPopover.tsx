import { useEffect, useState } from 'react';
import { Button } from '@govtechsg/sgds-react';
import { InfoPopover } from '@components/common/InfoPopover';
import { EscapableOverlayTrigger } from '@components/common/EscapableOverlayTrigger';
import { chatService, toolCallingNote, type ChatTools } from '@/features/chat/chatService';

/** "Tools · 8" in the chat's header: what the chat can look up (#1161). */
export function ChatToolsPopover() {
  const [tools, setTools] = useState<ChatTools | null>(null);
  useEffect(() => {
    let live = true;
    chatService.tools().then(t => live && setTools(t)).catch(() => live && setTools(null));
    return () => {
      live = false;
    };
  }, []);
  if (!tools) return null;
  const popover = (
    <InfoPopover
      id="chat-tools"
      kind="Tools"
      title="What the chat can look up"
      source="read-only, this capture only"
      docs="features/capture-chat"
      docsAnchor="the-tools"
      className="chat-tools-popover"
      width={340}
    >
      <ul className="chat-tools-list">
        {tools.tools.map(t => (
          <li key={t.name}>
            <b>{t.label}</b> <span className="text-muted">· {t.summary}</span>
            <div className="text-muted chat-tools-example">“{t.example}”</div>
          </li>
        ))}
      </ul>
      <p className="text-muted mb-0 mt-2">{toolCallingNote(tools.toolCalling)}</p>
    </InfoPopover>
  );
  return (
    <EscapableOverlayTrigger trigger="click" placement="bottom-end" overlay={popover}>
      <Button type="button" variant="outline-primary" size="sm" className="chat-tools-button">
        <i className="bi bi-tools me-1" aria-hidden="true" />
        Tools · {tools.tools.length}
      </Button>
    </EscapableOverlayTrigger>
  );
}
