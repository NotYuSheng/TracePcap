import { useEffect, useState } from 'react';
import { Button, Popover } from '@govtechsg/sgds-react';
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
    <Popover id="chat-tools" className="chat-tools-popover">
      <Popover.Header>Tools the chat can use</Popover.Header>
      <Popover.Body className="small p-0">
        <p className="text-muted px-3 pt-2 mb-1">
          Read-only, and only on this capture. Each answer lists the ones it used.
        </p>
        <ul className="chat-tools-list">
          {tools.tools.map(t => (
            <li key={t.name}>
              <b>{t.label}</b> <span className="text-muted">· {t.summary}</span>
              <div className="text-muted chat-tools-example">“{t.example}”</div>
            </li>
          ))}
        </ul>
        <p className="text-muted px-3 pb-2 mb-0">{toolCallingNote(tools.toolCalling)}</p>
      </Popover.Body>
    </Popover>
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
