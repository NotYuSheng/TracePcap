import type { Conversation } from '@/types';
import { formatBytes } from '@/utils/formatters';
import { getAppColor, getTextColor } from '@/utils/appColors';
import './ConversationListCompact.css';

function endpoint(ip: string, port?: number) {
  return (
    <>
      {ip}
      {port ? <span className="ccl-port">:{port}</span> : null}
    </>
  );
}

/**
 * Conversations B: one compact row per conversation, endpoints over app, flag, size and time.
 * The selected row is marked; the page shows its detail beside the list.
 */
export function ConversationListCompact({
  conversations,
  selectedId,
  onSelect,
}: {
  conversations: Conversation[];
  selectedId: string | null;
  onSelect: (c: Conversation, index: number) => void;
}) {
  return (
    <ul className="ccl" aria-label="Conversations">
      {conversations.map((c, i) => {
        const app = c.appName ?? c.protocol?.name ?? '—';
        const color = getAppColor(app);
        const flagged = c.flowRisks.length + c.customSignatures.length + c.suricataAlerts.length > 0;
        const on = c.id === selectedId;
        return (
          <li key={c.id}>
            <button
              type="button"
              className={`ccl-row${on ? ' active' : ''}`}
              aria-current={on ? 'true' : undefined}
              data-conversation-id={c.id}
              onClick={() => onSelect(c, i)}
            >
              <span className="ccl-ends">
                {endpoint(c.endpoints[0].ip, c.endpoints[0].port)} → {endpoint(c.endpoints[1].ip, c.endpoints[1].port)}
              </span>
              <span className="ccl-meta">
                <span className="ccl-app" style={{ backgroundColor: color, color: getTextColor(color) }}>
                  {app}
                </span>
                {flagged && (
                  <span className="ccl-flag">
                    <i className="bi bi-flag-fill" aria-hidden="true" /> flagged
                  </span>
                )}
                <span className="ccl-size">
                  {formatBytes(c.totalBytes)} · {new Date(c.startTime).toLocaleTimeString('en-GB')}
                </span>
              </span>
            </button>
          </li>
        );
      })}
    </ul>
  );
}
