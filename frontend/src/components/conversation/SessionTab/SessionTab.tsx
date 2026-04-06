import { useState } from 'react';
import { conversationService } from '@/features/conversation/services/conversationService';
import type {
  SessionData,
  SessionChunk,
  HttpExchange,
} from '@/features/conversation/services/conversationService';
import { formatBytes } from '@/utils/formatters';

interface SessionTabProps {
  conversationId: string;
  protocol: string;
}

// Wireshark colour palette
const CLIENT_COLOR = '#c0392b'; // red  — sent by client
const SERVER_COLOR = '#1a5276'; // blue — sent by server

// ─── Interleaved stream pane (Wireshark-style) ───────────────────────────────

function InterleavedStream({ chunks }: { chunks: SessionChunk[] }) {
  if (chunks.length === 0) {
    return <p className="text-muted text-center py-3">No payload data in this stream.</p>;
  }

  return (
    <div>
      {/* Legend */}
      <div className="d-flex gap-3 mb-2" style={{ fontSize: '0.75rem' }}>
        <span>
          <span
            style={{
              display: 'inline-block',
              width: 10,
              height: 10,
              borderRadius: 2,
              backgroundColor: CLIENT_COLOR,
              marginRight: 4,
            }}
          />
          Client
        </span>
        <span>
          <span
            style={{
              display: 'inline-block',
              width: 10,
              height: 10,
              borderRadius: 2,
              backgroundColor: SERVER_COLOR,
              marginRight: 4,
            }}
          />
          Server
        </span>
      </div>

      {/* Single scrollable pane */}
      <div
        className="tp-stream-pane"
        style={{
          maxHeight: '550px',
          overflowY: 'auto',
          border: '1px solid #dee2e6',
          borderRadius: '4px',
          backgroundColor: '#fdfdfd',
        }}
      >
        <pre
          style={{
            margin: 0,
            padding: '0.5rem',
            fontSize: '0.75rem',
            fontFamily: 'monospace',
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-all',
            lineHeight: 1.5,
          }}
        >
          {chunks.map((chunk, i) => (
            <ChunkSpan key={i} chunk={chunk} />
          ))}
        </pre>
      </div>
    </div>
  );
}

function ChunkSpan({ chunk }: { chunk: SessionChunk }) {
  const isClient = chunk.direction === 'CLIENT';
  const color = isClient ? CLIENT_COLOR : SERVER_COLOR;

  return <span style={{ color }}>{chunk.text}</span>;
}

// ─── HTTP exchange ────────────────────────────────────────────────────────────

function HttpMessageBlock({
  message,
  label,
  color,
}: {
  message: NonNullable<HttpExchange['request']>;
  label: string;
  color: string;
}) {
  const [showHeaders, setShowHeaders] = useState(false);
  const [showBody, setShowBody] = useState(true);

  const headerEntries = Object.entries(message.headers ?? {});

  return (
    <div
      style={{
        border: `1px solid ${color}`,
        borderRadius: '6px',
        marginBottom: '0.5rem',
        overflow: 'hidden',
      }}
    >
      <div
        style={{
          backgroundColor: color,
          color: '#fff',
          padding: '0.4rem 0.75rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
        }}
      >
        <span className="fw-semibold" style={{ fontSize: '0.8rem' }}>
          {label}
        </span>
        <code style={{ fontSize: '0.8rem', color: '#fff', flex: 1 }}>{message.firstLine}</code>
        {message.bodyDecompressed && (
          <span className="badge bg-light text-dark" style={{ fontSize: '0.65rem' }}>
            gzip decoded
          </span>
        )}
      </div>

      <div style={{ padding: '0.5rem 0.75rem' }}>
        {headerEntries.length > 0 && (
          <div className="mb-2">
            <button
              className="btn btn-link btn-sm p-0 text-muted"
              onClick={() => setShowHeaders(h => !h)}
              style={{ fontSize: '0.75rem', textDecoration: 'none' }}
            >
              {showHeaders ? '▾' : '▸'} Headers ({headerEntries.length})
            </button>
            {showHeaders && (
              <table
                className="table table-sm table-borderless mb-0 mt-1"
                style={{ fontSize: '0.75rem' }}
              >
                <tbody>
                  {headerEntries.map(([k, v]) => (
                    <tr key={k}>
                      <td
                        className="fw-semibold text-muted pe-2"
                        style={{ whiteSpace: 'nowrap', width: '1%' }}
                      >
                        {k}:
                      </td>
                      <td style={{ wordBreak: 'break-all' }}>{v}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {message.bodyLength > 0 && (
          <div>
            <button
              className="btn btn-link btn-sm p-0 text-muted"
              onClick={() => setShowBody(b => !b)}
              style={{ fontSize: '0.75rem', textDecoration: 'none' }}
            >
              {showBody ? '▾' : '▸'} Body ({formatBytes(message.bodyLength)}
              {message.bodyTruncated ? ', truncated' : ''})
            </button>
            {showBody && (
              <pre
                className="tp-stream-pane"
                style={{
                  fontSize: '0.72rem',
                  borderRadius: '4px',
                  padding: '0.5rem',
                  maxHeight: '300px',
                  overflowY: 'auto',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all',
                  margin: '0.25rem 0 0',
                }}
              >
                {message.bodyBinary
                  ? `[Binary data — ${formatBytes(message.bodyLength)}]`
                  : (message.body ?? '')}
              </pre>
            )}
          </div>
        )}

        {message.bodyLength === 0 && <small className="text-muted">No body</small>}
      </div>
    </div>
  );
}

function HttpExchangeBlock({ exchange, index }: { exchange: HttpExchange; index: number }) {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div className="mb-3">
      <button
        className="btn btn-link btn-sm p-0 text-muted mb-2"
        onClick={() => setCollapsed(c => !c)}
        style={{ fontSize: '0.8rem', textDecoration: 'none' }}
      >
        {collapsed ? '▸' : '▾'} Exchange #{index + 1}
        {exchange.request && (
          <code className="ms-2" style={{ fontSize: '0.78rem' }}>
            {exchange.request.firstLine.split(' ').slice(0, 2).join(' ')}
          </code>
        )}
      </button>
      {!collapsed && (
        <div style={{ paddingLeft: '0.5rem' }}>
          {exchange.request && (
            <HttpMessageBlock message={exchange.request} label="REQUEST" color={CLIENT_COLOR} />
          )}
          {exchange.response && (
            <HttpMessageBlock message={exchange.response} label="RESPONSE" color={SERVER_COLOR} />
          )}
        </div>
      )}
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export function SessionTab({ conversationId }: SessionTabProps) {
  const [session, setSession] = useState<SessionData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeView, setActiveView] = useState<'parsed' | 'raw'>('parsed');

  const handleReconstruct = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await conversationService.reconstructSession(conversationId);
      setSession(data);
      setActiveView(data.httpExchanges && data.httpExchanges.length > 0 ? 'parsed' : 'raw');
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Request failed');
    } finally {
      setLoading(false);
    }
  };

  // ── Pre-flight states ──────────────────────────────────────────────────────

  if (!session && !loading && !error) {
    return (
      <div className="text-center py-5">
        <p className="text-muted mb-3">
          Reconstruct the full application-layer byte stream for this conversation.
        </p>
        <button className="btn btn-primary" onClick={handleReconstruct}>
          Reconstruct Session
        </button>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="text-center py-5">
        <div className="spinner-border text-primary" role="status" />
        <p className="text-muted mt-3">Reconstructing session…</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-center py-4">
        <p className="text-danger mb-3">{error}</p>
        <button className="btn btn-outline-primary btn-sm" onClick={handleReconstruct}>
          Retry
        </button>
      </div>
    );
  }

  if (!session) return null;

  if (session.errorMessage) {
    return (
      <div className="py-4">
        <div className="alert alert-warning mb-3">{session.errorMessage}</div>
        <button className="btn btn-outline-primary btn-sm" onClick={handleReconstruct}>
          Retry
        </button>
      </div>
    );
  }

  // ── Session display ────────────────────────────────────────────────────────

  const hasHttp = session.httpExchanges && session.httpExchanges.length > 0;
  const isTls = session.detectedProtocol === 'TLS';

  return (
    <div>
      {/* Toolbar */}
      <div className="d-flex align-items-center gap-3 mb-3 flex-wrap">
        <div className="d-flex align-items-center gap-2">
          {session.detectedProtocol && (
            <span className="badge bg-info text-dark">{session.detectedProtocol}</span>
          )}
          <small className="text-muted">
            ↑ {formatBytes(session.totalClientBytes)} client &nbsp;·&nbsp; ↓{' '}
            {formatBytes(session.totalServerBytes)} server
          </small>
          {session.truncated && (
            <span className="badge bg-warning text-dark" title="Session truncated at 1 MB">
              Truncated
            </span>
          )}
        </div>

        {hasHttp && (
          <div className="btn-group btn-group-sm">
            <button
              className={`btn btn-outline-secondary${activeView === 'parsed' ? ' active' : ''}`}
              onClick={() => setActiveView('parsed')}
            >
              Parsed HTTP
            </button>
            <button
              className={`btn btn-outline-secondary${activeView === 'raw' ? ' active' : ''}`}
              onClick={() => setActiveView('raw')}
            >
              Raw Stream
            </button>
          </div>
        )}

        <button
          className="btn btn-outline-secondary btn-sm ms-auto"
          onClick={handleReconstruct}
          title="Re-run reconstruction"
        >
          ↺ Refresh
        </button>
      </div>

      {isTls && (
        <div className="alert alert-secondary py-2 mb-3" style={{ fontSize: '0.85rem' }}>
          This session uses TLS encryption — payload content cannot be decoded without the private
          key.
        </div>
      )}

      {session.truncated && (
        <div className="alert alert-warning py-2 mb-3" style={{ fontSize: '0.85rem' }}>
          Session exceeded 1 MB — only the first 1 MB of data is shown.
        </div>
      )}

      {/* Parsed HTTP view */}
      {hasHttp && activeView === 'parsed' && (
        <div>
          {session.httpExchanges!.map((ex, i) => (
            <HttpExchangeBlock key={i} exchange={ex} index={i} />
          ))}
        </div>
      )}

      {/* Interleaved raw stream (Wireshark-style) */}
      {(!hasHttp || activeView === 'raw') && <InterleavedStream chunks={session.chunks} />}
    </div>
  );
}
