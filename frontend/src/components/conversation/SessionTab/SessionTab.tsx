import { Spinner } from '@components/common/Spinner/Spinner';
import { useState } from 'react';
import { Alert, Badge, Button, ButtonGroup, Card } from '@govtechsg/sgds-react';
import { conversationService } from '@/features/conversation/services/conversationService';
import type {
  SessionData,
  SessionChunk,
  HttpExchange,
  StunMessage,
  MediaInfo,
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
          <Badge bg="light" text="dark" style={{ fontSize: '0.65rem' }}>
            {message.bodyEncoding ?? 'compressed'} decoded
            {message.bodyCompressedLength > 0 &&
              ` (${formatBytes(message.bodyCompressedLength)} → ${formatBytes(message.bodyLength)})`}
          </Badge>
        )}
      </div>

      <div style={{ padding: '0.5rem 0.75rem' }}>
        {headerEntries.length > 0 && (
          <div className="mb-2">
            <Button
              variant="link"
              size="sm"
              className="p-0 text-muted"
              onClick={() => setShowHeaders(h => !h)}
              style={{ fontSize: '0.75rem', textDecoration: 'none' }}
            >
              {showHeaders ? '▾' : '▸'} Headers ({headerEntries.length})
            </Button>
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
            <Button
              variant="link"
              size="sm"
              className="p-0 text-muted"
              onClick={() => setShowBody(b => !b)}
              style={{ fontSize: '0.75rem', textDecoration: 'none' }}
            >
              {showBody ? '▾' : '▸'} Body ({formatBytes(message.bodyLength)}
              {message.bodyTruncated ? ', truncated' : ''})
            </Button>
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
      <Button
        variant="link"
        size="sm"
        className="p-0 text-muted mb-2"
        onClick={() => setCollapsed(c => !c)}
        style={{ fontSize: '0.8rem', textDecoration: 'none' }}
      >
        {collapsed ? '▸' : '▾'} Exchange #{index + 1}
        {exchange.request && (
          <code className="ms-2" style={{ fontSize: '0.78rem' }}>
            {exchange.request.firstLine.split(' ').slice(0, 2).join(' ')}
          </code>
        )}
      </Button>
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

// ─── STUN message view ────────────────────────────────────────────────────────

function StunMessageBlock({ msg, index }: { msg: StunMessage; index: number }) {
  const [collapsed, setCollapsed] = useState(false);
  const isClient = msg.direction === 'CLIENT';
  const color = isClient ? CLIENT_COLOR : SERVER_COLOR;
  const attrEntries = Object.entries(msg.attributes ?? {});

  return (
    <div className="mb-2">
      <Button
        variant="link"
        size="sm"
        className="p-0 text-muted mb-1"
        onClick={() => setCollapsed(c => !c)}
        style={{ fontSize: '0.8rem', textDecoration: 'none' }}
      >
        {collapsed ? '▸' : '▾'} #{index + 1}
        <span
          className="badge ms-2"
          style={{ backgroundColor: color, color: '#fff', fontSize: '0.65rem' }}
        >
          {msg.direction}
        </span>
        <code className="ms-2" style={{ fontSize: '0.78rem' }}>
          {msg.messageType}
        </code>
      </Button>
      {!collapsed && (
        <div
          style={{
            border: `1px solid ${color}`,
            borderRadius: '6px',
            overflow: 'hidden',
            marginLeft: '0.5rem',
          }}
        >
          <div
            style={{
              backgroundColor: color,
              color: '#fff',
              padding: '0.35rem 0.75rem',
              fontSize: '0.8rem',
              display: 'flex',
              gap: '1rem',
              flexWrap: 'wrap',
            }}
          >
            <span className="fw-semibold">{msg.messageType}</span>
            <span style={{ opacity: 0.85, fontFamily: 'monospace', fontSize: '0.72rem' }}>
              tx: {msg.transactionId}
            </span>
          </div>
          {attrEntries.length > 0 && (
            <table
              className="table table-sm table-borderless mb-0"
              style={{ fontSize: '0.75rem' }}
            >
              <tbody>
                {attrEntries.map(([k, v]) => (
                  <tr key={k}>
                    <td
                      className="fw-semibold text-muted pe-2"
                      style={{ whiteSpace: 'nowrap', width: '1%', paddingLeft: '0.75rem' }}
                    >
                      {k}
                    </td>
                    <td style={{ wordBreak: 'break-all', paddingRight: '0.75rem' }}>{v}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {attrEntries.length === 0 && (
            <div style={{ padding: '0.4rem 0.75rem' }}>
              <small className="text-muted">No attributes</small>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function StunMessagesView({ messages }: { messages: StunMessage[] }) {
  if (messages.length === 0) {
    return <p className="text-muted text-center py-3">No STUN messages decoded.</p>;
  }
  return (
    <div>
      {messages.map((msg, i) => (
        <StunMessageBlock key={i} msg={msg} index={i} />
      ))}
    </div>
  );
}

// ─── Media info panel ─────────────────────────────────────────────────────────

function MediaInfoPanel({ info }: { info: MediaInfo }) {
  const rows: Array<[string, string]> = [];
  if (info.containerFormat) rows.push(['Container', info.containerFormat]);
  if (info.codec) rows.push(['Codec', info.codec]);
  if (info.width != null && info.height != null) rows.push(['Dimensions', `${info.width} × ${info.height}`]);
  if (info.sampleRate != null) rows.push(['Sample rate', `${info.sampleRate.toLocaleString()} Hz`]);
  if (info.streamCount != null) rows.push(['SSRC streams', String(info.streamCount)]);

  return (
    <Card className="mb-3" style={{ fontSize: '0.85rem' }}>
      <Card.Body className="p-3">
        <div className="fw-semibold mb-2">
          {info.mediaType} stream detected — {info.containerFormat}
        </div>
        {rows.length > 0 && (
          <table className="table table-sm table-borderless mb-0" style={{ fontSize: '0.8rem' }}>
            <tbody>
              {rows.map(([k, v]) => (
                <tr key={k}>
                  <td className="text-muted pe-3" style={{ whiteSpace: 'nowrap', width: '1%' }}>{k}</td>
                  <td>{v}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card.Body>
    </Card>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export function SessionTab({ conversationId }: SessionTabProps) {
  const [session, setSession] = useState<SessionData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeView, setActiveView] = useState<'parsed' | 'stun' | 'raw'>('parsed');

  const handleReconstruct = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await conversationService.reconstructSession(conversationId);
      setSession(data);
      if (data.httpExchanges && data.httpExchanges.length > 0) {
        setActiveView('parsed');
      } else if (data.stunMessages && data.stunMessages.length > 0) {
        setActiveView('stun');
      } else {
        setActiveView('raw');
      }
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
        <Button variant="primary" onClick={handleReconstruct}>
          Reconstruct Session
        </Button>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="text-center py-5">
        <Spinner animation="border" className="text-primary" role="status" />
        <p className="text-muted mt-3">Reconstructing session…</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-center py-4">
        <p className="text-danger mb-3">{error}</p>
        <Button size="sm" variant="outline-primary" onClick={handleReconstruct}>
          Retry
        </Button>
      </div>
    );
  }

  if (!session) return null;

  if (session.errorMessage) {
    return (
      <div className="py-4">
        <Alert variant="warning" className="mb-3">{session.errorMessage}</Alert>
        <Button size="sm" variant="outline-primary" onClick={handleReconstruct}>
          Retry
        </Button>
      </div>
    );
  }

  // ── Session display ────────────────────────────────────────────────────────

  const hasHttp = session.httpExchanges && session.httpExchanges.length > 0;
  const hasStun = session.stunMessages && session.stunMessages.length > 0;
  const hasMedia = session.mediaInfo != null;
  const isTls = session.detectedProtocol === 'TLS';

  return (
    <div>
      {/* Toolbar */}
      <div className="d-flex align-items-center gap-3 mb-3 flex-wrap">
        <div className="d-flex align-items-center gap-2">
          {session.detectedProtocol && (
            <Badge bg="info" text="dark">{session.detectedProtocol}</Badge>
          )}
          {hasMedia && (
            <Badge bg="primary">
              {session.mediaInfo!.containerFormat}
            </Badge>
          )}
          <small className="text-muted">
            ↑ {formatBytes(session.totalClientBytes)} client &nbsp;·&nbsp; ↓{' '}
            {formatBytes(session.totalServerBytes)} server
          </small>
          {session.truncated && (
            <Badge bg="warning" text="dark" title="Session truncated at 1 MB">
              Truncated
            </Badge>
          )}
        </div>

        {(hasHttp || hasStun) && (
          <ButtonGroup size="sm">
            {hasHttp && (
              <Button
                variant={activeView === 'parsed' ? 'secondary' : 'outline-secondary'}
                onClick={() => setActiveView('parsed')}
              >
                Parsed HTTP
              </Button>
            )}
            {hasStun && (
              <Button
                variant={activeView === 'stun' ? 'secondary' : 'outline-secondary'}
                onClick={() => setActiveView('stun')}
              >
                STUN Messages
              </Button>
            )}
            <Button
              variant={activeView === 'raw' ? 'secondary' : 'outline-secondary'}
              onClick={() => setActiveView('raw')}
            >
              Raw Stream
            </Button>
          </ButtonGroup>
        )}

        <Button
          size="sm"
          variant="outline-secondary"
          className="ms-auto"
          onClick={handleReconstruct}
          title="Re-run reconstruction"
        >
          ↺ Refresh
        </Button>
      </div>

      {isTls && (
        <Alert variant="secondary" className="py-2 mb-3" style={{ fontSize: '0.85rem' }}>
          This session uses TLS encryption — payload content cannot be decoded without the private
          key.
        </Alert>
      )}

      {session.truncated && (
        <Alert variant="warning" className="py-2 mb-3" style={{ fontSize: '0.85rem' }}>
          Session exceeded 1 MB — only the first 1 MB of data is shown.
        </Alert>
      )}

      {/* Media metadata panel */}
      {hasMedia && <MediaInfoPanel info={session.mediaInfo!} />}

      {/* Parsed HTTP view */}
      {hasHttp && activeView === 'parsed' && (
        <div>
          {session.httpExchanges!.map((ex, i) => (
            <HttpExchangeBlock key={i} exchange={ex} index={i} />
          ))}
        </div>
      )}

      {/* Decoded STUN messages */}
      {hasStun && activeView === 'stun' && (
        <StunMessagesView messages={session.stunMessages!} />
      )}

      {/* Interleaved raw stream (Wireshark-style) */}
      {activeView === 'raw' && <InterleavedStream chunks={session.chunks} />}
    </div>
  );
}
