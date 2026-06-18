import { Spinner } from '@components/common/Spinner/Spinner';
import { useState, useEffect, useRef } from 'react';
import { useOutletContext } from 'react-router-dom';
import { Badge, Button, Card, Form, Modal } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import type { AnalysisData, Packet } from '@/types';
import { apiClient } from '@/services/api/client';
import { filterService } from '@/features/filter/services/filterService';
import { Pagination } from '@components/common/Pagination';

interface AnalysisOutletContext {
  data: AnalysisData;
  fileId: string;
}

export const FilterGeneratorPage = () => {
  const { fileId } = useOutletContext<AnalysisOutletContext>();
  const [query, setQuery] = useState('');
  const [generatedFilter, setGeneratedFilter] = useState('');
  const [editableFilter, setEditableFilter] = useState('');
  const [explanation, setExplanation] = useState('');
  const [confidence, setConfidence] = useState<number | null>(null);
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [packets, setPackets] = useState<Packet[]>([]);
  const [totalMatches, setTotalMatches] = useState<number>(0);
  const [executionTime, setExecutionTime] = useState<number | null>(null);
  const [generating, setGenerating] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null);
  const [showCheatSheet, setShowCheatSheet] = useState(false);
  const [llmTimeoutMs, setLlmTimeoutMs] = useState<number>(300000);

  useEffect(() => {
    apiClient.get<{ llmTimeoutMs?: number }>('/system/limits')
      .then(res => { if (res.data.llmTimeoutMs) setLlmTimeoutMs(res.data.llmTimeoutMs); })
      .catch(() => { /* keep default */ });
  }, []);

  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize] = useState(25);
  const [totalPages, setTotalPages] = useState(0);
  const resultsRef = useRef<HTMLDivElement>(null);

  const validateFilter = (filter: string): { valid: boolean; message?: string } => {
    const trimmed = filter.trim();

    // Check if filter is empty
    if (!trimmed) {
      return {
        valid: false,
        message:
          'The AI generated an empty filter. This usually means the LLM service is not responding correctly or your query was too vague. Try a more specific query like "HTTP traffic" or "DNS queries".',
      };
    }

    // Check for common invalid patterns
    if (trimmed.includes('undefined') || trimmed.includes('null')) {
      return {
        valid: false,
        message:
          'The AI generated an incomplete filter. The LLM service may not be configured properly.',
      };
    }

    // Check minimum length
    if (trimmed.length < 2) {
      return {
        valid: false,
        message: 'The generated filter is too short to be valid. Try rephrasing your query.',
      };
    }

    return { valid: true };
  };

  const handleGenerateFilter = async () => {
    if (!query.trim()) {
      setError('Please enter a query');
      return;
    }

    try {
      setGenerating(true);
      setError(null);
      const result = await filterService.generateFilter(fileId, query, llmTimeoutMs);

      // Validate the generated filter
      const validation = validateFilter(result.filter);
      if (!validation.valid) {
        setError(`Invalid Filter Generated: ${validation.message}`);
        setGeneratedFilter('');
        setEditableFilter('');
        return;
      }

      setGeneratedFilter(result.filter);
      setEditableFilter(result.filter);
      setExplanation(result.explanation);
      setConfidence(result.confidence);
      setSuggestions(result.suggestions || []);
      // Clear previous packet results when generating new filter
      setPackets([]);
      setTotalMatches(0);
      setExecutionTime(null);
    } catch (err) {
      const status = (err as { response?: { status?: number } })?.response?.status;
      const data = (err as { response?: { data?: Record<string, unknown> } })?.response?.data ?? {};
      const errorMsg = err instanceof Error ? err.message : String(err);
      const isClientTimeout = (err as { code?: string })?.code === 'ECONNABORTED';
      if (data.errorCode === 'LLM_UNREACHABLE' || status === 502 || status === 503) {
        setError('The LLM server is not responding. Make sure the LLM service is running and reachable, then try again.');
      } else if (data.errorCode === 'LLM_TIMEOUT' || isClientTimeout) {
        const totalSeconds = Math.round(llmTimeoutMs / 1000);
        const timeoutLabel = totalSeconds < 60
          ? `${totalSeconds} second${totalSeconds !== 1 ? 's' : ''}`
          : `${Math.round(totalSeconds / 60)} minute${Math.round(totalSeconds / 60) !== 1 ? 's' : ''}`;
        setError(`Filter generation timed out after ${timeoutLabel}. The LLM is responding but took too long — try again or simplify your query.`);
      } else {
        setError(`Error: ${errorMsg || 'Failed to generate filter'}`);
      }
    } finally {
      setGenerating(false);
    }
  };

  const handleExecuteFilter = async (page: number = currentPage) => {
    if (!editableFilter.trim()) {
      setError('Please generate or enter a filter first');
      return;
    }

    try {
      setExecuting(true);
      setError(null);
      const result = await filterService.executeFilter(fileId, editableFilter, page, pageSize);
      setPackets(result.packets);
      setTotalMatches(result.totalMatches);
      setExecutionTime(result.executionTime);
      setTotalPages(result.totalPages || 0);
      setCurrentPage(page);
    } catch (err) {
      // Provide specific error message based on the error type
      const errorMsg = err instanceof Error ? err.message : String(err);

      if (
        errorMsg.includes('syntax error') ||
        errorMsg.includes('BPF') ||
        errorMsg.includes('parse filter')
      ) {
        setError(
          `Invalid BPF Syntax: The filter "${editableFilter}" is not valid BPF syntax. Common valid filters: "tcp port 80", "udp port 53", "host 192.168.1.1", "icmp". Check the BPF Cheat Sheet for help.`
        );
      } else if (errorMsg.includes('500')) {
        setError(
          'Server Error: The backend encountered an error while executing the filter. This might be due to invalid syntax or a server issue.'
        );
      } else if (errorMsg.includes('404')) {
        setError('File Not Found: The PCAP file could not be found. It may have been deleted.');
      } else {
        setError(`Execution Failed: ${errorMsg || 'Unknown error occurred'}`);
      }
    } finally {
      setExecuting(false);
      setTimeout(() => resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 50);
    }
  };

  const handlePageChange = (page: number) => {
    handleExecuteFilter(page);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && e.ctrlKey) {
      e.preventDefault();
      handleGenerateFilter();
    }
  };

  const formatTimestamp = (timestamp: number) => {
    return new Date(timestamp).toLocaleString();
  };

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  return (
    <div className="filter-generator-page">
      {/* Header */}
      <div className="row mb-4">
        <div className="col-12">
          <h4>Filter Generator</h4>
          <p className="text-muted mb-0">
            Generate pcap filters using natural language and view matching packets
          </p>
        </div>
      </div>

      {/* Natural Language Input */}
      <div className="row mb-4">
        <div className="col-12">
          <Card>
            <Card.Body>
              <h5 className="card-title mb-3">
                <i className="bi bi-chat-dots me-2"></i>
                Ask in Natural Language
              </h5>
              <div className="mb-3">
                <Form.Label htmlFor="query">
                  Describe what you want to filter
                </Form.Label>
                <Form.Control
                  as="textarea"
                  id="query"
                  rows={3}
                  placeholder="Examples:&#10;- Show me all HTTP traffic&#10;- Find DNS queries&#10;- Traffic from 192.168.1.1&#10;- SSH connections"
                  value={query}
                  onChange={e => setQuery(e.target.value)}
                  onKeyDown={handleKeyDown}
                  disabled={generating}
                />
                <small className="text-muted">Press Ctrl+Enter to generate filter</small>
              </div>
              <Button
                variant="primary"
                onClick={handleGenerateFilter}
                disabled={generating || !query.trim()}
              >
                {generating ? (
                  <>
                    <Spinner animation="border" size="sm" className="me-2" />
                    Generating...
                  </>
                ) : (
                  <>
                    <i className="bi bi-magic me-2"></i>
                    Generate Filter
                  </>
                )}
              </Button>
            </Card.Body>
          </Card>
        </div>
      </div>

      {/* Generated Filter Display */}
      {generatedFilter && (
        <div className="row mb-4">
          <div className="col-12">
            <Card>
              <Card.Body>
                <h5 className="card-title mb-3">
                  <i className="bi bi-funnel me-2"></i>
                  Generated Filter
                  {confidence !== null && (
                    <Badge
                      bg={confidence > 0.8 ? 'success' : confidence > 0.6 ? 'warning' : 'secondary'}
                      className="ms-2"
                    >
                      {(confidence * 100).toFixed(0)}% confidence
                    </Badge>
                  )}
                </h5>

                {/* Explanation */}
                {explanation && (
                  <Alert variant="info" className="mb-3">
                    <i className="bi bi-info-circle me-2"></i>
                    {explanation}
                  </Alert>
                )}

                {/* Editable Filter */}
                <div className="mb-3">
                  <Form.Label htmlFor="filter">
                    Filter Expression (editable)
                  </Form.Label>
                  <Form.Control
                    type="text"
                    id="filter"
                    className="font-monospace"
                    value={editableFilter}
                    onChange={e => setEditableFilter(e.target.value)}
                    disabled={executing}
                  />
                </div>

                {/* Suggestions */}
                {suggestions.length > 0 && (
                  <div className="mb-3">
                    <Form.Label>Suggestions:</Form.Label>
                    <ul className="list-unstyled mb-0">
                      {suggestions.map((suggestion, index) => (
                        <li key={index} className="text-muted small">
                          <i className="bi bi-lightbulb me-2"></i>
                          {suggestion}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Action Buttons */}
                <div className="d-flex gap-2">
                  <Button
                    variant="success"
                    onClick={() => handleExecuteFilter(1)}
                    disabled={executing || !editableFilter.trim()}
                  >
                    {executing ? (
                      <>
                        <Spinner animation="border" size="sm" className="me-2" />
                        Executing...
                      </>
                    ) : (
                      <>
                        <i className="bi bi-play-fill me-2"></i>
                        Execute Filter
                      </>
                    )}
                  </Button>
                  <Button variant="outline-info" onClick={() => setShowCheatSheet(true)}>
                    <i className="bi bi-file-earmark-text me-2"></i>
                    BPF Cheat Sheet
                  </Button>
                </div>
              </Card.Body>
            </Card>
          </div>
        </div>
      )}

      {/* Results anchor – scrolled into view after execution */}
      <div ref={resultsRef} />

      {/* Error Display */}
      {error && (
        <div className="row mb-4">
          <div className="col-12">
            <Alert variant="danger" dismissible onClose={() => setError(null)}>
              <i className="bi bi-exclamation-triangle me-2"></i>
              {error}
            </Alert>
          </div>
        </div>
      )}

      {/* No Results Message */}
      {!error && executionTime !== null && packets.length === 0 && (
        <div className="row mb-4">
          <div className="col-12">
            <Alert variant="info">
              <h5 className="alert-heading">
                <i className="bi bi-info-circle me-2"></i>
                No Matching Packets Found
              </h5>
              <p className="mb-2">
                The filter{' '}
                <code className="tp-code-inline px-2 py-1 rounded">{editableFilter}</code> is valid
                but didn't match any packets in this PCAP file.
              </p>
              <hr />
              <p className="mb-0">
                <strong>Suggestions:</strong>
              </p>
              <ul className="mb-0">
                <li>Try a broader filter (e.g., just "tcp" or "udp")</li>
                <li>Check if the PCAP file contains the type of traffic you're looking for</li>
                <li>
                  Modify the port numbers, IP addresses, or protocol if they don't match the capture
                </li>
                <li>Generate a new filter with a different query</li>
              </ul>
              {executionTime !== null && (
                <div className="mt-2">
                  <small className="text-muted">Execution time: {executionTime}ms</small>
                </div>
              )}
            </Alert>
          </div>
        </div>
      )}

      {/* Results */}
      {packets.length > 0 && (
        <div className="row mb-4">
          <div className="col-12">
            <Card>
              <Card.Body>
                <div className="d-flex justify-content-between align-items-center mb-3">
                  <h5 className="card-title mb-0">
                    <i className="bi bi-list-check me-2"></i>
                    Matching Packets
                  </h5>
                  <div>
                    <Badge bg="primary" className="me-2">{totalMatches} matches</Badge>
                    {executionTime !== null && (
                      <Badge bg="secondary">{executionTime}ms</Badge>
                    )}
                  </div>
                </div>

                {/* Packets Table */}
                <div className="table-responsive">
                  <table className="table table-hover table-sm">
                    <thead>
                      <tr>
                        <th style={{ width: '180px' }}>Timestamp</th>
                        <th>Source</th>
                        <th>Destination</th>
                        <th>Protocol</th>
                        <th>Size</th>
                        <th>Flags</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {packets.map(packet => (
                        <tr
                          key={packet.id}
                          className={selectedPacket?.id === packet.id ? 'table-active' : ''}
                        >
                          <td className="font-monospace small">
                            {formatTimestamp(packet.timestamp)}
                          </td>
                          <td className="font-monospace small">
                            {packet.source.ip}:{packet.source.port}
                          </td>
                          <td className="font-monospace small">
                            {packet.destination.ip}:{packet.destination.port}
                          </td>
                          <td>
                            <Badge bg="info">{packet.protocol.name}</Badge>
                          </td>
                          <td>{formatBytes(packet.size)}</td>
                          <td>
                            {packet.flags?.map((flag, idx) => (
                              <Badge key={idx} bg="secondary" className="me-1">
                                {flag}
                              </Badge>
                            ))}
                          </td>
                          <td>
                            <Button
                              size="sm"
                              variant="outline-primary"
                              onClick={() => setSelectedPacket(packet)}
                            >
                              Details
                            </Button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {/* Pagination */}
                {totalPages > 1 && (
                  <div className="mt-3">
                    <Pagination
                      currentPage={currentPage}
                      totalPages={totalPages}
                      onPageChange={handlePageChange}
                      pageSize={pageSize}
                      totalItems={totalMatches}
                    />
                  </div>
                )}
              </Card.Body>
            </Card>
          </div>
        </div>
      )}

      {/* Packet Details Modal */}
      <Modal show={!!selectedPacket} onHide={() => setSelectedPacket(null)} size="lg" centered>
        <Modal.Header closeButton>
          <Modal.Title>Packet Details</Modal.Title>
        </Modal.Header>
        {selectedPacket && (
          <Modal.Body>
            <div className="row mb-3">
              <div className="col-md-6">
                <strong>Timestamp:</strong>
                <p className="font-monospace">{formatTimestamp(selectedPacket.timestamp)}</p>
              </div>
              <div className="col-md-6">
                <strong>Protocol:</strong>
                <p>
                  {selectedPacket.protocol.name} ({selectedPacket.protocol.layer})
                </p>
              </div>
            </div>
            <div className="row mb-3">
              <div className="col-md-6">
                <strong>Source:</strong>
                <p className="font-monospace">
                  {selectedPacket.source.ip}:{selectedPacket.source.port}
                  {selectedPacket.source.hostname && (
                    <>
                      <br />
                      <small className="text-muted">{selectedPacket.source.hostname}</small>
                    </>
                  )}
                </p>
              </div>
              <div className="col-md-6">
                <strong>Destination:</strong>
                <p className="font-monospace">
                  {selectedPacket.destination.ip}:{selectedPacket.destination.port}
                  {selectedPacket.destination.hostname && (
                    <>
                      <br />
                      <small className="text-muted">
                        {selectedPacket.destination.hostname}
                      </small>
                    </>
                  )}
                </p>
              </div>
            </div>
            <div className="row mb-3">
              <div className="col-md-6">
                <strong>Size:</strong>
                <p>{formatBytes(selectedPacket.size)}</p>
              </div>
              <div className="col-md-6">
                <strong>Flags:</strong>
                <p>
                  {selectedPacket.flags?.map((flag, idx) => (
                    <Badge key={idx} bg="secondary" className="me-1">
                      {flag}
                    </Badge>
                  )) || 'None'}
                </p>
              </div>
            </div>
            <div className="row">
              <div className="col-12">
                <strong>Payload:</strong>
                <pre
                  className="tp-payload-pre p-3 rounded mt-2 font-monospace small"
                  style={{ maxHeight: '300px', overflow: 'auto' }}
                >
                  {selectedPacket.payload || 'No payload data'}
                </pre>
              </div>
            </div>
          </Modal.Body>
        )}
        <Modal.Footer>
          <Button
            type="button"
            variant="secondary"
            onClick={() => setSelectedPacket(null)}
          >
            Close
          </Button>
        </Modal.Footer>
      </Modal>

      {/* Cheat Sheet Modal */}
      <Modal show={showCheatSheet} onHide={() => setShowCheatSheet(false)} size="xl" centered>
        <Modal.Header closeButton>
          <Modal.Title>
            <i className="bi bi-file-earmark-text me-2"></i>
            BPF Filter Cheat Sheet
          </Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <div className="text-center">
            <img
              src="/assets/Wireshark-Cheat-Sheet.jpg"
              alt="Wireshark BPF Filter Cheat Sheet"
              className="img-fluid"
              style={{ maxHeight: '80vh', objectFit: 'contain' }}
            />
          </div>
        </Modal.Body>
        <Modal.Footer>
          <a
            href="/assets/Wireshark-Cheat-Sheet.jpg"
            download="Wireshark-Cheat-Sheet.jpg"
            className="btn btn-outline-primary"
          >
            <i className="bi bi-download me-2"></i>
            Download
          </a>
          <Button
            type="button"
            variant="secondary"
            onClick={() => setShowCheatSheet(false)}
          >
            Close
          </Button>
        </Modal.Footer>
      </Modal>
    </div>
  );
};
