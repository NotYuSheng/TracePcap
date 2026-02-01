import { useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import type { AnalysisData, Packet } from '@/types'
import { filterService } from '@/features/filter/services/filterService'
import { Pagination } from '@components/common/Pagination'

interface AnalysisOutletContext {
  data: AnalysisData
  fileId: string
}

export const FilterGeneratorPage = () => {
  const { fileId } = useOutletContext<AnalysisOutletContext>()
  const [query, setQuery] = useState('')
  const [generatedFilter, setGeneratedFilter] = useState('')
  const [editableFilter, setEditableFilter] = useState('')
  const [explanation, setExplanation] = useState('')
  const [confidence, setConfidence] = useState<number | null>(null)
  const [suggestions, setSuggestions] = useState<string[]>([])
  const [packets, setPackets] = useState<Packet[]>([])
  const [totalMatches, setTotalMatches] = useState<number>(0)
  const [executionTime, setExecutionTime] = useState<number | null>(null)
  const [generating, setGenerating] = useState(false)
  const [executing, setExecuting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null)
  const [showCheatSheet, setShowCheatSheet] = useState(false)

  // Pagination state
  const [currentPage, setCurrentPage] = useState(1)
  const [pageSize] = useState(25)
  const [totalPages, setTotalPages] = useState(0)

  const validateFilter = (filter: string): { valid: boolean; message?: string } => {
    const trimmed = filter.trim()

    // Check if filter is empty
    if (!trimmed) {
      return {
        valid: false,
        message: 'The AI generated an empty filter. This usually means the LLM service is not responding correctly or your query was too vague. Try a more specific query like "HTTP traffic" or "DNS queries".'
      }
    }

    // Check for common invalid patterns
    if (trimmed.includes('undefined') || trimmed.includes('null')) {
      return {
        valid: false,
        message: 'The AI generated an incomplete filter. The LLM service may not be configured properly.'
      }
    }

    // Check minimum length
    if (trimmed.length < 2) {
      return {
        valid: false,
        message: 'The generated filter is too short to be valid. Try rephrasing your query.'
      }
    }

    return { valid: true }
  }

  const handleGenerateFilter = async () => {
    if (!query.trim()) {
      setError('Please enter a query')
      return
    }

    try {
      setGenerating(true)
      setError(null)
      const result = await filterService.generateFilter(fileId, query)

      // Validate the generated filter
      const validation = validateFilter(result.filter)
      if (!validation.valid) {
        setError(`❌ Invalid Filter Generated: ${validation.message}`)
        setGeneratedFilter('')
        setEditableFilter('')
        return
      }

      setGeneratedFilter(result.filter)
      setEditableFilter(result.filter)
      setExplanation(result.explanation)
      setConfidence(result.confidence)
      setSuggestions(result.suggestions || [])
      // Clear previous packet results when generating new filter
      setPackets([])
      setTotalMatches(0)
      setExecutionTime(null)
    } catch (err) {
      // Provide helpful error message for common issues
      const errorMsg = err instanceof Error ? err.message : String(err)
      if (errorMsg.includes('500') || errorMsg.includes('LLM') || errorMsg.includes('Failed to generate')) {
        setError('🔴 LLM Service Unavailable: The AI service at http://100.64.0.1:1234 is not responding. Please start LM Studio or another OpenAI-compatible LLM server, then try again.')
      } else if (errorMsg.includes('timeout') || errorMsg.includes('ECONNREFUSED')) {
        setError('🔴 Connection Failed: Cannot reach the LLM service. Make sure it\'s running on http://100.64.0.1:1234')
      } else {
        setError(`❌ Error: ${errorMsg || 'Failed to generate filter'}`)
      }
    } finally {
      setGenerating(false)
    }
  }

  const handleExecuteFilter = async (page: number = currentPage) => {
    if (!editableFilter.trim()) {
      setError('Please generate or enter a filter first')
      return
    }

    try {
      setExecuting(true)
      setError(null)
      const result = await filterService.executeFilter(fileId, editableFilter, page, pageSize)
      setPackets(result.packets)
      setTotalMatches(result.totalMatches)
      setExecutionTime(result.executionTime)
      setTotalPages(result.totalPages || 0)
      setCurrentPage(page)
    } catch (err) {
      // Provide specific error message based on the error type
      const errorMsg = err instanceof Error ? err.message : String(err)

      if (errorMsg.includes('syntax error') || errorMsg.includes('BPF') || errorMsg.includes('parse filter')) {
        setError(`❌ Invalid BPF Syntax: The filter "${editableFilter}" is not valid BPF syntax. Common valid filters: "tcp port 80", "udp port 53", "host 192.168.1.1", "icmp". Check the BPF Cheat Sheet for help.`)
      } else if (errorMsg.includes('500')) {
        setError('🔴 Server Error: The backend encountered an error while executing the filter. This might be due to invalid syntax or a server issue.')
      } else if (errorMsg.includes('404')) {
        setError('❌ File Not Found: The PCAP file could not be found. It may have been deleted.')
      } else {
        setError(`❌ Execution Failed: ${errorMsg || 'Unknown error occurred'}`)
      }
    } finally {
      setExecuting(false)
    }
  }

  const handlePageChange = (page: number) => {
    handleExecuteFilter(page)
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && e.ctrlKey) {
      e.preventDefault()
      handleGenerateFilter()
    }
  }

  const formatTimestamp = (timestamp: number) => {
    return new Date(timestamp).toLocaleString()
  }

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
  }

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
          <div className="card">
            <div className="card-body">
              <h5 className="card-title mb-3">
                <i className="bi bi-chat-dots me-2"></i>
                Ask in Natural Language
              </h5>
              <div className="mb-3">
                <label htmlFor="query" className="form-label">
                  Describe what you want to filter
                </label>
                <textarea
                  id="query"
                  className="form-control"
                  rows={3}
                  placeholder="Examples:&#10;- Show me all HTTP traffic&#10;- Find DNS queries&#10;- Traffic from 192.168.1.1&#10;- SSH connections"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  onKeyDown={handleKeyDown}
                  disabled={generating}
                />
                <small className="text-muted">Press Ctrl+Enter to generate filter</small>
              </div>
              <button
                className="btn btn-primary"
                onClick={handleGenerateFilter}
                disabled={generating || !query.trim()}
              >
                {generating ? (
                  <>
                    <span className="spinner-border spinner-border-sm me-2" />
                    Generating...
                  </>
                ) : (
                  <>
                    <i className="bi bi-magic me-2"></i>
                    Generate Filter
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Generated Filter Display */}
      {generatedFilter && (
        <div className="row mb-4">
          <div className="col-12">
            <div className="card">
              <div className="card-body">
                <h5 className="card-title mb-3">
                  <i className="bi bi-funnel me-2"></i>
                  Generated Filter
                  {confidence !== null && (
                    <span className={`badge ms-2 ${confidence > 0.8 ? 'bg-success' : confidence > 0.6 ? 'bg-warning' : 'bg-secondary'}`}>
                      {(confidence * 100).toFixed(0)}% confidence
                    </span>
                  )}
                </h5>

                {/* Explanation */}
                {explanation && (
                  <div className="alert alert-info mb-3">
                    <i className="bi bi-info-circle me-2"></i>
                    {explanation}
                  </div>
                )}

                {/* Editable Filter */}
                <div className="mb-3">
                  <label htmlFor="filter" className="form-label">
                    Filter Expression (editable)
                  </label>
                  <input
                    type="text"
                    id="filter"
                    className="form-control font-monospace"
                    value={editableFilter}
                    onChange={(e) => setEditableFilter(e.target.value)}
                    disabled={executing}
                  />
                </div>

                {/* Suggestions */}
                {suggestions.length > 0 && (
                  <div className="mb-3">
                    <label className="form-label">Suggestions:</label>
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
                  <button
                    className="btn btn-success"
                    onClick={() => handleExecuteFilter(1)}
                    disabled={executing || !editableFilter.trim()}
                  >
                    {executing ? (
                      <>
                        <span className="spinner-border spinner-border-sm me-2" />
                        Executing...
                      </>
                    ) : (
                      <>
                        <i className="bi bi-play-fill me-2"></i>
                        Execute Filter
                      </>
                    )}
                  </button>
                  <button
                    className="btn btn-outline-info"
                    onClick={() => setShowCheatSheet(true)}
                  >
                    <i className="bi bi-file-earmark-text me-2"></i>
                    BPF Cheat Sheet
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Error Display */}
      {error && (
        <div className="row mb-4">
          <div className="col-12">
            <div className="alert alert-danger alert-dismissible fade show" role="alert">
              <i className="bi bi-exclamation-triangle me-2"></i>
              {error}
              <button
                type="button"
                className="btn-close"
                onClick={() => setError(null)}
                aria-label="Close"
              ></button>
            </div>
          </div>
        </div>
      )}

      {/* No Results Message */}
      {!error && executionTime !== null && packets.length === 0 && (
        <div className="row mb-4">
          <div className="col-12">
            <div className="alert alert-info" role="alert">
              <h5 className="alert-heading">
                <i className="bi bi-info-circle me-2"></i>
                No Matching Packets Found
              </h5>
              <p className="mb-2">
                The filter <code className="text-dark bg-light px-2 py-1 rounded">{editableFilter}</code> is valid but didn't match any packets in this PCAP file.
              </p>
              <hr />
              <p className="mb-0">
                <strong>Suggestions:</strong>
              </p>
              <ul className="mb-0">
                <li>Try a broader filter (e.g., just "tcp" or "udp")</li>
                <li>Check if the PCAP file contains the type of traffic you're looking for</li>
                <li>Modify the port numbers, IP addresses, or protocol if they don't match the capture</li>
                <li>Generate a new filter with a different query</li>
              </ul>
              {executionTime !== null && (
                <div className="mt-2">
                  <small className="text-muted">Execution time: {executionTime}ms</small>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Results */}
      {packets.length > 0 && (
        <div className="row mb-4">
          <div className="col-12">
            <div className="card">
              <div className="card-body">
                <div className="d-flex justify-content-between align-items-center mb-3">
                  <h5 className="card-title mb-0">
                    <i className="bi bi-list-check me-2"></i>
                    Matching Packets
                  </h5>
                  <div>
                    <span className="badge bg-primary me-2">
                      {totalMatches} matches
                    </span>
                    {executionTime !== null && (
                      <span className="badge bg-secondary">
                        {executionTime}ms
                      </span>
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
                      {packets.map((packet) => (
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
                            <span className="badge bg-info">
                              {packet.protocol.name}
                            </span>
                          </td>
                          <td>{formatBytes(packet.size)}</td>
                          <td>
                            {packet.flags?.map((flag, idx) => (
                              <span key={idx} className="badge bg-secondary me-1">
                                {flag}
                              </span>
                            ))}
                          </td>
                          <td>
                            <button
                              className="btn btn-sm btn-outline-primary"
                              onClick={() => setSelectedPacket(packet)}
                            >
                              Details
                            </button>
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
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Packet Details Modal */}
      {selectedPacket && (
        <div className="modal show d-block" tabIndex={-1} style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}>
          <div className="modal-dialog modal-lg">
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title">Packet Details</h5>
                <button
                  type="button"
                  className="btn-close"
                  onClick={() => setSelectedPacket(null)}
                ></button>
              </div>
              <div className="modal-body">
                <div className="row mb-3">
                  <div className="col-md-6">
                    <strong>Timestamp:</strong>
                    <p className="font-monospace">{formatTimestamp(selectedPacket.timestamp)}</p>
                  </div>
                  <div className="col-md-6">
                    <strong>Protocol:</strong>
                    <p>{selectedPacket.protocol.name} ({selectedPacket.protocol.layer})</p>
                  </div>
                </div>
                <div className="row mb-3">
                  <div className="col-md-6">
                    <strong>Source:</strong>
                    <p className="font-monospace">
                      {selectedPacket.source.ip}:{selectedPacket.source.port}
                      {selectedPacket.source.hostname && (
                        <><br /><small className="text-muted">{selectedPacket.source.hostname}</small></>
                      )}
                    </p>
                  </div>
                  <div className="col-md-6">
                    <strong>Destination:</strong>
                    <p className="font-monospace">
                      {selectedPacket.destination.ip}:{selectedPacket.destination.port}
                      {selectedPacket.destination.hostname && (
                        <><br /><small className="text-muted">{selectedPacket.destination.hostname}</small></>
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
                        <span key={idx} className="badge bg-secondary me-1">
                          {flag}
                        </span>
                      )) || 'None'}
                    </p>
                  </div>
                </div>
                <div className="row">
                  <div className="col-12">
                    <strong>Payload:</strong>
                    <pre className="bg-light p-3 rounded mt-2 font-monospace small" style={{ maxHeight: '300px', overflow: 'auto' }}>
                      {selectedPacket.payload || 'No payload data'}
                    </pre>
                  </div>
                </div>
              </div>
              <div className="modal-footer">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setSelectedPacket(null)}
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Cheat Sheet Modal */}
      {showCheatSheet && (
        <div className="modal show d-block" tabIndex={-1} style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}>
          <div className="modal-dialog modal-xl">
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title">
                  <i className="bi bi-file-earmark-text me-2"></i>
                  BPF Filter Cheat Sheet
                </h5>
                <button
                  type="button"
                  className="btn-close"
                  onClick={() => setShowCheatSheet(false)}
                ></button>
              </div>
              <div className="modal-body">
                <div className="text-center">
                  <img
                    src="/assets/Wireshark-Cheat-Sheet.jpg"
                    alt="Wireshark BPF Filter Cheat Sheet"
                    className="img-fluid"
                    style={{ maxHeight: '80vh', objectFit: 'contain' }}
                  />
                </div>
              </div>
              <div className="modal-footer">
                <a
                  href="/assets/Wireshark-Cheat-Sheet.jpg"
                  download="Wireshark-Cheat-Sheet.jpg"
                  className="btn btn-outline-primary"
                >
                  <i className="bi bi-download me-2"></i>
                  Download
                </a>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setShowCheatSheet(false)}
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

    </div>
  )
}
