export const StoryInfoCard = () => (
  <div className="card">
    <div className="card-header">
      <h6 className="mb-0">
        <i className="bi bi-info-circle me-2"></i>
        How Stories Are Generated &amp; Limitations
      </h6>
    </div>
    <div className="card-body">
      <p className="text-muted small mb-2">
        The following data is sent to the configured LLM to generate the narrative:
      </p>
      <ul className="small text-muted mb-3">
        <li>File metadata, traffic summary, protocol breakdown, and category distribution</li>
        <li>
          The top <strong>N</strong> conversations by volume, including nDPI app names, categories,
          TLS certificate details, and risk flags (configurable via{' '}
          <code>STORY_MAX_CONVERSATIONS</code>, default 20)
        </li>
        <li>
          Security alerts listing up to <strong>N</strong> at-risk conversations — the LLM is told
          the total count even when the list is truncated
        </li>
      </ul>
      <p className="text-muted small mb-2">
        <strong>Not sent to the LLM:</strong>
      </p>
      <ul className="small text-muted mb-0">
        <li>Packet payloads and HTTP bodies</li>
        <li>DNS query names and TLS SNI</li>
        <li>Conversations beyond the configured cap</li>
      </ul>
    </div>
  </div>
);
