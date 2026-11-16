import { Spinner } from '@components/common/Spinner/Spinner';
import { useState, useRef, useEffect } from 'react';
import { Button, Card, Form } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { storyService } from '@/features/story/services/storyService';

interface Message {
  role: 'user' | 'assistant';
  text: string;
}

interface StoryChatProps {
  storyId: string;
  suggestedQuestions?: string[];
  /** 'panel' fills a side column: messages scroll, the input stays at the bottom. */
  variant?: 'card' | 'panel';
}

export const StoryChat = ({ storyId, suggestedQuestions, variant = 'card' }: StoryChatProps) => {
  const panel = variant === 'panel';
  const [messages, setMessages] = useState<Message[]>([]);
  const [currentSuggestions, setCurrentSuggestions] = useState<string[]>(suggestedQuestions ?? []);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const messagesContainerRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    if ((messages.length > 0 || loading) && messagesContainerRef.current) {
      messagesContainerRef.current.scrollTop = messagesContainerRef.current.scrollHeight;
    }
  }, [messages, loading]);

  const handleSubmit = async () => {
    const question = input.trim();
    if (!question || loading) return;

    setInput('');
    setError(null);
    setMessages(prev => [...prev, { role: 'user', text: question }]);
    setLoading(true);

    try {
      const { answer, followUpQuestions } = await storyService.askQuestion(
        storyId,
        question,
        messages
      );
      setMessages(prev => [...prev, { role: 'assistant', text: answer }]);
      setCurrentSuggestions(followUpQuestions ?? []);
    } catch {
      setError('Failed to get a response. Make sure the LLM service is running.');
      // Remove the unanswered user message so they can retry
      setMessages(prev => prev.slice(0, -1));
      setInput(question);
    } finally {
      setLoading(false);
      inputRef.current?.focus();
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSubmit();
    }
  };

  const thread = (
    <>
      {messages.map((msg, i) => (
        <div
          key={i}
          className={`d-flex mb-3 ${msg.role === 'user' ? 'justify-content-end' : 'justify-content-start'}`}
        >
          {msg.role === 'assistant' && (
            <div
              className="rounded-circle bg-primary d-flex align-items-center justify-content-center flex-shrink-0 me-2"
              style={{ width: 28, height: 28, marginTop: 2 }}
            >
              <i className="bi bi-cpu text-white" style={{ fontSize: '0.7rem' }} aria-hidden="true"></i>
            </div>
          )}
          <div
            className={`px-3 py-2 rounded-3 small ${
              msg.role === 'user' ? 'bg-primary text-white' : 'bg-light text-dark border'
            }`}
            style={{ maxWidth: '85%', whiteSpace: 'pre-wrap', lineHeight: 1.5 }}
          >
            {msg.text}
          </div>
        </div>
      ))}
      {loading && (
        <div className="d-flex justify-content-start mb-3">
          <div
            className="rounded-circle bg-primary d-flex align-items-center justify-content-center flex-shrink-0 me-2"
            style={{ width: 28, height: 28 }}
          >
            <i className="bi bi-cpu text-white" style={{ fontSize: '0.7rem' }} aria-hidden="true"></i>
          </div>
          <div className="px-3 py-2 rounded-3 small bg-light border text-muted">
            <Spinner animation="border" size="sm" className="me-2" style={{ width: '0.7rem', height: '0.7rem' }} />
            Thinking...
          </div>
        </div>
      )}
    </>
  );

  const suggestions = currentSuggestions.length > 0 && !loading && (
    <div className={panel ? 'story-chat-suggestions' : 'px-3 pb-2 pt-3 d-flex flex-wrap gap-2'}>
      {currentSuggestions.map((q, i) => (
        <button
          key={i}
          type="button"
          className="story-chat-chip"
          onClick={() => {
            setInput(q);
            inputRef.current?.focus();
          }}
          disabled={loading}
        >
          <span className="story-chat-chip-text">{q}</span>
        </button>
      ))}
    </div>
  );

  const composer = (
    <div className={panel ? 'story-chat-composer' : 'p-3 d-flex gap-2 align-items-end'}>
      <Form.Control
        ref={inputRef}
        as="textarea"
        size="sm"
        rows={2}
        placeholder={panel ? 'Ask a question… (Enter to send)' : 'Ask a question about this story… (Enter to send, Shift+Enter for new line)'}
        aria-label="Ask a question about this capture"
        value={input}
        onChange={e => setInput(e.target.value)}
        onKeyDown={handleKeyDown}
        disabled={loading}
        style={{ resize: 'none' }}
      />
      <Button
        variant="primary"
        size="sm"
        className="flex-shrink-0"
        onClick={handleSubmit}
        disabled={loading || !input.trim()}
        aria-label="Send"
      >
        {loading ? <Spinner animation="border" size="sm" /> : 'Ask'}
      </Button>
    </div>
  );

  if (panel) {
    // The side column (canvas Story B): the conversation scrolls between the header and the
    // composer; suggestions sit as chips just above the composer. The parent sets the height.
    return (
      <Card className="story-chat-panel">
        <div className="story-chat-header">
          <h2 className="story-chat-title">Ask about this capture</h2>
          <div className="text-muted small">Answers come from the findings and the story.</div>
        </div>
        <div ref={messagesContainerRef} className="story-chat-messages" aria-live="polite">
          {messages.length === 0 && !loading ? (
            <p className="text-muted small mb-0">
              Ask anything about this capture: a host, a time, why something was flagged.
            </p>
          ) : (
            thread
          )}
        </div>
        <div className="story-chat-foot">
          {error && <Alert variant="danger" className="small py-2 mb-2">{error}</Alert>}
          {suggestions}
          {composer}
        </div>
      </Card>
    );
  }

  return (
    <Card className="mb-4">
      <Card.Header>
        <h6 className="mb-0">
          <i className="bi bi-chat-dots me-2" aria-hidden="true"></i>
          Ask the LLM
        </h6>
      </Card.Header>
      <Card.Body className="p-0">
        {messages.length > 0 && (
          <div
            ref={messagesContainerRef}
            className="px-3 pt-3"
            style={{ maxHeight: '320px', overflowY: 'auto' }}
          >
            {thread}
          </div>
        )}
        {error && <Alert variant="danger" className="mx-3 mt-3 small py-2 mb-0">{error}</Alert>}
        {suggestions}
        {composer}
      </Card.Body>
    </Card>
  );
};
