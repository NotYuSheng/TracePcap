import { useState, useRef, useEffect } from 'react';
import { storyService } from '@/features/story/services/storyService';

interface Message {
  role: 'user' | 'assistant';
  text: string;
}

interface StoryChatProps {
  storyId: string;
  suggestedQuestions?: string[];
}

export const StoryChat = ({ storyId, suggestedQuestions }: StoryChatProps) => {
  const [messages, setMessages] = useState<Message[]>([]);
  const [currentSuggestions, setCurrentSuggestions] = useState<string[]>(suggestedQuestions ?? []);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const messagesContainerRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    if (messages.length > 0 && messagesContainerRef.current) {
      messagesContainerRef.current.scrollTop = messagesContainerRef.current.scrollHeight;
    }
  }, [messages]);

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

  return (
    <div className="card mb-4">
      <div className="card-header">
        <h6 className="mb-0">
          <i className="bi bi-chat-dots me-2"></i>
          Ask the LLM
        </h6>
      </div>
      <div className="card-body p-0">
        {messages.length > 0 && (
          <div
            ref={messagesContainerRef}
            className="px-3 pt-3"
            style={{ maxHeight: '320px', overflowY: 'auto' }}
          >
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
                    <i className="bi bi-cpu text-white" style={{ fontSize: '0.7rem' }}></i>
                  </div>
                )}
                <div
                  className={`px-3 py-2 rounded-3 small ${
                    msg.role === 'user' ? 'bg-primary text-white' : 'bg-light text-dark border'
                  }`}
                  style={{ maxWidth: '80%', whiteSpace: 'pre-wrap', lineHeight: 1.5 }}
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
                  <i className="bi bi-cpu text-white" style={{ fontSize: '0.7rem' }}></i>
                </div>
                <div className="px-3 py-2 rounded-3 small bg-light border text-muted">
                  <span
                    className="spinner-border spinner-border-sm me-2"
                    style={{ width: '0.7rem', height: '0.7rem' }}
                  ></span>
                  Thinking...
                </div>
              </div>
            )}
          </div>
        )}

        {error && <div className="mx-3 mt-3 alert alert-danger small py-2 mb-0">{error}</div>}

        {currentSuggestions.length > 0 && !loading && (
          <div className="px-3 pb-2 pt-3 d-flex flex-wrap gap-2">
            {currentSuggestions.map((q, i) => (
              <button
                key={i}
                className="btn btn-outline-secondary btn-sm text-start"
                style={{ fontSize: '0.78rem', maxWidth: '100%' }}
                onClick={() => {
                  setCurrentSuggestions([]);
                  setInput(q);
                  inputRef.current?.focus();
                }}
                disabled={loading}
              >
                <i className="bi bi-lightbulb me-1 text-warning"></i>
                {q}
              </button>
            ))}
          </div>
        )}

        <div className="p-3 d-flex gap-2 align-items-end">
          <textarea
            ref={inputRef}
            className="form-control form-control-sm"
            rows={2}
            placeholder="Ask a question about this story… (Enter to send, Shift+Enter for new line)"
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            disabled={loading}
            style={{ resize: 'none' }}
          />
          <button
            className="btn btn-primary btn-sm flex-shrink-0"
            onClick={handleSubmit}
            disabled={loading || !input.trim()}
            style={{ height: '58px', width: '42px' }}
          >
            {loading ? (
              <span className="spinner-border spinner-border-sm"></span>
            ) : (
              <i className="bi bi-send-fill"></i>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
