import { Spinner } from '@components/common/Spinner/Spinner';
import { useState, useRef, useEffect } from 'react';
import { Alert, Button, Card, Form } from '@govtechsg/sgds-react';
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
    <Card className="mb-4">
      <Card.Header>
        <h6 className="mb-0">
          <i className="bi bi-chat-dots me-2"></i>
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
                  <Spinner animation="border" size="sm" className="me-2" style={{ width: '0.7rem', height: '0.7rem' }} />
                  Thinking...
                </div>
              </div>
            )}
          </div>
        )}

        {error && <Alert variant="danger" className="mx-3 mt-3 small py-2 mb-0">{error}</Alert>}

        {currentSuggestions.length > 0 && !loading && (
          <div className="px-3 pb-2 pt-3 d-flex flex-wrap gap-2">
            {currentSuggestions.map((q, i) => (
              <Button
                key={i}
                variant="outline-secondary"
                size="sm"
                className="text-start"
                style={{ fontSize: '0.78rem', maxWidth: '100%' }}
                onClick={() => {
                  setInput(q);
                  inputRef.current?.focus();
                }}
                disabled={loading}
              >
                <i className="bi bi-lightbulb me-1 text-warning"></i>
                {q}
              </Button>
            ))}
          </div>
        )}

        <div className="p-3 d-flex gap-2 align-items-end">
          <Form.Control
            ref={inputRef}
            as="textarea"
            size="sm"
            rows={2}
            placeholder="Ask a question about this story… (Enter to send, Shift+Enter for new line)"
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
            style={{ height: '58px', width: '42px' }}
          >
            {loading ? (
              <Spinner animation="border" size="sm" />
            ) : (
              <i className="bi bi-send-fill"></i>
            )}
          </Button>
        </div>
      </Card.Body>
    </Card>
  );
};
