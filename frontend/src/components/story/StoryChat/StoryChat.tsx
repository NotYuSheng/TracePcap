import { Spinner } from '@components/common/Spinner/Spinner';
import { useState, useRef, useEffect } from 'react';
import { Button, Card, Form } from '@govtechsg/sgds-react';
import { PermissionLock } from '@components/common/PermissionLock';
import { usePermission } from '@/features/me/useMe';
import { Alert } from '@components/common/Alert';
import { chatService, type ChatTurn } from '@/features/chat/chatService';
import { ChatToolsPopover } from './ChatToolsPopover';
import { ChatSteps } from './ChatSteps';
import { FilterCard } from './FilterCard';
import './StoryChat.css';

interface Message {
  role: 'user' | 'assistant';
  text: string;
  /** The turn behind an answer: its tool steps and checked filters. */
  turn?: ChatTurn;
}

interface StoryChatProps {
  fileId: string;
  /** Read with this network's detection rules (#925). */
  networkId?: string | null;
  suggestedQuestions?: string[];
  /** Whether a story has been written; without one the chat answers from the findings and tools. */
  hasStory: boolean;
}

const POLL_MS = 1000;

/** The answer with `inline code` (how models quote filters and addresses) shown as code. */
function AnswerText({ text }: { text: string }) {
  const parts = text.split(/(`[^`\n]+`)/g);
  return (
    <div className="chat-msg-text">
      {parts.map((p, i) =>
        p.length > 2 && p.startsWith('`') && p.endsWith('`') ? (
          <code key={i}>{p.slice(1, -1)}</code>
        ) : (
          p
        )
      )}
    </div>
  );
}

/** A failed turn, as a sentence to act on. */
function turnError(turn: ChatTurn): string {
  switch (turn.errorCode) {
    case 'LLM_UNREACHABLE':
      return 'The LLM server is not responding. Make sure it is running and reachable, then try again.';
    case 'LLM_TIMEOUT':
      return 'The LLM took too long to answer. Try again, or ask something narrower.';
    case 'CONTEXT_TOO_LONG':
      return 'This capture’s context is longer than the model can read at once. Use a model with a larger context window.';
    default:
      return turn.error ?? 'The chat couldn’t answer. Try again.';
  }
}

/**
 * Ask about this capture (#1161): the LLM answers, looking things up with tools first; each answer
 * shows the tools it used, and a filter it checked comes back as a card. The side column of the
 * Story tab (canvas Story B, tools design A); the page sets its height.
 */
export const StoryChat = ({ fileId, networkId, suggestedQuestions, hasStory }: StoryChatProps) => {
  const [messages, setMessages] = useState<Message[]>([]);
  const [suggestions, setSuggestions] = useState<string[]>(suggestedQuestions ?? []);
  const [input, setInput] = useState('');
  const [working, setWorking] = useState<ChatTurn | null>(null);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const alive = useRef(true);

  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);

  useEffect(() => {
    setSuggestions(suggestedQuestions ?? []);
  }, [suggestedQuestions]);

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [messages, working]);

  const busy = sending || working !== null;
  const ai = usePermission('ASK_AI');

  const submit = async () => {
    const question = input.trim();
    if (!question || busy) return;
    const history = messages.map(m => ({ role: m.role, text: m.text }));
    setInput('');
    setError(null);
    setSending(true);
    setMessages(prev => [...prev, { role: 'user', text: question }]);
    try {
      let turn = await chatService.ask(fileId, question, history, networkId);
      setWorking(turn);
      while (turn.status === 'RUNNING') {
        await new Promise(r => setTimeout(r, POLL_MS));
        if (!alive.current) return;
        turn = await chatService.turn(fileId, turn.id);
        setWorking(turn);
      }
      if (turn.status === 'FAILED') {
        setError(turnError(turn));
        setMessages(prev => prev.slice(0, -1));
        setInput(question);
      } else {
        const done = turn;
        setMessages(prev => [...prev, { role: 'assistant', text: done.answer ?? '', turn: done }]);
        setSuggestions(done.followUpQuestions ?? []);
      }
    } catch {
      setError('The question couldn’t be sent. Check that the backend and the LLM are running.');
      setMessages(prev => prev.slice(0, -1));
      setInput(question);
    } finally {
      if (alive.current) {
        setWorking(null);
        setSending(false);
        inputRef.current?.focus();
      }
    }
  };

  const onKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      void submit();
    }
  };

  return (
    <Card className="story-chat-panel">
      <div className="story-chat-header">
        <div className="flex-grow-1">
          <h2 className="story-chat-title">Ask about this capture</h2>
          <div className="text-muted small">
            {hasStory
              ? 'Answers come from the findings, the story and the tools.'
              : 'Answers come from the findings and the tools; the story adds more once written.'}
          </div>
        </div>
        <ChatToolsPopover />
      </div>

      <div ref={scrollRef} className="story-chat-messages" aria-live="polite">
        {messages.length === 0 && !busy && (
          <p className="text-muted small mb-0">
            Ask anything about this capture: a host, a time, why something was flagged, or a
            Wireshark filter for something you want to see.
          </p>
        )}
        {messages.map((m, i) =>
          m.role === 'user' ? (
            <div key={i} className="chat-msg chat-msg-user">
              {m.text}
            </div>
          ) : (
            <div key={i} className="chat-msg chat-msg-ai">
              {m.turn && (
                <ChatSteps steps={m.turn.steps} running={false} elapsedMs={m.turn.elapsedMs} />
              )}
              <AnswerText text={m.text} />
              {m.turn?.filters.map(f => (
                <FilterCard key={f.expression} fileId={fileId} filter={f} />
              ))}
              {m.turn && !m.turn.toolsOffered && (
                <div className="chat-msg-note">
                  Answered without tools: the LLM server didn’t take them.
                </div>
              )}
              {m.turn?.modelNote && <div className="chat-msg-note">{m.turn.modelNote}</div>}
            </div>
          )
        )}
        {busy && (
          <div className="chat-msg chat-msg-ai">
            {working && working.steps.length > 0 ? (
              <ChatSteps steps={working.steps} running elapsedMs={working.elapsedMs} />
            ) : (
              <div className="text-muted small">
                <Spinner
                  animation="border"
                  size="sm"
                  className="me-2"
                  style={{ width: '0.7rem', height: '0.7rem' }}
                />
                Thinking…{working ? ` ${Math.round(working.elapsedMs / 1000)} s` : ''}
              </div>
            )}
          </div>
        )}
      </div>

      <div className="story-chat-foot">
        {error && (
          <Alert variant="danger" className="small py-2 mb-2">
            {error}
          </Alert>
        )}
        {suggestions.length > 0 && !busy && ai.allowed && (
          <div className="story-chat-suggestions">
            {suggestions.map((q, i) => (
              <button
                key={i}
                type="button"
                className="story-chat-chip"
                onClick={() => {
                  setInput(q);
                  inputRef.current?.focus();
                }}
              >
                <span className="story-chat-chip-text">{q}</span>
              </button>
            ))}
          </div>
        )}
        <div className="story-chat-composer">
          <Form.Control
            ref={inputRef}
            as="textarea"
            size="sm"
            rows={2}
            placeholder={
              ai.allowed
                ? 'Ask a question… (Enter to send)'
                : "Your roles don't allow asking the AI"
            }
            aria-label="Ask a question about this capture"
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={onKeyDown}
            disabled={busy || !ai.allowed}
            style={{ resize: 'none' }}
          />
          <Button
            variant="primary"
            size="sm"
            className="flex-shrink-0"
            onClick={() => void submit()}
            disabled={busy || !input.trim() || !ai.allowed}
          >
            {busy ? <Spinner animation="border" size="sm" /> : 'Ask'}
          </Button>
          <PermissionLock action="ASK_AI" className="align-self-center" />
        </div>
      </div>
    </Card>
  );
};
