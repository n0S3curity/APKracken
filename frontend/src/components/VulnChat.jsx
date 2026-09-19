import { useEffect, useRef, useState } from 'react';
import { api, apiErrorMessages } from '../api/client.js';
import Markdown from './Markdown.jsx';
import CopyButton from './CopyButton.jsx';
import { useConfirm } from './ConfirmProvider.jsx';

const SUGGESTIONS = [
  'Explain this vulnerability in simple terms.',
  'Give me a concrete adb PoC to exploit it.',
  'What is the real-world impact and worst case?',
  'How exactly do I fix it in the code?',
  'Can this be chained with other issues?',
];

// Per-vulnerability AI chat. The backend assembles the full finding context (files, source,
// static + dynamic analysis, PoC) on the first message and persists the conversation, so
// follow-ups are fast and grounded.
export default function VulnChat({ vulnId }) {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const [error, setError] = useState(null);
  const [loaded, setLoaded] = useState(false);
  const scrollRef = useRef(null);
  const confirm = useConfirm();

  useEffect(() => {
    let alive = true;
    setLoaded(false);
    setError(null);
    api
      .vulnChatHistory(vulnId)
      .then((data) => {
        if (alive) setMessages(Array.isArray(data?.messages) ? data.messages : []);
      })
      .catch(() => {
        if (alive) setMessages([]);
      })
      .finally(() => {
        if (alive) setLoaded(true);
      });
    return () => {
      alive = false;
    };
  }, [vulnId]);

  useEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [messages, sending]);

  const send = async (text) => {
    const question = String(text ?? input).trim();
    if (!question || sending) return;
    setError(null);
    setInput('');
    // Optimistic: show the user's message immediately while the model thinks.
    setMessages((prev) => [...prev, { id: `tmp-${Date.now()}`, role: 'user', content: question, pending: true }]);
    setSending(true);
    try {
      const data = await api.vulnChatSend(vulnId, question);
      setMessages(Array.isArray(data?.messages) ? data.messages : []);
    } catch (e) {
      // Roll back the optimistic message and restore the text so the user can retry.
      setMessages((prev) => prev.filter((m) => !m.pending));
      setInput(question);
      setError(apiErrorMessages(e)[0] || 'The model could not answer. Is it running?');
    } finally {
      setSending(false);
    }
  };

  const clearChat = async () => {
    const ok = await confirm({
      title: 'Clear conversation',
      message: 'Delete this finding’s entire chat history? This cannot be undone.',
      confirmLabel: 'Clear',
      danger: true,
    });
    if (!ok) return;
    try {
      await api.vulnChatClear(vulnId);
      setMessages([]);
      setError(null);
    } catch (e) {
      setError(apiErrorMessages(e)[0] || 'Could not clear the conversation.');
    }
  };

  const onKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  };

  const empty = loaded && messages.length === 0;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: 'min(70vh, 640px)' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
        <div style={{ fontSize: 12.5, color: 'var(--text-3)' }}>
          Chat with the local model about this specific finding. It already has the code, analysis, and PoC.
        </div>
        {messages.length > 0 && (
          <button
            type="button"
            onClick={clearChat}
            style={{
              border: '1px solid var(--border-2)',
              background: 'var(--surface)',
              color: 'var(--text-2)',
              borderRadius: 7,
              fontSize: 11.5,
              padding: '4px 10px',
              cursor: 'pointer',
              flex: 'none',
            }}
          >
            Clear
          </button>
        )}
      </div>

      <div
        ref={scrollRef}
        style={{
          flex: 1,
          overflowY: 'auto',
          border: '1px solid var(--border)',
          borderRadius: 12,
          background: 'var(--surface)',
          padding: 16,
          display: 'flex',
          flexDirection: 'column',
          gap: 12,
          minHeight: 0,
        }}
      >
        {empty && (
          <div style={{ margin: 'auto', textAlign: 'center', maxWidth: 460 }}>
            <div style={{ fontSize: 30, marginBottom: 8 }}>🤖</div>
            <div style={{ fontSize: 13.5, color: 'var(--text-2)', marginBottom: 16, lineHeight: 1.5 }}>
              Ask anything about this vulnerability — exploitation, impact, remediation, or chaining. The model has
              the full context.
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, justifyContent: 'center' }}>
              {SUGGESTIONS.map((s) => (
                <button
                  key={s}
                  type="button"
                  onClick={() => send(s)}
                  disabled={sending}
                  style={{
                    border: '1px solid var(--border-2)',
                    background: 'var(--surface-2)',
                    color: 'var(--text)',
                    borderRadius: 20,
                    fontSize: 12,
                    padding: '6px 12px',
                    cursor: sending ? 'default' : 'pointer',
                  }}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((m) => (
          <MessageBubble key={m.id} role={m.role} content={m.content} />
        ))}

        {sending && <ThinkingBubble />}
      </div>

      {error && (
        <div style={{ marginTop: 8, fontSize: 12, color: 'var(--fail)' }}>{error}</div>
      )}

      <div style={{ display: 'flex', gap: 8, marginTop: 10, alignItems: 'flex-end' }}>
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={onKeyDown}
          placeholder="Ask about this vulnerability…  (Enter to send, Shift+Enter for newline)"
          rows={2}
          style={{
            flex: 1,
            resize: 'vertical',
            minHeight: 42,
            maxHeight: 160,
            padding: '10px 12px',
            borderRadius: 10,
            border: '1px solid var(--border)',
            background: 'var(--surface)',
            color: 'var(--text)',
            fontSize: 13,
            lineHeight: 1.5,
            fontFamily: 'inherit',
          }}
        />
        <button
          type="button"
          onClick={() => send()}
          disabled={sending || !input.trim()}
          style={{
            flex: 'none',
            height: 42,
            padding: '0 18px',
            borderRadius: 10,
            border: 0,
            background: sending || !input.trim() ? 'var(--surface-2)' : 'var(--accent)',
            color: sending || !input.trim() ? 'var(--text-3)' : '#fff',
            fontSize: 13,
            fontWeight: 600,
            cursor: sending || !input.trim() ? 'default' : 'pointer',
          }}
        >
          Send
        </button>
      </div>
    </div>
  );
}

function ToolSteps({ content }) {
  let steps = [];
  try {
    const parsed = JSON.parse(content);
    if (Array.isArray(parsed)) steps = parsed;
  } catch {
    return null;
  }
  if (!steps.length) return null;
  const argSummary = (s) => {
    const a = s.args || {};
    return a.path || a.pattern || Object.values(a)[0] || '';
  };
  return (
    <div style={{ alignSelf: 'flex-start', maxWidth: '92%', border: '1px solid var(--border-2)', borderRadius: 10, background: 'var(--surface)', padding: '8px 12px' }}>
      <div style={{ fontSize: 10.5, textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--text-3)', marginBottom: 5 }}>
        🔧 Researched the source ({steps.length} step{steps.length === 1 ? '' : 's'})
      </div>
      {steps.map((s, i) => (
        <div key={i} className="mono" style={{ fontSize: 11, color: 'var(--text-2)', padding: '1px 0', wordBreak: 'break-all' }}>
          {s.tool} <span style={{ color: 'var(--accent)' }}>{argSummary(s)}</span>
        </div>
      ))}
    </div>
  );
}

function MessageBubble({ role, content }) {
  if (role === 'tool') return <ToolSteps content={content} />;
  const isUser = role === 'user';
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: isUser ? 'flex-end' : 'flex-start' }}>
      <div
        style={{
          maxWidth: '88%',
          padding: '10px 14px',
          borderRadius: 12,
          border: '1px solid var(--border-2)',
          background: isUser ? 'var(--accent-subtle)' : 'var(--surface-2)',
          color: 'var(--text)',
          fontSize: 13,
          lineHeight: 1.55,
        }}
      >
        {isUser ? (
          <span style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{content}</span>
        ) : (
          <Markdown source={content || ''} />
        )}
      </div>
      {!isUser && content && (
        <div style={{ marginTop: 3 }}>
          <CopyButton text={content} label="Copy" />
        </div>
      )}
    </div>
  );
}

const THINK_MSGS = [
  'Reading the decompiled source…',
  'Tracing the vulnerability flow…',
  'Checking the code and guards…',
  'Writing the answer…',
];

function ThinkingBubble() {
  const [i, setI] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setI((x) => (x + 1) % THINK_MSGS.length), 2600);
    return () => clearInterval(t);
  }, []);
  return (
    <div
      style={{
        alignSelf: 'flex-start',
        maxWidth: '88%',
        padding: '11px 15px',
        borderRadius: 12,
        border: '1px solid var(--border-2)',
        background: 'var(--surface-2)',
        display: 'flex',
        alignItems: 'center',
        gap: 11,
      }}
    >
      <span style={{ display: 'inline-flex', gap: 4 }}>
        <Dot delay="0s" />
        <Dot delay=".18s" />
        <Dot delay=".36s" />
      </span>
      <span style={{ fontSize: 12.5, color: 'var(--text-2)', fontWeight: 500 }}>{THINK_MSGS[i]}</span>
    </div>
  );
}

function Dot({ delay }) {
  return (
    <span
      style={{
        width: 7,
        height: 7,
        borderRadius: '50%',
        background: 'var(--accent)',
        display: 'inline-block',
        animation: 'okpulse 1s ease-in-out infinite',
        animationDelay: delay,
      }}
    />
  );
}
