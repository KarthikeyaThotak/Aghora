import { useState, useRef, useEffect } from "react";
import { Send, X, Loader2, Bot, Wifi, WifiOff, Sparkles } from "lucide-react";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { ScrollArea } from "./ui/scroll-area";
import { useAIChat } from "@/hooks/useAIChat";
import { useAnalysisSession } from "@/contexts/AnalysisSessionContext";
import { API_BASE_URL } from "@/hooks/useChartAgent";
import ReactMarkdown from "react-markdown";

const SUGGESTED = [
  "What malware family is this?",
  "List the main IOCs",
  "What persistence mechanisms are used?",
  "How can I detect this on a network?",
  "What is the SHA-256 hash?",
  "What does this malware do?",
];

interface AiChatProps {
  onClose: () => void;
  sessionId?: string;
}

export const AiChat = ({ onClose, sessionId = "default" }: AiChatProps) => {
  const { messages, loading, error, sendMessage } = useAIChat(undefined, sessionId);
  const { sessionMetadata } = useAnalysisSession();
  const [inputValue, setInputValue] = useState("");
  const [backendOk, setBackendOk] = useState<boolean | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Scroll to newest message
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading]);

  // Quick backend health check
  useEffect(() => {
    const check = async () => {
      try {
        const r = await fetch(`${API_BASE_URL}/`, { signal: AbortSignal.timeout(3000) });
        setBackendOk(r.ok);
      } catch {
        setBackendOk(false);
      }
    };
    check();
  }, []);

  const doSend = async (text?: string) => {
    const msg = (text ?? inputValue).trim();
    if (!msg || loading) return;
    setInputValue("");
    await sendMessage(msg, sessionId, sessionMetadata?.fileName, sessionMetadata?.fileHash);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); doSend(); }
  };

  return (
    <div className="w-80 md:w-96 h-full bg-background border-l border-border flex flex-col">

      {/* ── Header ──────────────────────────────────────────── */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-border flex-shrink-0">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0">
            <Bot className="h-4 w-4 text-primary" />
          </div>
          <div className="min-w-0">
            <p className="text-sm font-semibold text-foreground truncate">AI Analyst</p>
            <p className="text-xs text-muted-foreground truncate">
              {sessionMetadata?.fileName
                ? `Analysing: ${sessionMetadata.fileName}`
                : "No file loaded"}
            </p>
          </div>
        </div>
        <Button variant="ghost" size="icon" onClick={onClose} className="flex-shrink-0 ml-2 h-8 w-8">
          <X className="h-4 w-4" />
        </Button>
      </div>

      {/* ── Backend status banner ────────────────────────────── */}
      {backendOk === false && (
        <div className="mx-3 mt-3 flex items-center gap-2 text-xs text-orange-400 bg-orange-500/10 border border-orange-500/20 rounded-lg px-3 py-2 flex-shrink-0">
          <WifiOff className="h-3.5 w-3.5 flex-shrink-0" />
          Backend offline — run <code className="font-mono mx-1">python server.py</code> to enable AI chat
        </div>
      )}

      {/* ── Messages ─────────────────────────────────────────── */}
      <ScrollArea className="flex-1 px-3 py-3">
        <div className="space-y-3">
          {messages.map(msg => (
            <div key={msg.id} className={`flex ${msg.sender === "user" ? "justify-end" : "justify-start"}`}>
              <div
                className={`max-w-[85%] rounded-2xl px-3.5 py-2.5 text-sm leading-relaxed ${
                  msg.sender === "user"
                    ? "bg-primary text-primary-foreground rounded-br-sm"
                    : "bg-muted text-foreground rounded-bl-sm"
                }`}
                style={{ wordBreak: "break-word", overflowWrap: "anywhere" }}
              >
                {msg.sender === "ai" ? (
                  <div className="prose prose-sm prose-invert max-w-none prose-p:my-1 prose-headings:my-1 prose-ul:my-1 prose-li:my-0 prose-strong:text-white prose-em:text-white prose-code:text-xs prose-pre:text-xs prose-pre:bg-background/60 prose-pre:border prose-pre:border-border">
                    <ReactMarkdown
                      components={{
                        p: ({ children }) => <p className="mb-1.5 last:mb-0">{children}</p>,
                        ul: ({ children }) => <ul className="mb-1.5 ml-4 list-disc">{children}</ul>,
                        ol: ({ children }) => <ol className="mb-1.5 ml-4 list-decimal">{children}</ol>,
                        li: ({ children }) => <li className="mb-0.5">{children}</li>,
                        code: ({ children, className }) => className
                          ? <code className={`${className} break-all`}>{children}</code>
                          : <code className="bg-background/60 px-1 py-0.5 rounded text-xs font-mono">{children}</code>,
                        pre: ({ children }) => (
                          <pre className="bg-background p-2.5 rounded-lg overflow-x-auto border border-border mb-1.5 whitespace-pre-wrap break-all">{children}</pre>
                        ),
                      }}
                    >
                      {msg.content}
                    </ReactMarkdown>
                  </div>
                ) : (
                  <p>{msg.content}</p>
                )}
                <p className={`text-[10px] opacity-50 mt-1.5 ${msg.sender === "user" ? "text-right" : ""}`}>
                  {msg.timestamp.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                </p>
              </div>
            </div>
          ))}

          {loading && (
            <div className="flex justify-start">
              <div className="bg-muted rounded-2xl rounded-bl-sm px-4 py-3">
                <div className="flex items-center gap-2">
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" />
                  <span className="text-sm text-muted-foreground">Thinking…</span>
                </div>
              </div>
            </div>
          )}
        </div>
        <div ref={messagesEndRef} />
      </ScrollArea>

      {/* ── Suggested questions (only when no user messages yet) ── */}
      {messages.length <= 1 && !loading && (
        <div className="px-3 pb-2 flex-shrink-0">
          <p className="text-xs text-muted-foreground mb-2 flex items-center gap-1.5">
            <Sparkles className="h-3 w-3" /> Try asking…
          </p>
          <div className="flex flex-wrap gap-1.5">
            {SUGGESTED.map(q => (
              <button
                key={q}
                onClick={() => doSend(q)}
                className="text-xs bg-muted hover:bg-primary/10 hover:text-primary border border-border rounded-full px-2.5 py-1 text-muted-foreground transition-colors text-left"
              >
                {q}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* ── Input bar ────────────────────────────────────────── */}
      <div className="px-3 pb-3 pt-2 border-t border-border flex-shrink-0">
        <div className="flex gap-2">
          <Input
            value={inputValue}
            onChange={e => setInputValue(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask about the malware…"
            className="flex-1 bg-muted border-border text-sm h-9"
            disabled={loading}
          />
          <Button
            onClick={() => doSend()}
            size="icon"
            className="h-9 w-9 flex-shrink-0"
            disabled={loading || !inputValue.trim()}
          >
            {loading
              ? <Loader2 className="h-4 w-4 animate-spin" />
              : <Send className="h-4 w-4" />
            }
          </Button>
        </div>
      </div>