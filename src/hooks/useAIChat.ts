/**
 * React hook for AI chat functionality with malware analysis.
 * Chat history is persisted to the local SQLite database and
 * reloaded automatically whenever the sessionId changes.
 */

import { useState, useCallback, useEffect, useRef } from 'react';
import { API_BASE_URL } from './useChartAgent';

const GREETING: ChatMessage = {
  id: 'greeting',
  content:
    "Hello! I'm your AI malware analysis assistant. I can help you analyze suspicious files, explain threats, and provide security insights. Upload a file to start analysis, or ask me questions about malware analysis.",
  sender: 'ai',
  timestamp: new Date(),
};

export interface ChatMessage {
  id: string;
  content: string;
  sender: 'user' | 'ai';
  timestamp: Date;
}

interface UseAIChatReturn {
  messages: ChatMessage[];
  loading: boolean;
  error: string | null;
  sendMessage: (message: string, sessionId: string, fileName?: string, fileHash?: string) => Promise<void>;
  clearMessages: () => void;
}

export const useAIChat = (
  baseUrl: string = API_BASE_URL,
  sessionId?: string,
): UseAIChatReturn => {
  const [messages, setMessages] = useState<ChatMessage[]>([GREETING]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Track the last session we loaded so we don't double-fetch
  const loadedSessionRef = useRef<string | null>(null);

  // Load persisted chat history whenever sessionId changes
  useEffect(() => {
    if (!sessionId || sessionId === loadedSessionRef.current) return;

    loadedSessionRef.current = sessionId;

    const loadHistory = async () => {
      try {
        const res = await fetch(`${baseUrl}/api/sessions/${sessionId}/chat`);
        if (!res.ok) return; // Session may not have chat yet — that's fine

        const data = await res.json();
        const history: ChatMessage[] = (data.messages ?? []).map(
          (m: { id: number; sender: 'user' | 'ai'; content: string; created_at: string }) => ({
            id: String(m.id),
            content: m.content,
            sender: m.sender,
            timestamp: new Date(m.created_at),
          }),
        );

        if (history.length > 0) {
          setMessages([GREETING, ...history]);
        }
      } catch {
        // Network error — history simply won't load; that's acceptable
      }
    };

    loadHistory();
  }, [sessionId, baseUrl]);

  const sendMessage = useCallback(
    async (message: string, sid: string, fileName?: string, fileHash?: string) => {
      if (!message.trim()) return;

      const userMessage: ChatMessage = {
        id: Date.now().toString(),
        content: message,
        sender: 'user',
        timestamp: new Date(),
      };

      setMessages((prev) => [...prev, userMessage]);
      setLoading(true);
      setError(null);

      try {
        const requestBody: Record<string, string> = { message, sessionId: sid };
        if (fileName) requestBody.fileName = fileName;
        if (fileHash) requestBody.fileHash = fileHash;

        const response = await fetch(`${baseUrl}/api/analysis/chat`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(requestBody),
        });

        if (!response.ok) throw new Error(`API error: ${response.statusText}`);

        const data = await response.json();
        const aiContent =
          data.response || 'I apologize, but I encountered an error processing your request.';

        const aiMessage: ChatMessage = {
          id: (Date.now() + 1).toString(),
          content: aiContent,
          sender: 'ai',
          timestamp: new Date(),
        };

        setMessages((prev) => [...prev, aiMessage]);
      } catch (err) {
        const errorMessage = err instanceof Error ? err.message : 'Failed to send message';
        setError(errorMessage);

        setMessages((prev) => [
          ...prev,
          {
            id: (Date.now() + 1).toString(),
            content: `I'm sorry, I encountered an error: ${errorMessage}. Please make sure the analysis server is running.`,
            sender: 'ai',
            timestamp: new Date(),
          },
        ]);
      } finally {
        setLoading(false);
      }
    },
    [baseUrl],
  );

  const clearMessages = useCallback(() => {
    setMessages([GREETING]);
    loadedSessionRef.current = null;
  }, []);

  return { messages, loading, error, sendMessage, clearMessages };
};
