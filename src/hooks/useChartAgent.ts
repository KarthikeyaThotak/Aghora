/**
 * React hook for connecting to the Python backend Chart Agent API.
 * Provides real-time graph updates via WebSocket with REST fallback.
 *
 * Key fix: onGraphUpdate callback is now called whenever the server pushes
 * graph_update or graph_state via WebSocket, so GraphView stays in sync.
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { GraphNode, GraphConnection } from '@/types/graph';

export const API_BASE_URL =
  (import.meta as any).env?.VITE_API_URL ?? 'http://localhost:8000';

interface ChartAgentConfig {
  baseUrl?: string;
  sessionId?: string;
  useWebSocket?: boolean;
  /** Called whenever the server pushes a full graph_update or graph_state */
  onGraphUpdate?: (nodes: GraphNode[], connections: GraphConnection[]) => void;
  /** Called whenever the server signals analysis_complete */
  onAnalysisComplete?: (data: { threat_level: string; summary: string }) => void;
}

interface UseChartAgentReturn {
  connected: boolean;
  loading: boolean;
  error: string | null;
  updateGraph: (nodes: GraphNode[], connections: GraphConnection[]) => Promise<void>;
  addNode: (node: GraphNode) => Promise<void>;
  addConnection: (connection: GraphConnection) => Promise<void>;
  deleteNode: (nodeId: string) => Promise<void>;
  deleteConnection: (connectionId: string) => Promise<void>;
  getGraph: () => Promise<{ nodes: GraphNode[]; connections: GraphConnection[] } | null>;
}

export const useChartAgent = (config: ChartAgentConfig = {}): UseChartAgentReturn => {
  const {
    baseUrl = API_BASE_URL,
    sessionId = 'default',
    useWebSocket = true,
    onGraphUpdate,
    onAnalysisComplete,
  } = config;

  const [connected, setConnected] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const onGraphUpdateRef = useRef(onGraphUpdate);
  const onAnalysisCompleteRef = useRef(onAnalysisComplete);

  // Keep callback refs fresh so WebSocket handler always calls the latest version
  useEffect(() => { onGraphUpdateRef.current = onGraphUpdate; }, [onGraphUpdate]);
  useEffect(() => { onAnalysisCompleteRef.current = onAnalysisComplete; }, [onAnalysisComplete]);

  // WebSocket connection
  useEffect(() => {
    if (!useWebSocket) {
      setConnected(true);
      return;
    }

    let destroyed = false;

    const connectWebSocket = () => {
      if (destroyed) return;
      try {
        const wsUrl = `${baseUrl.replace(/^http/, 'ws')}/ws/${sessionId}`;
        const ws = new WebSocket(wsUrl);

        ws.onopen = () => {
          if (destroyed) { ws.close(); return; }
          setConnected(true);
          setError(null);
          if (reconnectTimeoutRef.current) {
            clearTimeout(reconnectTimeoutRef.current);
            reconnectTimeoutRef.current = null;
          }
        };

        ws.onmessage = (event) => {
          try {
            const message = JSON.parse(event.data as string);

            switch (message.type) {
              case 'graph_update':
              case 'graph_state': {
                const data = message.data ?? {};
                const nodes: GraphNode[] = data.nodes ?? [];
                const connections: GraphConnection[] = data.connections ?? [];
                if (nodes.length > 0) {
                  onGraphUpdateRef.current?.(nodes, connections);
                }
                break;
              }
              case 'analysis_complete':
                onAnalysisCompleteRef.current?.(message.data ?? {});
                break;
              case 'node_update':
              case 'connection_update':
              case 'pong':
                break;
              default:
                break;
            }
          } catch {
            // malformed frame — ignore
          }
        };

        ws.onerror = () => {
          setError('Backend not reachable — make sure the Python server is running on port 8000');
          setConnected(false);
        };

        ws.onclose = () => {
          setConnected(false);
          if (!destroyed) {
            reconnectTimeoutRef.current = setTimeout(connectWebSocket, 4000);
          }
        };

        wsRef.current = ws;
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Connection failed');
        setConnected(false);
        if (!destroyed) {
          reconnectTimeoutRef.current = setTimeout(connectWebSocket, 4000);
        }
      }
    };

    connectWebSocket();

    return () => {
      destroyed = true;
      wsRef.current?.close();
      wsRef.current = null;
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
    };
  }, [baseUrl, sessionId, useWebSocket]);

  // REST helper
  const apiRequest = useCallback(async (
    method: 'GET' | 'POST' | 'DELETE',
    endpoint: string,
    data?: unknown,
  ) => {
    const url = `${baseUrl}/api${endpoint}`;
    const options: RequestInit = { method, headers: { 'Content-Type': 'application/json' } };
    if (data && method === 'POST') options.body = JSON.stringify(data);
    const response = await fetch(url, options);
    if (!response.ok) throw new Error(`API ${method} ${endpoint} → ${response.status} ${response.statusText}`);
    return response.json();
  }, [baseUrl]);

  const updateGraph = useCallback(async (nodes: GraphNode[], connections: GraphConnection[]) => {
    setLoading(true);
    setError(null);
    try {
      const payload = {
        nodes: nodes.map(n => ({ id: n.id, type: n.type, label: n.label, x: n.x, y: n.y, connections: n.connections, isMainNode: n.isMainNode, sha256Hash: n.sha256Hash, fileName: n.fileName, details: n.details })),
        connections: connections.map(c => ({ id: c.id, sourceId: c.sourceId, targetId: c.targetId, type: c.type, weight: c.weight })),
        sessionId,
      };
      if (useWebSocket && wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({ type: 'update_graph', data: payload }));
      } else {
        await apiRequest('POST', '/graph/update', payload);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update graph');
      throw err;
    } finally {
      setLoading(false);
    }
  }, [apiRequest, sessionId, useWebSocket]);

  const addNode = useCallback(async (node: GraphNode) => {
    setLoading(true);
    setError(null);
    try {
      await apiRequest('POST', '/graph/node', { node: { id: node.id, type: node.type, label: node.label, x: node.x, y: node.y, connections: node.connections, isMainNode: node.isMainNode, sha256Hash: node.sha256Hash, fileName: node.fileName, details: node.details }, sessionId });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add node');
      throw err;
    } finally {
      setLoading(false);
    }
  }, [apiRequest, sessionId]);

  const addConnection = useCallback(async (connection: GraphConnection) => {
    setLoading(true);
    setError(null);
    try {
      await apiRequest('POST', '/graph/connection', { connection: { id: connection.id, sourceId: connection.sourceId, targetId: connection.targetId, type: connection.type, weight: connection.weight }, sessionId });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add connection');
      throw err;
    } finally {
      setLoading(false);
    }
  }, [apiRequest, sessionId]);

  const deleteNode = useCallback(async (nodeId: string) => {
    setLoading(true);
    setError(null);
    try {
      await apiRequest('DELETE', `/graph/node/${nodeId}?session_id=${encodeURIComponent(sessionId)}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete node');
      throw err;
    } finally {
      setLoading(false);
    }
  }, [apiRequest, sessionId]);

  const deleteConnection = useCallback(async (connectionId: string) => {
    setLoading(true);
    setError(null);
    try {
      await apiRequest('DELETE', `/graph/connection/${connectionId}?session_id=${encodeURIComponent(sessionId)}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete connection');
      throw err;
    } finally {
      setLoading(false);
    }
  }, [apiRequest, sessionId]);

  const getGraph = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await apiRequest('GET', `/graph/${sessionId}`);
      if (response?.data) {
        return { nodes: response.data.nodes as GraphNode[], connections: response.data.connections as GraphConnection[] };
      }
      return null;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to get graph');
      return null;
    } finally {
      setLoading(false);
    }
  }, [apiRequest, sessionId]);

  return { connected, loading, error, updateGraph, addNode, addConnection, deleteNode, deleteConnection, getGraph };
};
