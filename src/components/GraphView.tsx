import { useState, useCallback, useEffect, useRef } from "react";
import { GraphNode, GraphConnection, GraphViewport } from "@/types/graph";
import { GraphCanvas, GraphControls, NodeDetailPanel, NodeDetailWindow } from "./graph";
import { useAnalysisSession } from "@/contexts/AnalysisSessionContext";
import { useChartAgent, API_BASE_URL } from "@/hooks/useChartAgent";
import { Loader2, Wifi, WifiOff, Activity, ChevronDown, ChevronUp, FileDown } from "lucide-react";
import { Badge } from "./ui/badge";

// ── Legend data ───────────────────────────────────────────────────────────────
const LEGEND_ITEMS = [
  { type: "main",     color: "#dc2626", shape: "hex",  label: "Sample (Main)"       },
  { type: "network",  color: "#3b82f6", shape: "diam", label: "Network / C2 IOC"    },
  { type: "inject",   color: "#ef4444", shape: "pent", label: "Process Injection"   },
  { type: "persist",  color: "#f97316", shape: "sq",   label: "Persistence"         },
  { type: "registry", color: "#f59e0b", shape: "sq",   label: "Registry Key"        },
  { type: "api",      color: "#8b5cf6", shape: "hex",  label: "Win32 API Category"  },
  { type: "crypto",   color: "#10b981", shape: "tri",  label: "Cryptography"        },
  { type: "section",  color: "#06b6d4", shape: "sq",   label: "PE Section"          },
  { type: "threat",   color: "#e11d48", shape: "tri",  label: "AI / Threat Finding" },
  { type: "file",     color: "#f59e0b", shape: "sq",   label: "File Artifact"       },
  { type: "process",  color: "#a78bfa", shape: "pent", label: "Process"             },
] as const;

function LegendShape({ shape, color }: { shape: string; color: string }) {
  const r = 7;
  let path = "";
  if (shape === "hex") {
    const pts = Array.from({ length: 6 }, (_, i) => {
      const a = (Math.PI / 3) * i - Math.PI / 6;
      return `${(r * Math.cos(a)).toFixed(1)},${(r * Math.sin(a)).toFixed(1)}`;
    });
    path = `M ${pts.join(" L ")} Z`;
  } else if (shape === "diam") {
    const w = (r * 0.72).toFixed(1);
    path = `M 0,${-r} L ${w},0 L 0,${r} L ${-w},0 Z`;
  } else if (shape === "sq") {
    const s = (r * 0.84).toFixed(1);
    path = `M ${-s},${-s} L ${s},${-s} L ${s},${s} L ${-s},${s} Z`;
  } else if (shape === "pent") {
    const pts = Array.from({ length: 5 }, (_, i) => {
      const a = (Math.PI * 2 / 5) * i - Math.PI / 2;
      return `${(r * Math.cos(a)).toFixed(1)},${(r * Math.sin(a)).toFixed(1)}`;
    });
    path = `M ${pts.join(" L ")} Z`;
  } else if (shape === "tri") {
    path = `M 0,${-r} L ${(r * 0.87).toFixed(1)},${(r * 0.5).toFixed(1)} L ${(-r * 0.87).toFixed(1)},${(r * 0.5).toFixed(1)} Z`;
  }
  return (
    <svg width={18} height={18} viewBox="-9 -9 18 18" style={{ flexShrink: 0 }}>
      <path d={path} fill={`${color}22`} stroke={color} strokeWidth={1.6} />
    </svg>
  );
}

interface GraphViewProps {
  analysisSessionId?: string;
}

export const GraphView = ({ analysisSessionId }: GraphViewProps) => {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [draggedNode, setDraggedNode] = useState<string | null>(null);
  const [viewport, setViewport] = useState<GraphViewport>({ scale: 1, offset: { x: 0, y: 0 } });
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [connections, setConnections] = useState<GraphConnection[]>([]);
  const [loading, setLoading] = useState(false);
  const [analysisStatus, setAnalysisStatus] = useState<string | null>(null);
  const [threatLevel, setThreatLevel] = useState<string | null>(null);
  const [openWindows, setOpenWindows] = useState<Set<string>>(new Set());
  const [windowPositions, setWindowPositions] = useState<Record<string, { x: number; y: number }>>({});
  const [draggedWindow, setDraggedWindow] = useState<string | null>(null);
  const [legendOpen, setLegendOpen] = useState(true);

  // Container ref for auto-fit
  const containerRef = useRef<HTMLDivElement>(null);
  const hasFittedRef = useRef(false);

  useAnalysisSession(); // kept for context side-effects; metadata set by Workspace

  // ── Auto-fit helper ─────────────────────────────────────────────────────────
  const fitToNodes = useCallback((nodeList: GraphNode[]) => {
    if (nodeList.length === 0) return;
    const container = containerRef.current;
    if (!container) return;
    const { width, height } = container.getBoundingClientRect();
    if (width === 0 || height === 0) return;

    const xs = nodeList.map(n => n.x);
    const ys = nodeList.map(n => n.y);
    const minX = Math.min(...xs), maxX = Math.max(...xs);
    const minY = Math.min(...ys), maxY = Math.max(...ys);
    const pad = 90; // world-space padding
    const worldW = (maxX - minX) + pad * 2;
    const worldH = (maxY - minY) + pad * 2;

    const scale = Math.min(Math.min(width / worldW, height / worldH), 1.1);
    const worldCx = (minX + maxX) / 2;
    const worldCy = (minY + maxY) / 2;
    setViewport({
      scale,
      offset: { x: width / 2 - worldCx * scale, y: height / 2 - worldCy * scale },
    });
  }, []);

  // Live graph updates from WebSocket — this is the core real-time path
  const handleGraphUpdate = useCallback((newNodes: GraphNode[], newConnections: GraphConnection[]) => {
    if (newNodes.length === 0) return;
    setNodes(newNodes);
    setConnections(newConnections);
    setLoading(false);
    setAnalysisStatus("Graph updated from analysis");
    setTimeout(() => setAnalysisStatus(null), 4000);
  }, []);

  const handleAnalysisComplete = useCallback((data: { threat_level: string; summary: string }) => {
    setThreatLevel(data.threat_level);
    setAnalysisStatus(`Analysis complete — Threat level: ${data.threat_level?.toUpperCase() ?? "UNKNOWN"}`);
    setLoading(false);
  }, []);

  const { connected, getGraph } = useChartAgent({
    sessionId: analysisSessionId ?? "default",
    onGraphUpdate: handleGraphUpdate,
    onAnalysisComplete: handleAnalysisComplete,
  });

  // Auto-fit when nodes first arrive (not on subsequent drags)
  useEffect(() => {
    if (nodes.length > 0 && !hasFittedRef.current) {
      hasFittedRef.current = true;
      // Small timeout so the SVG container has rendered its final size
      setTimeout(() => fitToNodes(nodes), 120);
    }
  }, [nodes, fitToNodes]);

  // When session ID changes: reset state and try to fetch any existing graph
  useEffect(() => {
    hasFittedRef.current = false; // allow re-fit for new session
    if (!analysisSessionId) {
      setNodes([]);
      setConnections([]);
      setThreatLevel(null);
      setSelectedNode(null);
      return;
    }

    setLoading(true);
    setNodes([]);
    setConnections([]);
    setThreatLevel(null);
    setSelectedNode(null);

    // Attempt to pull the graph from the server (in case analysis already ran)
    let cancelled = false;
    const tryFetchGraph = async () => {
      try {
        const result = await getGraph();
        if (!cancelled && result && result.nodes.length > 0) {
          setNodes(result.nodes);
          setConnections(result.connections);
          setLoading(false);
        } else if (!cancelled) {
          // No data yet — keep showing spinner; WebSocket will deliver when ready
          setLoading(false);
        }
      } catch {
        if (!cancelled) setLoading(false);
      }
    };

    // Small delay so server has time to register the session
    const t = setTimeout(tryFetchGraph, 800);
    return () => { cancelled = true; clearTimeout(t); };
  }, [analysisSessionId]); // eslint-disable-line react-hooks/exhaustive-deps

  // Node event handlers
  const handleNodeSelect = useCallback((node: GraphNode) => setSelectedNode(node), []);
  const handleNodeHover = useCallback((nodeId: string | null) => setHoveredNode(nodeId), []);
  const handleNodeMouseDown = useCallback((_e: React.MouseEvent, nodeId: string) => setDraggedNode(nodeId), []);
  const handleCanvasClick = useCallback(() => setSelectedNode(null), []);

  const handleNodeDrag = useCallback((nodeId: string, newX: number, newY: number) => {
    setNodes(prev => prev.map(n => n.id === nodeId ? { ...n, x: newX, y: newY } : n));
  }, []);

  // ── Report export ───────────────────────────────────────────────────────────
  const [exporting, setExporting] = useState(false);
  const handleExportReport = useCallback(async () => {
    if (!analysisSessionId || exporting) return;
    setExporting(true);
    try {
      const res = await fetch(`${API_BASE_URL}/report/${analysisSessionId}`);
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        alert(`Report generation failed: ${err.detail ?? res.statusText}`);
        return;
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      const cd = res.headers.get("Content-Disposition") ?? "";
      const match = cd.match(/filename="([^"]+)"/);
      a.download = match ? match[1] : `aghora_report_${analysisSessionId}.pdf`;
      a.href = url;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      alert("Could not reach the backend. Make sure server.py is running.");
    } finally {
      setExporting(false);
    }
  }, [analysisSessionId, exporting]);

  const handleViewportChange = useCallback((v: GraphViewport) => setViewport(v), []);
  const handleZoomIn = useCallback(() => setViewport(p => ({ ...p, scale: Math.min(3, p.scale + 0.2) })), []);
  const handleZoomOut = useCallback(() => setViewport(p => ({ ...p, scale: Math.max(0.3, p.scale - 0.2) })), []);
  const handleReset = useCallback(() => {
    if (nodes.length > 0) {
      fitToNodes(nodes);
    } else {
      setViewport({ scale: 1, offset: { x: 0, y: 0 } });
    }
  }, [nodes, fitToNodes]);

  const openDetailWindow = useCallback((nodeId: string) => {
    setOpenWindows(prev => new Set([...prev, nodeId]));
    setWindowPositions(prev => prev[nodeId] ? prev : {
      ...prev,
      [nodeId]: { x: 120 + (openWindows.size * 40), y: 120 + (openWindows.size * 40) }
    });
  }, [openWindows]);

  const closeDetailWindow = useCallback((nodeId: string) => {
    setOpenWindows(prev => { const s = new Set(prev); s.delete(nodeId); return s; });
  }, []);

  const handleWindowMouseDown = useCallback((e: React.MouseEvent, nodeId: string) => {
    e.stopPropagation();
    e.preventDefault();
    setDraggedWindow(nodeId);
    const startMX = e.clientX, startMY = e.clientY;
    const startWX = windowPositions[nodeId]?.x ?? 120;
    const startWY = windowPositions[nodeId]?.y ?? 120;
    const onMove = (ev: MouseEvent) => setWindowPositions(prev => ({
      ...prev,
      [nodeId]: {
        x: Math.max(0, Math.min(window.innerWidth - 400, startWX + ev.clientX - startMX)),
        y: Math.max(0, Math.min(window.innerHeight - 120, startWY + ev.clientY - startMY)),
      }
    }));
    const onUp = () => { setDraggedWindow(null); document.removeEventListener('mousemove', onMove); document.removeEventListener('mouseup', onUp); };
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  }, [windowPositions]);

  const threatColors: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border-red-500/40",
    high: "bg-orange-500/20 text-orange-400 border-orange-500/40",
    medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/40",
    low: "bg-green-500/20 text-green-400 border-green-500/40",
  };

  return (
    <div ref={containerRef} className="h-full bg-background-tertiary relative overflow-hidden">

      {/* ── Loading overlay ─────────────────────────────────── */}
      {loading && (
        <div className="absolute inset-0 bg-background-tertiary/80 flex items-center justify-center z-50 backdrop-blur-sm">
          <div className="text-center space-y-3">
            <Loader2 className="h-10 w-10 animate-spin text-primary mx-auto" />
            <p className="text-muted-foreground text-sm">Running analysis — graph will appear shortly…</p>
          </div>
        </div>
      )}

      {/* ── Empty state ──────────────────────────────────────── */}
      {!loading && !analysisSessionId && (
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="text-center space-y-3 max-w-sm">
            <Activity className="h-12 w-12 text-muted-foreground/40 mx-auto" />
            <h3 className="text-lg font-semibold text-foreground">No analysis loaded</h3>
            <p className="text-muted-foreground text-sm">Upload a malware sample on the Upload tab to generate an analysis graph.</p>
          </div>
        </div>
      )}

      {/* ── Waiting for analysis ─────────────────────────────── */}
      {!loading && analysisSessionId && nodes.length === 0 && (
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="text-center space-y-3 max-w-sm">
            <Loader2 className="h-10 w-10 animate-spin text-primary/60 mx-auto" />
            <h3 className="text-base font-semibold text-foreground">Waiting for analysis results…</h3>
            <p className="text-muted-foreground text-sm">The graph will populate automatically when the backend finishes.</p>
          </div>
        </div>
      )}

      {/* ── Graph canvas ─────────────────────────────────────── */}
      {analysisSessionId && nodes.length > 0 && (
        <>
          <GraphCanvas
            nodes={nodes}
            connections={connections}
            viewport={viewport}
            selectedNode={selectedNode}
            hoveredNode={hoveredNode}
            draggedNode={draggedNode}
            onNodeSelect={handleNodeSelect}
            onNodeDrag={handleNodeDrag}
            onNodeHover={handleNodeHover}
            onNodeMouseDown={handleNodeMouseDown}
            onViewportChange={handleViewportChange}
            onCanvasClick={handleCanvasClick}
          />

          <GraphControls
            scale={viewport.scale}
            onZoomIn={handleZoomIn}
            onZoomOut={handleZoomOut}
            onReset={handleReset}
          />

          {selectedNode && (
            <NodeDetailPanel
              node={selectedNode}
              position={{ x: 0, y: 0 }}
              scale={viewport.scale}
              offset={viewport.offset}
              onExpand={openDetailWindow}
            />
          )}

          {Array.from(openWindows).map((nodeId, index) => {
            const node = nodes.find(n => n.id === nodeId);
            if (!node) return null;
            return (
              <NodeDetailWindow
                key={nodeId}
                node={node}
                position={windowPositions[nodeId] ?? { x: 120 + index * 40, y: 120 + index * 40 }}
                isDragged={draggedWindow === nodeId}
                onClose={() => closeDetailWindow(nodeId)}
                onDrag={handleWindowMouseDown}
              />
            );
          })}
        </>
      )}

      {/* ── Status bar (top-left) ────────────────────────────── */}
      <div className="absolute top-3 left-3 flex flex-col gap-2 z-20 pointer-events-none">
        {/* Connection pill */}
        <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border backdrop-blur-sm ${connected ? 'bg-green-500/10 text-green-400 border-green-500/30' : 'bg-red-500/10 text-red-400 border-red-500/30'}`}>
          {connected ? <Wifi className="h-3 w-3" /> : <WifiOff className="h-3 w-3" />}
          {connected ? 'Backend connected' : 'Backend offline'}
        </div>

        {/* Threat level */}
        {threatLevel && (
          <div className={`px-2.5 py-1 rounded-full text-xs font-semibold border backdrop-blur-sm ${threatColors[threatLevel] ?? threatColors.low}`}>
            Threat: {threatLevel.toUpperCase()}
          </div>
        )}

        {/* Transient status */}
        {analysisStatus && (
          <div className="bg-primary/10 text-primary border border-primary/20 px-2.5 py-1 rounded-full text-xs backdrop-blur-sm animate-fade-in">
            {analysisStatus}
          </div>
        )}
      </div>

      {/* ── Export Report button (top-right) ─────────────────── */}
      {analysisSessionId && nodes.length > 0 && (
        <div className="absolute top-3 right-3 z-20">
          <button
            onClick={handleExportReport}
            disabled={exporting}
            className={`
              flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-semibold
              border transition-all duration-200 backdrop-blur-sm
              ${exporting
                ? "bg-primary/10 border-primary/20 text-primary/50 cursor-not-allowed"
                : "bg-primary/10 border-primary/30 text-primary hover:bg-primary/20 hover:border-primary/60 hover:shadow-[0_0_12px_rgba(220,38,38,0.3)]"
              }
            `}
          >
            {exporting
              ? <Loader2 className="h-4 w-4 animate-spin" />
              : <FileDown className="h-4 w-4" />
            }
            {exporting ? "Generating…" : "Export Report"}
          </button>
        </div>
      )}

      {/* ── Node/connection count (bottom-left) ─────────────── */}
      {nodes.length > 0 && (
        <div className="absolute bottom-16 left-3 z-20 pointer-events-none">
          <div className="bg-background-secondary/80 border border-border rounded-lg px-3 py-1.5 text-xs text-muted-foreground backdrop-blur-sm">
            {nodes.length} nodes · {connections.length} connections
          </div>
        </div>
      )}

      {/* ── Legend panel (bottom-right) ──────────────────────── */}
      <div className="absolute bottom-3 right-3 z-20">
        <div className="bg-background/85 border border-border rounded-xl backdrop-blur-sm shadow-lg overflow-hidden"
             style={{ minWidth: 168 }}>
          <button
            className="w-full flex items-center justify-between px-3 py-2 text-xs font-semibold text-muted-foreground hover:text-foreground transition-colors"
            onClick={() => setLegendOpen(o => !o)}
          >
            <span>Node Legend</span>
            {legendOpen
              ? <ChevronDown className="h-3 w-3" />
              : <ChevronUp className="h-3 w-3" />}
          </button>
          {legendOpen && (
            <div className="px-3 pb-2.5 space-y-1.5">
              {LEGEND_ITEMS.map(item => (
                <div key={item.type} className="flex items-center gap-2">
                  <LegendShape shape={item.shape} color={item.color} />
                  <span className="text-[11px] text-muted-foreground leading-none">{item.label}</span>
                </div>
              ))}
              <div className="mt-2 pt-2 border-t border-border space-y-1">
                <div className="flex items-center gap-2">
                  <div className="h-0.5 w-4 rounded-full" style={{ background: "#3b82f6", opacity: 0.8 }} />
                  <span className="text-[10px] text-muted-foreground">Network flow</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="h-0.5 w-4 rounded-full" style={{ background: "#ef4444", opacity: 0.8 }} />
                  <span className="text-[10px] text-muted-foreground">Injection flow</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="h-0.5 w-4 rounded-full" style={{ background: "#f97316", opacity: 0.8 }} />
                  <span className="text-[10px] text-muted-foreground">Persistence flow</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="h-0.5 w-4 rounded-full" style={{ background: "#10b981", opacity: 0.8 }} />
                  <span className="text-[10px] text-muted-foreground">Crypto flow</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
