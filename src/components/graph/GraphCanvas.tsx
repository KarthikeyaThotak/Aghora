import React, { useRef, useCallback } from "react";
import { GraphCanvasProps, ConnectionFlowType } from "@/types/graph";
import { GraphNode, NODE_COLORS } from "./GraphNode";

// ── Connection color by flow type ──────────────────────────────────────────────
const CONN_COLORS: Record<string, string> = {
  network:     "#3b82f6",  // blue
  injection:   "#ef4444",  // red
  persistence: "#f97316",  // orange
  api:         "#8b5cf6",  // violet
  section:     "#06b6d4",  // cyan
  crypto:      "#10b981",  // emerald
  direct:      "#94a3b8",  // slate
  bidirectional:"#94a3b8",
};

const FLOW_TYPES = new Set(["network", "injection", "api", "crypto"]);
const CONN_TYPES = Object.keys(CONN_COLORS) as ConnectionFlowType[];

// Cubic bezier path between two points with a gentle curve
function bezierPath(x1: number, y1: number, x2: number, y2: number): string {
  const dx = x2 - x1, dy = y2 - y1;
  const len = Math.sqrt(dx * dx + dy * dy) || 1;
  // Perpendicular offset for the control points
  const nx = -dy / len, ny = dx / len;
  const bend = Math.min(len * 0.28, 70);
  const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
  const cp1x = mx + nx * bend * 0.5, cp1y = my + ny * bend * 0.5;
  return `M ${x1} ${y1} Q ${cp1x} ${cp1y} ${x2} ${y2}`;
}

export const GraphCanvas: React.FC<GraphCanvasProps> = ({
  nodes, connections, viewport,
  selectedNode, hoveredNode, draggedNode,
  onNodeSelect, onNodeDrag, onNodeHover, onNodeMouseDown,
  onViewportChange, onCanvasClick,
}) => {
  const svgRef = useRef<SVGSVGElement>(null);
  const isPanning = useRef(false);
  const panStart = useRef({ x: 0, y: 0, ox: 0, oy: 0 });

  // ── Zoom ──────────────────────────────────────────────────────────────────────
  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    const rect = svgRef.current?.getBoundingClientRect();
    if (!rect) return;
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;
    const delta = e.deltaY < 0 ? 1.1 : 0.91;
    const newScale = Math.max(0.18, Math.min(4, viewport.scale * delta));
    // Zoom toward cursor
    const ox = mouseX - (mouseX - viewport.offset.x) * (newScale / viewport.scale);
    const oy = mouseY - (mouseY - viewport.offset.y) * (newScale / viewport.scale);
    onViewportChange({ scale: newScale, offset: { x: ox, y: oy } });
  }, [viewport, onViewportChange]);

  // ── Pan ───────────────────────────────────────────────────────────────────────
  const handleCanvasMouseDown = useCallback((e: React.MouseEvent) => {
    if (e.button !== 0) return;
    isPanning.current = true;
    panStart.current = { x: e.clientX, y: e.clientY, ox: viewport.offset.x, oy: viewport.offset.y };
    const onMove = (ev: MouseEvent) => {
      if (!isPanning.current) return;
      onViewportChange({
        scale: viewport.scale,
        offset: {
          x: panStart.current.ox + ev.clientX - panStart.current.x,
          y: panStart.current.oy + ev.clientY - panStart.current.y,
        },
      });
    };
    const onUp = () => { isPanning.current = false; document.removeEventListener("mousemove", onMove); document.removeEventListener("mouseup", onUp); };
    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
  }, [viewport, onViewportChange]);

  // ── Node drag ─────────────────────────────────────────────────────────────────
  const handleNodeMouseDown = useCallback((e: React.MouseEvent, nodeId: string) => {
    e.stopPropagation();
    e.preventDefault();
    const node = nodes.find(n => n.id === nodeId);
    if (!node) return;
    const startMX = e.clientX, startMY = e.clientY;
    const startNX = node.x, startNY = node.y;
    const onMove = (ev: MouseEvent) => {
      onNodeDrag(nodeId, startNX + (ev.clientX - startMX) / viewport.scale, startNY + (ev.clientY - startMY) / viewport.scale);
    };
    const onUp = () => { document.removeEventListener("mousemove", onMove); document.removeEventListener("mouseup", onUp); };
    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
  }, [nodes, viewport.scale, onNodeDrag]);

  // ── Render ────────────────────────────────────────────────────────────────────
  return (
    <svg
      ref={svgRef}
      className="w-full h-full select-none"
      onWheel={handleWheel}
      onMouseDown={handleCanvasMouseDown}
      onClick={onCanvasClick}
      style={{ cursor: isPanning.current ? "grabbing" : "default" }}
    >
      <defs>
        {/* Keyframe animations */}
        <style>{`
          @keyframes ringPulse {
            0%,100% { r: var(--r0); opacity: 0.3; }
            50%      { r: var(--r1); opacity: 0.55; }
          }
          @keyframes flowDash {
            from { stroke-dashoffset: 20; }
            to   { stroke-dashoffset: 0; }
          }
          @keyframes spin {
            from { transform: rotate(0deg); }
            to   { transform: rotate(360deg); }
          }
          @keyframes critPulse {
            0%,100% { opacity: 0.3; }
            50%      { opacity: 0.7; }
          }
        `}</style>

        {/* Dot-grid background pattern */}
        <pattern id="dotGrid" width="28" height="28" patternUnits="userSpaceOnUse">
          <circle cx="14" cy="14" r="1.1" fill="hsl(var(--muted-foreground))" opacity="0.18" />
        </pattern>

        {/* Arrow markers — one per connection type */}
        {CONN_TYPES.map(t => (
          <marker key={t} id={`arrow-${t}`}
            viewBox="0 0 10 10" refX="9" refY="5"
            markerWidth="5" markerHeight="5"
            orient="auto-start-reverse"
          >
            <path d="M 0 1 L 9 5 L 0 9 z" fill={CONN_COLORS[t]} opacity="0.85" />
          </marker>
        ))}

        {/* Glow filters */}
        <filter id="glowBlue" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="3" result="blur" />
          <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
      </defs>

      {/* ── Dot grid background (fixed, fills the entire SVG) ──────────────── */}
      <rect width="100%" height="100%" fill="url(#dotGrid)" />

      {/* ── Viewport group (pan + zoom) ─────────────────────────────────────── */}
      <g transform={`translate(${viewport.offset.x},${viewport.offset.y}) scale(${viewport.scale})`}>

        {/* ── Connections ────────────────────────────────────────────────────── */}
        {connections.map(conn => {
          const src = nodes.find(n => n.id === conn.sourceId);
          const tgt = nodes.find(n => n.id === conn.targetId);
          if (!src || !tgt) return null;

          const connType = (conn.type ?? "direct") as string;
          const color = CONN_COLORS[connType] ?? CONN_COLORS.direct;
          const isLit = hoveredNode === src.id || hoveredNode === tgt.id ||
                        selectedNode?.id === src.id || selectedNode?.id === tgt.id;
          const isFlow = FLOW_TYPES.has(connType);
          const weight = conn.weight ?? 1;
          const path = bezierPath(src.x, src.y, tgt.x, tgt.y);

          return (
            <g key={conn.id}>
              {/* Glow underline for lit connections */}
              {isLit && (
                <path d={path} fill="none"
                  stroke={color} strokeWidth={weight * 6}
                  opacity="0.18"
                  style={{ filter: `blur(4px)` }}
                />
              )}
              {/* Main connection line */}
              <path d={path} fill="none"
                stroke={color}
                strokeWidth={isLit ? weight * 3 : weight * 1.8}
                opacity={isLit ? 0.9 : 0.45}
                strokeDasharray={isFlow ? "8 5" : undefined}
                markerEnd={`url(#arrow-${connType})`}
                style={{
                  animation: isFlow ? "flowDash 1s linear infinite" : undefined,
                  transition: isFlow ? "none" : "all 0.25s ease",
                }}
              />
            </g>
          );
        })}

        {/* Legacy node.connections array (backward compat) */}
        {nodes.map(node =>
          node.connections.map(targetId => {
            const tgt = nodes.find(n => n.id === targetId);
            if (!tgt) return null;
            const isLit = hoveredNode === node.id || hoveredNode === targetId;
            const path = bezierPath(node.x, node.y, tgt.x, tgt.y);
            const color = NODE_COLORS[node.type] ?? "#94a3b8";
            return (
              <path key={`${node.id}-${targetId}`} d={path} fill="none"
                stroke={color}
                strokeWidth={isLit ? 3 : 1.8}
                opacity={isLit ? 0.85 : 0.35}
                markerEnd={`url(#arrow-direct)`}
              />
            );
          })
        )}

        {/* ── Nodes (rendered on top of connections) ─────────────────────────── */}
        {nodes.map(node => (
          <GraphNode
            key={node.id}
            node={node}
            isSelected={selectedNode?.id === node.id}
            isHovered={hoveredNode === node.id}
            isDragged={draggedNode === node.id}
            scale={viewport.scale}
            onSelect={onNodeSelect}
            onDrag={onNodeDrag}
            onHover={onNodeHover}
            onMouseDown={handleNodeMouseDown}
          />
        ))}
      </g>
    </svg>
  );
};
