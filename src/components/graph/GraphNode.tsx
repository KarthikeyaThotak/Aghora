import React from "react";
import { GraphNodeProps, NodeType, RiskLevel } from "@/types/graph";
import { truncateFileName } from "@/lib/hashUtils";
import {
  Globe, Network, Database, FileText, Shield, Settings,
  AlertTriangle, Code2, Lock, Cpu, Layers, LucideIcon,
} from "lucide-react";

// ── Color palette by node type ─────────────────────────────────────────────────
export const NODE_COLORS: Record<NodeType, string> = {
  main:     "#dc2626",  // red      — primary threat
  network:  "#3b82f6",  // blue     — C2 / network IOC
  registry: "#f59e0b",  // amber    — registry persistence
  file:     "#f59e0b",  // amber    — file artifact
  persist:  "#f97316",  // orange   — persistence cluster
  api:      "#8b5cf6",  // violet   — Win32 API
  inject:   "#ef4444",  // bright red — injection
  crypto:   "#10b981",  // emerald  — encryption
  section:  "#06b6d4",  // cyan     — PE section
  threat:   "#e11d48",  // rose     — generic threat
  process:  "#a78bfa",  // lavender — process
  system:   "#64748b",  // slate    — system
};

// ── Node radius by risk level ──────────────────────────────────────────────────
export function getNodeRadius(risk: RiskLevel, isMain?: boolean): number {
  if (isMain) return 42;
  switch (risk) {
    case "critical": return 30;
    case "high":     return 26;
    case "medium":   return 22;
    default:         return 18;
  }
}

// ── SVG shape generators (all centered at 0,0) ────────────────────────────────
function hexPath(r: number): string {
  const pts = Array.from({ length: 6 }, (_, i) => {
    const a = (Math.PI / 3) * i - Math.PI / 6;
    return `${(r * Math.cos(a)).toFixed(2)},${(r * Math.sin(a)).toFixed(2)}`;
  });
  return `M ${pts.join(" L ")} Z`;
}
function diamondPath(r: number): string {
  const w = (r * 0.72).toFixed(2);
  return `M 0,${-r} L ${w},0 L 0,${r} L ${-w},0 Z`;
}
function squarePath(r: number): string {
  const s = (r * 0.84).toFixed(2);
  const c = (r * 0.18).toFixed(2); // corner cut
  return `M ${-s},${-(+s - +c)} L ${-(+s - +c)},${-s} L ${+s - +c},${-s} L ${s},${-(+s - +c)} L ${s},${+s - +c} L ${+s - +c},${s} L ${-(+s - +c)},${s} L ${-s},${+s - +c} Z`;
}
function pentPath(r: number): string {
  const pts = Array.from({ length: 5 }, (_, i) => {
    const a = (Math.PI * 2 / 5) * i - Math.PI / 2;
    return `${(r * Math.cos(a)).toFixed(2)},${(r * Math.sin(a)).toFixed(2)}`;
  });
  return `M ${pts.join(" L ")} Z`;
}
function triPath(r: number): string {
  return `M 0,${(-r).toFixed(2)} L ${(r * 0.87).toFixed(2)},${(r * 0.5).toFixed(2)} L ${(-r * 0.87).toFixed(2)},${(r * 0.5).toFixed(2)} Z`;
}

function getShape(type: NodeType, r: number): string {
  switch (type) {
    case "main":     return hexPath(r);
    case "network":  return diamondPath(r);
    case "registry": return squarePath(r);
    case "file":     return squarePath(r);
    case "persist":  return squarePath(r);
    case "section":  return squarePath(r);
    case "api":      return hexPath(r);
    case "inject":   return pentPath(r);
    case "process":  return pentPath(r);
    case "crypto":   return triPath(r);
    case "threat":   return triPath(r);
    default:         return hexPath(r);
  }
}

// ── Short type tags shown inside each node ─────────────────────────────────────
const TYPE_TAG: Partial<Record<NodeType, string>> = {
  main:     "⚠",
  network:  "⬡",
  registry: "REG",
  file:     "FILE",
  persist:  "PERS",
  api:      "API",
  inject:   "INJ",
  crypto:   "ENC",
  section:  "SEC",
  threat:   "THR",
  process:  "PRC",
  system:   "SYS",
};

// ── Component ─────────────────────────────────────────────────────────────────
export const GraphNode: React.FC<GraphNodeProps> = ({
  node, isSelected, isHovered, isDragged,
  scale, onSelect, onDrag, onHover, onMouseDown,
}) => {
  const color  = NODE_COLORS[node.type] ?? "#64748b";
  const r      = getNodeRadius(node.details.riskLevel, node.isMainNode);
  const shape  = getShape(node.type, r);
  const isCrit = node.details.riskLevel === "critical" || node.isMainNode;
  const isHigh = node.details.riskLevel === "high";
  const tag    = TYPE_TAG[node.type] ?? node.type.slice(0, 3).toUpperCase();

  const rawLabel = node.isMainNode && node.fileName
    ? truncateFileName(node.fileName, 16)
    : node.label;
  const label = rawLabel.length > 15 ? rawLabel.slice(0, 14) + "…" : rawLabel;

  return (
    // Outer group — positioned at node coords via SVG transform
    <g transform={`translate(${node.x},${node.y})`}
      onMouseEnter={() => onHover(node.id)}
      onMouseLeave={() => onHover(null)}
      onMouseDown={(e) => onMouseDown(e, node.id)}
      onClick={(e) => { e.stopPropagation(); onSelect(node); }}
      style={{ cursor: isDragged ? "grabbing" : "pointer" }}
    >
      {/* Inner group — scale effect centered at node origin (0,0) */}
      <g style={{
        transform: `scale(${isHovered && !isDragged ? 1.18 : isSelected ? 1.06 : 1})`,
        transition: isDragged ? "none" : "transform 0.2s cubic-bezier(.34,1.56,.64,1)",
        transformOrigin: "0 0",
      }}>

        {/* === Outer ambient glow (always present, intensity by risk) === */}
        <circle cx="0" cy="0" r={r + 22}
          fill={color}
          opacity={isCrit ? 0.12 : isHigh ? 0.08 : 0.04}
          style={{ filter: "blur(10px)" }}
        />

        {/* === Critical/main nodes: animated concentric rings === */}
        {isCrit && (
          <>
            <circle cx="0" cy="0" r={r + 18} fill="none"
              stroke={color} strokeWidth="1" opacity="0.3"
              style={{ animation: "ringPulse 2.4s ease-in-out infinite" }} />
            <circle cx="0" cy="0" r={r + 30} fill="none"
              stroke={color} strokeWidth="0.5" opacity="0.15"
              style={{ animation: "ringPulse 2.4s ease-in-out infinite 0.8s" }} />
          </>
        )}

        {/* High nodes: single soft ring */}
        {isHigh && !isCrit && (
          <circle cx="0" cy="0" r={r + 14} fill="none"
            stroke={color} strokeWidth="1" opacity="0.2"
            style={{ animation: "ringPulse 3s ease-in-out infinite" }} />
        )}

        {/* === Hover / select glow boost === */}
        {(isHovered || isSelected) && (
          <circle cx="0" cy="0" r={r + 8}
            fill={color} opacity="0.22"
            style={{ filter: "blur(5px)" }} />
        )}

        {/* === Node body === */}
        <path
          d={shape}
          fill={`${color}14`}
          stroke={color}
          strokeWidth={isSelected ? 3.5 : isHovered ? 2.8 : node.isMainNode ? 2.5 : 2}
          style={{
            filter: isHovered || isDragged
              ? `drop-shadow(0 0 18px ${color})`
              : isSelected
              ? `drop-shadow(0 0 10px ${color})`
              : isCrit
              ? `drop-shadow(0 0 5px ${color}88)`
              : "none",
            transition: isDragged ? "none" : "all 0.2s ease",
          }}
        />

        {/* === Selected: spinning dashed orbit === */}
        {isSelected && (
          <circle cx="0" cy="0" r={r + 10}
            fill="none" stroke={color} strokeWidth="1.5"
            strokeDasharray="6 5" opacity="0.7"
            style={{ animation: "spin 5s linear infinite", transformOrigin: "0 0" }}
          />
        )}

        {/* === Type tag inside the shape === */}
        <text x="0" y="1"
          textAnchor="middle" dominantBaseline="middle"
          fill={color}
          style={{
            fontSize: `${Math.max(7, r * 0.3)}px`,
            fontFamily: "monospace",
            fontWeight: 700,
            letterSpacing: "0.04em",
            pointerEvents: "none",
            userSelect: "none",
            opacity: 0.95,
          }}
        >
          {tag}
        </text>

        {/* === Label below node === */}
        <text x="0" y={r + 15}
          textAnchor="middle"
          fill="hsl(var(--foreground))"
          style={{
            fontSize: isHovered ? "12px" : "11px",
            fontWeight: isHovered ? 600 : 500,
            transition: "font-size 0.15s ease",
            pointerEvents: "none",
            userSelect: "none",
          }}
        >
          {label}
        </text>

        {/* === Hover tooltip === */}
        {isHovered && (
          <g>
            <rect x="-62" y={-(r + 38)} width="124" height="24" rx="5"
              fill="hsl(var(--popover))"
              stroke={color} strokeWidth="1"
              style={{ filter: "drop-shadow(0 4px 12px rgba(0,0,0,0.5))" }}
            />
            <text x="0" y={-(r + 26)}
              textAnchor="middle"
              fill="hsl(var(--popover-foreground))"
              style={{ fontSize: "10px", fontWeight: 600, pointerEvents: "none", userSelect: "none" }}
            >
              {node.details.riskLevel.toUpperCase()} · {node.type.toUpperCase()}
            </text>
          </g>
        )}
      </g>
    </g>
  );
};

// ── Icon map by node type (used by detail panels) ────────────────────────────
export const getNodeIcon = (type: NodeType): LucideIcon => {
  switch (type) {
    case "main":     return AlertTriangle;
    case "network":  return Globe;
    case "registry": return Database;
    case "file":     return FileText;
    case "persist":  return Shield;
    case "api":      return Code2;
    case "inject":   return Cpu;
    case "crypto":   return Lock;
    case "section":  return Layers;
    case "threat":   return AlertTriangle;
    case "process":  return Settings;
    case "system":   return Network;
    default:         return FileText;
  }
};

// Legacy export for GraphCanvas connection coloring
export const getNodeColor = (risk: RiskLevel): string => {
  switch (risk) {
    case "critical": return "#dc2626";
    case "high":     return "#f97316";
    case "medium":   return "#eab308";
    default:         return "#22c55e";
  }
};
