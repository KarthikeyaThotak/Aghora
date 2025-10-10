import { LucideIcon } from "lucide-react";

export type NodeType = "file" | "network" | "registry" | "process" | "threat" | "system" | "main";
export type RiskLevel = "low" | "medium" | "high" | "critical";

export interface GraphNode {
  id: string;
  type: NodeType;
  label: string;
  x: number;
  y: number;
  connections: string[];
  isMainNode?: boolean; // Flag to identify the main node (tree root)
  sha256Hash?: string; // SHA256 hash for file nodes
  fileName?: string; // Original file name for file nodes
  details: {
    description: string;
    riskLevel: RiskLevel;
    metadata: Record<string, string>;
  };
}

export interface GraphConnection {
  id: string;
  sourceId: string;
  targetId: string;
  type?: "direct" | "bidirectional";
  weight?: number;
}

export interface GraphViewport {
  scale: number;
  offset: { x: number; y: number };
}

export interface GraphNodeProps {
  node: GraphNode;
  isSelected: boolean;
  isHovered: boolean;
  isDragged: boolean;
  scale: number;
  onSelect: (node: GraphNode) => void;
  onDrag: (nodeId: string, x: number, y: number) => void;
  onHover: (nodeId: string | null) => void;
  onMouseDown: (e: React.MouseEvent, nodeId: string) => void;
}

export interface GraphCanvasProps {
  nodes: GraphNode[];
  connections: GraphConnection[];
  viewport: GraphViewport;
  selectedNode: GraphNode | null;
  hoveredNode: string | null;
  draggedNode: string | null;
  onNodeSelect: (node: GraphNode) => void;
  onNodeDrag: (nodeId: string, x: number, y: number) => void;
  onNodeHover: (nodeId: string | null) => void;
  onNodeMouseDown: (e: React.MouseEvent, nodeId: string) => void;
  onViewportChange: (viewport: GraphViewport) => void;
  onCanvasClick: () => void;
}

export interface GraphControlsProps {
  scale: number;
  onZoomIn: () => void;
  onZoomOut: () => void;
  onReset: () => void;
}

export interface NodeDetailWindowProps {
  node: GraphNode;
  position: { x: number; y: number };
  isDragged: boolean;
  onClose: () => void;
  onDrag: (e: React.MouseEvent, nodeId: string) => void;
}

export interface NodeDetailPanelProps {
  node: GraphNode;
  position: { x: number; y: number };
  scale: number;
  offset: { x: number; y: number };
  onExpand: (nodeId: string) => void;
}

export interface GraphUtils {
  getNodeIcon: (type: NodeType) => LucideIcon;
  getNodeColor: (riskLevel: RiskLevel) => string;
  getConnectionColor: (sourceNode: GraphNode, targetNode: GraphNode, isHighlighted: boolean) => string;
}
