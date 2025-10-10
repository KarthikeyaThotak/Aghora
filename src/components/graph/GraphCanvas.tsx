import React, { useRef, useCallback } from "react";
import { GraphCanvasProps } from "@/types/graph";
import { GraphNode } from "./GraphNode";
import { getNodeColor } from "./GraphNode";

export const GraphCanvas: React.FC<GraphCanvasProps> = ({
  nodes,
  connections,
  viewport,
  selectedNode,
  hoveredNode,
  draggedNode,
  onNodeSelect,
  onNodeDrag,
  onNodeHover,
  onNodeMouseDown,
  onViewportChange,
  onCanvasClick,
}) => {
  const svgRef = useRef<SVGSVGElement>(null);

  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    const newScale = Math.max(0.5, Math.min(3, viewport.scale + e.deltaY * -0.001));
    onViewportChange({ ...viewport, scale: newScale });
  }, [viewport, onViewportChange]);

  const handleNodeDrag = useCallback((nodeId: string, newX: number, newY: number) => {
    onNodeDrag(nodeId, newX, newY);
  }, [onNodeDrag]);

  const handleMouseDown = useCallback((e: React.MouseEvent, nodeId: string) => {
    e.stopPropagation();
    e.preventDefault();
    
    const rect = svgRef.current?.getBoundingClientRect();
    if (!rect) return;
    
    const node = nodes.find(n => n.id === nodeId);
    if (!node) return;
    
    // Store initial positions
    const startMouseX = e.clientX;
    const startMouseY = e.clientY;
    const startNodeX = node.x;
    const startNodeY = node.y;
    
    const handleMouseMove = (e: MouseEvent) => {
      // Calculate mouse movement in SVG coordinates
      const mouseX = (e.clientX - startMouseX) / viewport.scale;
      const mouseY = (e.clientY - startMouseY) / viewport.scale;
      
      // Update node position relative to its starting position
      const newX = startNodeX + mouseX;
      const newY = startNodeY + mouseY;
      
      handleNodeDrag(nodeId, newX, newY);
    };
    
    const handleMouseUp = () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };
    
    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
  }, [handleNodeDrag, viewport.scale, nodes]);

  return (
    <svg
      ref={svgRef}
      className="w-full h-full cursor-grab active:cursor-grabbing"
      onWheel={handleWheel}
      onClick={onCanvasClick}
    >
      <g transform={`translate(${viewport.offset.x}, ${viewport.offset.y}) scale(${viewport.scale})`}>
        {/* Connections */}
        {connections.map((connection) => {
          const sourceNode = nodes.find(n => n.id === connection.sourceId);
          const targetNode = nodes.find(n => n.id === connection.targetId);
          
          if (!sourceNode || !targetNode) return null;
          
          const isHighlighted = hoveredNode === sourceNode.id || hoveredNode === targetNode.id;
          
          return (
            <line
              key={connection.id}
              x1={sourceNode.x}
              y1={sourceNode.y}
              x2={targetNode.x}
              y2={targetNode.y}
              stroke={isHighlighted ? getNodeColor(sourceNode.details.riskLevel) : "hsl(var(--primary))"}
              strokeWidth={isHighlighted ? "4" : "2"}
              opacity={isHighlighted ? "0.8" : "0.4"}
              className={isHighlighted ? "animate-pulse" : "transition-all duration-300"}
              style={{
                filter: isHighlighted ? `drop-shadow(0 0 8px ${getNodeColor(sourceNode.details.riskLevel)})` : 'none'
              }}
            />
          );
        })}

        {/* Legacy connections from node.connections for backward compatibility */}
        {nodes.map((node) =>
          node.connections.map((targetId) => {
            const targetNode = nodes.find((n) => n.id === targetId);
            if (!targetNode) return null;
            
            const isHighlighted = hoveredNode === node.id || hoveredNode === targetId;
            
            return (
              <line
                key={`${node.id}-${targetId}`}
                x1={node.x}
                y1={node.y}
                x2={targetNode.x}
                y2={targetNode.y}
                stroke={isHighlighted ? getNodeColor(node.details.riskLevel) : "hsl(var(--primary))"}
                strokeWidth={isHighlighted ? "4" : "2"}
                opacity={isHighlighted ? "0.8" : "0.4"}
                className={isHighlighted ? "animate-pulse" : "transition-all duration-300"}
                style={{
                  filter: isHighlighted ? `drop-shadow(0 0 8px ${getNodeColor(node.details.riskLevel)})` : 'none'
                }}
              />
            );
          })
        )}

        {/* Nodes */}
        {nodes.map((node) => (
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
            onMouseDown={handleMouseDown}
          />
        ))}
      </g>
    </svg>
  );
};
