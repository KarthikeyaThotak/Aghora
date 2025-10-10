import React from "react";
import { FileText, Network, HardDrive, Shield, AlertTriangle, Zap, Crown } from "lucide-react";
import { GraphNodeProps, NodeType, RiskLevel } from "@/types/graph";
import { truncateFileName } from "@/lib/hashUtils";

const getNodeIcon = (type: NodeType) => {
  switch (type) {
    case "file": return FileText;
    case "network": return Network;
    case "registry": return HardDrive;
    case "process": return Zap;
    case "threat": return AlertTriangle;
    case "system": return Shield;
    case "main": return Crown;
    default: return FileText;
  }
};

const getNodeColor = (riskLevel: RiskLevel) => {
  switch (riskLevel) {
    case "critical": return "hsl(0 84% 60%)"; // destructive
    case "high": return "hsl(25 95% 53%)"; // orange
    case "medium": return "hsl(45 93% 47%)"; // yellow  
    case "low": return "hsl(142 76% 36%)"; // green
    default: return "hsl(var(--muted-foreground))"; // muted
  }
};

export const GraphNode: React.FC<GraphNodeProps> = ({
  node,
  isSelected,
  isHovered,
  isDragged,
  scale,
  onSelect,
  onDrag,
  onHover,
  onMouseDown,
}) => {
  const Icon = getNodeIcon(node.type);
  const nodeColor = getNodeColor(node.details.riskLevel);

  const handleClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    onSelect(node);
  };

  const handleMouseEnter = () => {
    onHover(node.id);
  };

  const handleMouseLeave = () => {
    onHover(null);
  };

  return (
    <g
      transform={`translate(${node.x}, ${node.y})`}
      className={`cursor-pointer transition-all duration-300 ease-smooth ${isDragged ? 'cursor-grabbing' : 'cursor-grab'}`}
      style={{ 
        transformOrigin: '0 0',
        transform: `translate(${node.x}px, ${node.y}px) scale(${isHovered && !isDragged ? 1.15 : isSelected ? 1.05 : 1})`,
        transition: isDragged ? 'none' : 'transform 0.2s ease-out'
      }}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
      onMouseDown={(e) => onMouseDown(e, node.id)}
      onClick={handleClick}
    >
      {/* Outer glow effect */}
      <circle
        cx="0"
        cy="0"
        r={isHovered && !isDragged ? "40" : "35"}
        fill={nodeColor}
        opacity={isHovered && !isDragged ? "0.3" : "0.2"}
        className={isHovered && !isDragged ? "animate-pulse" : ""}
        style={{
          filter: isHovered && !isDragged ? `blur(2px)` : 'blur(1px)',
          transition: isDragged ? 'none' : 'all 0.2s ease'
        }}
      />
      
      {/* Middle glow */}
      {isHovered && !isDragged && (
        <circle
          cx="0"
          cy="0"
          r="30"
          fill={nodeColor}
          opacity="0.4"
          style={{ filter: 'blur(1px)' }}
        />
      )}
      
      {/* Node background */}
      <circle
        cx="0"
        cy="0"
        r="25"
        fill="hsl(var(--card))"
        stroke={nodeColor}
        strokeWidth={isSelected ? "4" : "3"}
        className="transition-all duration-300"
        style={{
          filter: isHovered || isDragged ? `drop-shadow(0 0 15px ${nodeColor})` : 
                  isSelected ? `drop-shadow(0 0 8px ${nodeColor})` : 'none'
        }}
      />
      
      {/* Selection ring */}
      {isSelected && (
        <circle
          cx="0"
          cy="0"
          r="30"
          fill="none"
          stroke={nodeColor}
          strokeWidth="2"
          strokeDasharray="4 4"
          opacity="0.8"
          className="animate-spin"
          style={{ animationDuration: '3s' }}
        />
      )}
      
      {/* Node icon */}
      <foreignObject 
        x="-12" 
        y="-12" 
        width="24" 
        height="24" 
        className="pointer-events-none transition-all duration-300"
        style={{
          transform: isHovered || isDragged ? 'scale(1.2)' : 'scale(1)',
          filter: isHovered || isDragged ? `drop-shadow(0 0 5px ${nodeColor})` : 'none'
        }}
      >
        <Icon
          className="w-6 h-6 transition-all duration-300"
          style={{ 
            color: nodeColor,
            filter: isHovered || isDragged ? 'brightness(1.3)' : 'brightness(1)'
          }}
        />
      </foreignObject>
      
      {/* Node label */}
      <text
        x="0"
        y="45"
        textAnchor="middle"
        className="fill-foreground font-medium pointer-events-none select-none transition-all duration-300"
        style={{ 
          fontSize: isHovered || isDragged ? "14px" : "12px",
          filter: isHovered || isDragged ? `drop-shadow(0 0 3px hsl(var(--foreground)))` : 'none'
        }}
      >
        {node.isMainNode && node.fileName 
          ? truncateFileName(node.fileName, 15)
          : node.label.length > 15 ? node.label.slice(0, 15) + "..." : node.label
        }
      </text>
      
      {/* Hover tooltip */}
      {isHovered && (
        <g>
          <rect
            x="-60"
            y="-80"
            width="120"
            height="30"
            fill="hsl(var(--popover))"
            stroke="hsl(var(--border))"
            strokeWidth="1"
            rx="6"
            className="animate-fade-in"
            style={{
              filter: 'drop-shadow(0 4px 6px rgb(0 0 0 / 0.1))'
            }}
          />
          <text
            x="0"
            y="-68"
            textAnchor="middle"
            className="fill-popover-foreground text-xs font-medium pointer-events-none select-none"
            style={{ fontSize: "10px" }}
          >
            {node.details.riskLevel.toUpperCase()}
          </text>
          <text
            x="0"
            y="-58"
            textAnchor="middle"
            className="fill-muted-foreground text-xs pointer-events-none select-none"
            style={{ fontSize: "9px" }}
          >
            Click to select
          </text>
        </g>
      )}
    </g>
  );
};

// Export utility functions for use in other components
export { getNodeIcon, getNodeColor };
