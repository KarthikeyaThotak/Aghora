import React, { useCallback } from "react";
import { Card } from "../ui/card";
import { NodeDetailWindowProps } from "@/types/graph";
import { getNodeIcon, getNodeColor } from "./GraphNode";
import { formatSHA256ForDisplay } from "@/lib/hashUtils";

export const NodeDetailWindow: React.FC<NodeDetailWindowProps> = ({
  node,
  position,
  isDragged,
  onClose,
  onDrag,
}) => {
  const Icon = getNodeIcon(node.type);
  const nodeColor = getNodeColor(node.details.riskLevel);

  const handleWindowMouseDown = useCallback((e: React.MouseEvent) => {
    e.stopPropagation();
    e.preventDefault();
    onDrag(e, node.id);
  }, [onDrag, node.id]);

  return (
    <Card
      className={`fixed w-96 max-h-[80vh] bg-background border-border shadow-xl overflow-hidden animate-scale-in ${isDragged ? 'cursor-grabbing' : ''}`}
      style={{
        left: position.x,
        top: position.y,
        zIndex: 100
      }}
    >
      {/* Close button positioned above title */}
      <div className="absolute -top-2 -right-2 z-10">
        <button
          onClick={onClose}
          className="w-8 h-8 rounded-full bg-destructive hover:bg-destructive/80 transition-colors flex items-center justify-center text-destructive-foreground shadow-lg"
        >
          ×
        </button>
      </div>

      {/* Draggable header */}
      <div 
        className={`flex items-center gap-3 p-4 border-b border-border bg-background-secondary cursor-grab ${isDragged ? 'cursor-grabbing' : 'cursor-grab'}`}
        onMouseDown={handleWindowMouseDown}
      >
        <Icon className="w-6 h-6 flex-shrink-0" style={{ color: nodeColor }} />
        <div className="min-w-0 flex-1">
          <div className="overflow-x-auto">
            <h3 className="font-semibold text-foreground whitespace-nowrap">{node.label}</h3>
          </div>
          <p className="text-sm text-muted-foreground capitalize">{node.type}</p>
        </div>
      </div>
      
      <div className="p-4 overflow-y-auto max-h-[calc(80vh-80px)]">
        <div className="space-y-4">
          
          <div>
            <p className="text-sm font-medium text-muted-foreground mb-2">Description</p>
            <div className="overflow-x-auto">
              <p className="text-sm text-foreground leading-relaxed whitespace-nowrap">{node.details.description}</p>
            </div>
          </div>
          
          <div>
            <p className="text-sm font-medium text-muted-foreground mb-2">Risk Level</p>
            <span
              className="inline-block px-3 py-1 rounded-full text-sm font-medium uppercase"
              style={{
                backgroundColor: nodeColor + "20",
                color: nodeColor
              }}
            >
              {node.details.riskLevel}
            </span>
          </div>
          
          <div>
            <p className="text-sm font-medium text-muted-foreground mb-3">Metadata</p>
            <div className="space-y-3">
              {Object.entries(node.details.metadata).map(([key, value]) => (
                <div key={key} className="bg-background-tertiary rounded-lg p-3">
                  <p className="text-xs font-medium text-muted-foreground mb-1">{key}</p>
                  <div className="overflow-x-auto">
                    <p className="text-sm text-foreground font-mono whitespace-nowrap">{value}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </Card>
  );
};
