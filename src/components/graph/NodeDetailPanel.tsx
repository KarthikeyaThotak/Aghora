import React from "react";
import { Card } from "../ui/card";
import { NodeDetailPanelProps } from "@/types/graph";
import { getNodeIcon, getNodeColor } from "./GraphNode";
import { formatSHA256ForDisplay } from "@/lib/hashUtils";

export const NodeDetailPanel: React.FC<NodeDetailPanelProps> = ({
  node,
  position,
  scale,
  offset,
  onExpand,
}) => {
  const Icon = getNodeIcon(node.type);
  const nodeColor = getNodeColor(node.details.riskLevel);

  return (
    <Card 
      className="absolute w-80 bg-background-secondary border-border shadow-glow-soft overflow-hidden cursor-pointer hover:shadow-lg transition-shadow"
      style={{
        left: Math.min(window.innerWidth - 340, Math.max(20, (node.x * scale) + offset.x + 50)),
        top: Math.min(window.innerHeight - 300, Math.max(20, (node.y * scale) + offset.y - 150)),
        zIndex: 50
      }}
      onClick={() => onExpand(node.id)}
    >
      <div className="p-4">
        <div className="flex items-center gap-3 mb-3">
          <Icon className="w-6 h-6 flex-shrink-0" style={{ color: nodeColor }} />
          <div className="min-w-0 flex-1">
            <div className="overflow-x-auto">
              <h3 className="font-semibold text-foreground whitespace-nowrap">{node.label}</h3>
            </div>
            <p className="text-sm text-muted-foreground capitalize">{node.type}</p>
          </div>
        </div>
        
        <div className="space-y-3">
          {node.isMainNode && node.sha256Hash && (
            <div>
              <p className="text-sm text-muted-foreground mb-1">SHA256 Hash</p>
              <div className="bg-muted/50 p-2 rounded text-xs">
                <p className="font-mono text-xs break-all text-foreground">
                  {formatSHA256ForDisplay(node.sha256Hash)}
                </p>
              </div>
            </div>
          )}
          
          <div>
            <p className="text-sm text-muted-foreground mb-1">Description</p>
            <p className="text-sm text-foreground break-words line-clamp-2">{node.details.description}</p>
          </div>
          
          <div>
            <p className="text-sm text-muted-foreground mb-1">Risk Level</p>
            <span
              className="inline-block px-2 py-1 rounded text-xs font-medium uppercase"
              style={{
                backgroundColor: nodeColor + "20",
                color: nodeColor
              }}
            >
              {node.details.riskLevel}
            </span>
          </div>
          
          <div>
            <p className="text-sm text-muted-foreground mb-2">Metadata</p>
            <div className="space-y-1">
              {Object.entries(node.details.metadata).slice(0, 2).map(([key, value]) => (
                 <div key={key} className="flex justify-between text-xs gap-2">
                   <span className="text-muted-foreground flex-shrink-0">{key}:</span>
                   <div className="overflow-x-auto text-right flex-1">
                     <span className="text-foreground font-mono whitespace-nowrap">{value}</span>
                   </div>
                 </div>
              ))}
              {Object.entries(node.details.metadata).length > 2 && (
                <p className="text-xs text-muted-foreground">... and more</p>
              )}
            </div>
          </div>
          
          <div className="pt-2 border-t border-border">
            <p className="text-xs text-muted-foreground text-center">Click to expand details</p>
          </div>
        </div>
      </div>
    </Card>
  );
};
