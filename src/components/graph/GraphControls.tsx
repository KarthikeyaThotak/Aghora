import React from "react";
import { GraphControlsProps } from "@/types/graph";

export const GraphControls: React.FC<GraphControlsProps> = ({
  scale,
  onZoomIn,
  onZoomOut,
  onReset,
}) => {
  return (
    <div className="absolute top-4 right-4 flex flex-col gap-2">
      <button
        onClick={onZoomIn}
        className="w-10 h-10 rounded-lg bg-background-secondary border border-border hover:bg-accent transition-colors text-foreground text-lg font-bold"
        title="Zoom In"
      >
        +
      </button>
      <button
        onClick={onZoomOut}
        className="w-10 h-10 rounded-lg bg-background-secondary border border-border hover:bg-accent transition-colors text-foreground text-lg font-bold"
        title="Zoom Out"
      >
        −
      </button>
      <button
        onClick={onReset}
        className="w-10 h-10 rounded-lg bg-background-secondary border border-border hover:bg-accent transition-colors text-foreground text-xs font-medium"
        title="Reset View"
      >
        Reset
      </button>
    </div>
  );
};
