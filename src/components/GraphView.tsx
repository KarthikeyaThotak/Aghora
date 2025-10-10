import { useState, useCallback, useEffect } from "react";
import { GraphNode, GraphConnection, GraphViewport } from "@/types/graph";
import { GraphCanvas, GraphControls, NodeDetailPanel, NodeDetailWindow } from "./graph";
import { mockNodes, mockConnections } from "@/data/mockGraphData";
import { truncateFileName } from "@/lib/hashUtils";
import FirestoreService, { AnalysisSession, GraphNode as FirestoreGraphNode } from "@/lib/firestoreService";
import { useAuth } from "@/contexts/AuthContext";

interface GraphViewProps {
  analysisSessionId?: string; // Current analysis session to display
  uploadedFiles?: Array<{
    id: string;
    name: string;
    sha256Hash: string;
    analysisSessionId: string;
  }>;
}

export const GraphView = ({ analysisSessionId, uploadedFiles = [] }: GraphViewProps) => {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [draggedNode, setDraggedNode] = useState<string | null>(null);
  const [viewport, setViewport] = useState<GraphViewport>({ scale: 1, offset: { x: 0, y: 0 } });
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [connections, setConnections] = useState<GraphConnection[]>([]);
  const [loading, setLoading] = useState(false);
  const [currentSession, setCurrentSession] = useState<AnalysisSession | null>(null);
  const { user } = useAuth();

  // Load analysis session and graph nodes
  useEffect(() => {
    const loadAnalysisSession = async () => {
      if (!analysisSessionId || !user) {
        setNodes([]);
        setConnections([]);
        setCurrentSession(null);
        return;
      }

      setLoading(true);
      console.log('Loading analysis session:', analysisSessionId);
      try {
        // Load analysis session
        const session = await FirestoreService.getAnalysisSession(analysisSessionId, user.uid);
        if (session) {
          console.log('Analysis session loaded:', session);
          setCurrentSession(session);
          
          // Load graph nodes for this session
          const graphNodes = await FirestoreService.getSessionGraphNodes(analysisSessionId, user.uid);
          console.log('Graph nodes loaded:', graphNodes);
          
          // Convert FirestoreGraphNode to GraphNode
          const convertedNodes: GraphNode[] = graphNodes.map(node => ({
            id: node.id,
            type: node.type === 'main' ? 'main' : 
                 node.type === 'sub' ? 'file' : 
                 node.type === 'connection' ? 'network' : 'file',
            label: node.label,
            x: node.x,
            y: node.y,
            connections: [], // Initialize empty connections array
            isMainNode: node.type === 'main',
            sha256Hash: node.sha256Hash,
            fileName: node.fileName,
            details: node.details || {
              description: `Node for ${node.fileName || 'Unknown'}`,
              riskLevel: 'low',
              metadata: {}
            }
          }));
          
          setNodes(convertedNodes);
          setConnections([]); // Start with empty connections for new sessions
        } else {
          console.warn('Analysis session not found:', analysisSessionId);
          setNodes([]);
          setConnections([]);
          setCurrentSession(null);
        }
      } catch (error) {
        console.error('Error loading analysis session:', error);
        setNodes([]);
        setConnections([]);
        setCurrentSession(null);
      } finally {
        setLoading(false);
      }
    };

    loadAnalysisSession();
  }, [analysisSessionId, user]);
  const [openWindows, setOpenWindows] = useState<Set<string>>(new Set());
  const [windowPositions, setWindowPositions] = useState<Record<string, { x: number; y: number }>>({});
  const [draggedWindow, setDraggedWindow] = useState<string | null>(null);

  // Event handlers
  const handleNodeSelect = useCallback((node: GraphNode) => {
    setSelectedNode(node);
  }, []);

  const handleNodeDrag = useCallback((nodeId: string, newX: number, newY: number) => {
    setNodes(prevNodes => 
      prevNodes.map(node => 
        node.id === nodeId 
          ? { ...node, x: newX, y: newY }
          : node
      )
    );
  }, []);

  const handleNodeHover = useCallback((nodeId: string | null) => {
    setHoveredNode(nodeId);
  }, []);

  const handleNodeMouseDown = useCallback((e: React.MouseEvent, nodeId: string) => {
    setDraggedNode(nodeId);
  }, []);

  const handleViewportChange = useCallback((newViewport: GraphViewport) => {
    setViewport(newViewport);
  }, []);

  const handleCanvasClick = useCallback(() => {
    setSelectedNode(null);
  }, []);

  const handleZoomIn = useCallback(() => {
    setViewport(prev => ({ ...prev, scale: Math.min(3, prev.scale + 0.2) }));
  }, []);

  const handleZoomOut = useCallback(() => {
    setViewport(prev => ({ ...prev, scale: Math.max(0.5, prev.scale - 0.2) }));
  }, []);

  const handleReset = useCallback(() => {
    setViewport({ scale: 1, offset: { x: 0, y: 0 } });
  }, []);

  const openDetailWindow = useCallback((nodeId: string) => {
    setOpenWindows(prev => new Set([...prev, nodeId]));
    // Set initial position if not set
    if (!windowPositions[nodeId]) {
      const windowCount = openWindows.size;
      setWindowPositions(prev => ({
        ...prev,
        [nodeId]: { x: 100 + (windowCount * 50), y: 100 + (windowCount * 50) }
      }));
    }
  }, [openWindows, windowPositions]);

  const closeDetailWindow = useCallback((nodeId: string) => {
    setOpenWindows(prev => {
      const newSet = new Set(prev);
      newSet.delete(nodeId);
      return newSet;
    });
  }, []);

  const handleWindowMouseDown = useCallback((e: React.MouseEvent, nodeId: string) => {
    e.stopPropagation();
    e.preventDefault();
    setDraggedWindow(nodeId);
    
    const startMouseX = e.clientX;
    const startMouseY = e.clientY;
    const startWindowX = windowPositions[nodeId]?.x || 100;
    const startWindowY = windowPositions[nodeId]?.y || 100;
    
    const handleMouseMove = (e: MouseEvent) => {
      const deltaX = e.clientX - startMouseX;
      const deltaY = e.clientY - startMouseY;
      
      setWindowPositions(prev => ({
        ...prev,
        [nodeId]: {
          x: Math.max(0, Math.min(window.innerWidth - 384, startWindowX + deltaX)),
          y: Math.max(0, Math.min(window.innerHeight - 100, startWindowY + deltaY))
        }
      }));
    };
    
    const handleMouseUp = () => {
      setDraggedWindow(null);
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };
    
    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
  }, [windowPositions]);

  return (
    <div className="h-full bg-background-tertiary relative overflow-hidden">
      {loading && (
        <div className="absolute inset-0 bg-background-tertiary/80 flex items-center justify-center z-50">
          <div className="text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto mb-4"></div>
            <p className="text-muted-foreground">Loading analysis session...</p>
          </div>
        </div>
      )}
      
      {!loading && !analysisSessionId && (
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="text-center">
            <h3 className="text-lg font-semibold text-foreground mb-2">No Analysis Session</h3>
            <p className="text-muted-foreground">Upload a file to start a new analysis session</p>
          </div>
        </div>
      )}

      {!loading && analysisSessionId && (
        <>
          {/* Session Info Header */}
          {currentSession && (
            <div className="absolute top-4 left-4 bg-background-secondary/90 backdrop-blur-sm border border-border rounded-lg p-3 z-10">
              <div className="text-sm font-semibold text-foreground">{currentSession.fileName}</div>
              <div className="text-xs text-muted-foreground">
                Session: {analysisSessionId} | Status: {currentSession.status}
              </div>
              <div className="text-xs text-muted-foreground">
                Nodes: {nodes.length} | Connections: {connections.length}
              </div>
            </div>
          )}

          {/* Graph Canvas */}
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

          {/* Controls */}
          <GraphControls
            scale={viewport.scale}
            onZoomIn={handleZoomIn}
            onZoomOut={handleZoomOut}
            onReset={handleReset}
          />

          {/* Node Details Panel */}
          {selectedNode && (
            <NodeDetailPanel
              node={selectedNode}
              position={{ x: 0, y: 0 }} // Position is calculated inside the component
              scale={viewport.scale}
              offset={viewport.offset}
              onExpand={openDetailWindow}
            />
          )}

          {/* Detail Windows */}
          {Array.from(openWindows).map((nodeId, index) => {
            const node = nodes.find(n => n.id === nodeId);
            if (!node) return null;

            const position = windowPositions[nodeId] || { x: 100 + (index * 50), y: 100 + (index * 50) };
            const isDragged = draggedWindow === nodeId;
            
            return (
              <NodeDetailWindow
                key={nodeId}
                node={node}
                position={position}
                isDragged={isDragged}
                onClose={() => closeDetailWindow(nodeId)}
                onDrag={handleWindowMouseDown}
              />
            );
          })}
        </>
      )}
    </div>
  );
};