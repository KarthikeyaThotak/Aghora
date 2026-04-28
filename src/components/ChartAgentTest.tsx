/**
 * Example component demonstrating how to use the Chart Agent
 * This component can be used to test the Python agent connection
 */

import { useState } from 'react';
import { useChartAgent } from '@/hooks/useChartAgent';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { GraphNode, GraphConnection } from '@/types/graph';

export const ChartAgentTest = () => {
  const [sessionId, setSessionId] = useState('test_session');
  const [baseUrl, setBaseUrl] = useState('http://localhost:8000');
  
  const {
    connected,
    loading,
    error,
    updateGraph,
    addNode,
    addConnection,
    getGraph
  } = useChartAgent({
    baseUrl,
    sessionId,
    useWebSocket: true
  });

  const handleCreateExampleGraph = async () => {
    const nodes: GraphNode[] = [
      {
        id: '1',
        type: 'main',
        label: 'malware.exe',
        x: 300,
        y: 200,
        connections: ['2', '3'],
        isMainNode: true,
        sha256Hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        fileName: 'malware.exe',
        details: {
          description: 'Suspicious executable file detected',
          riskLevel: 'critical',
          metadata: {
            'File Size': '2.3 MB',
            'Hash (SHA256)': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'First Seen': new Date().toLocaleString()
          }
        }
      },
      {
        id: '2',
        type: 'network',
        label: 'TCP 443',
        x: 500,
        y: 100,
        connections: ['4'],
        details: {
          description: 'Outbound HTTPS connection',
          riskLevel: 'high',
          metadata: {
            'Destination': '185.123.45.67',
            'Port': '443',
            'Protocol': 'HTTPS'
          }
        }
      },
      {
        id: '3',
        type: 'registry',
        label: 'HKLM\\Software\\...',
        x: 100,
        y: 300,
        connections: [],
        details: {
          description: 'Registry modification for persistence',
          riskLevel: 'high',
          metadata: {
            'Action': 'Write',
            'Value': 'malware.exe',
            'Type': 'REG_SZ'
          }
        }
      },
      {
        id: '4',
        type: 'threat',
        label: 'C&C Server',
        x: 700,
        y: 150,
        connections: [],
        details: {
          description: 'Command and control server communication',
          riskLevel: 'critical',
          metadata: {
            'IP': '185.123.45.67',
            'Geolocation': 'Russia',
            'Known Threat': 'APT29'
          }
        }
      }
    ];

    const connections: GraphConnection[] = [
      {
        id: 'conn-1-2',
        sourceId: '1',
        targetId: '2',
        type: 'direct'
      },
      {
        id: 'conn-1-3',
        sourceId: '1',
        targetId: '3',
        type: 'direct'
      },
      {
        id: 'conn-2-4',
        sourceId: '2',
        targetId: '4',
        type: 'direct'
      }
    ];

    try {
      await updateGraph(nodes, connections);
      alert('Graph updated successfully!');
    } catch (err) {
      alert(`Error: ${err instanceof Error ? err.message : 'Unknown error'}`);
    }
  };

  const handleAddNode = async () => {
    const newNode: GraphNode = {
      id: `node-${Date.now()}`,
      type: 'file',
      label: 'new_file.exe',
      x: Math.random() * 500 + 100,
      y: Math.random() * 400 + 100,
      connections: [],
      details: {
        description: 'New file node',
        riskLevel: 'medium',
        metadata: {}
      }
    };

    try {
      await addNode(newNode);
      alert('Node added successfully!');
    } catch (err) {
      alert(`Error: ${err instanceof Error ? err.message : 'Unknown error'}`);
    }
  };

  const handleGetGraph = async () => {
    try {
      const graph = await getGraph();
      if (graph) {
        console.log('Current graph:', graph);
        alert(`Graph retrieved: ${graph.nodes.length} nodes, ${graph.connections.length} connections`);
      } else {
        alert('No graph data found');
      }
    } catch (err) {
      alert(`Error: ${err instanceof Error ? err.message : 'Unknown error'}`);
    }
  };

  return (
    <Card className="w-full max-w-2xl mx-auto">
      <CardHeader>
        <CardTitle>Chart Agent Test</CardTitle>
        <CardDescription>
          Test the connection to the Python Chart Agent API
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Connection Status */}
        <div className="flex items-center gap-2">
          <div className={`w-3 h-3 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'}`} />
          <span className="text-sm">
            {connected ? 'Connected' : 'Disconnected'}
          </span>
          {loading && <span className="text-sm text-muted-foreground">(Loading...)</span>}
        </div>

        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {/* Configuration */}
        <div className="space-y-2">
          <Label htmlFor="baseUrl">Base URL</Label>
          <Input
            id="baseUrl"
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder="http://localhost:8000"
          />
        </div>

        <div className="space-y-2">
          <Label htmlFor="sessionId">Session ID</Label>
          <Input
            id="sessionId"
            value={sessionId}
            onChange={(e) => setSessionId(e.target.value)}
            placeholder="test_session"
          />
        </div>

        {/* Actions */}
        <div className="flex flex-wrap gap-2">
          <Button
            onClick={handleCreateExampleGraph}
            disabled={!connected || loading}
          >
            Create Example Graph
          </Button>
          <Button
            onClick={handleAddNode}
            disabled={!connected || loading}
            variant="outline"
          >
            Add Random Node
          </Button>
          <Button
            onClick={handleGetGraph}
            disabled={!connected || loading}
            variant="outline"
          >
            Get Current Graph
          </Button>
        </div>

        {/* Instructions */}
        <div className="mt-4 p-4 bg-muted rounded-lg">
          <h4 className="font-semibold mb-2">Instructions:</h4>
          <ol className="list-decimal list-inside space-y-1 text-sm text-muted-foreground">
            <li>Start the Python server: <code className="bg-background px-1 rounded">python python_agent/server.py</code></li>
            <li>Make sure the server is running on {baseUrl}</li>
            <li>Click "Create Example Graph" to send test data</li>
            <li>Check the browser console for WebSocket messages</li>
          </ol>
        </div>
      </CardContent>
    </Card>
  );
};


