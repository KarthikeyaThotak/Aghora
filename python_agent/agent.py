"""
Python Agent for communicating with the frontend chart interface.
This agent can send graph data, nodes, and connections to update the chart.
"""

import requests
import json
from typing import List, Dict, Optional
from datetime import datetime
import uuid

class ChartAgent:
    """Agent for communicating with the Aghora chart interface"""
    
    def __init__(self, base_url: str = "http://localhost:8000", session_id: str = "default"):
        """
        Initialize the chart agent.
        
        Args:
            base_url: Base URL of the FastAPI server
            session_id: Session ID for grouping graph updates
        """
        self.base_url = base_url.rstrip('/')
        self.session_id = session_id
        self.api_url = f"{self.base_url}/api"
    
    def _make_request(self, method: str, endpoint: str, data: Optional[Dict] = None) -> Dict:
        """Make an HTTP request to the API"""
        url = f"{self.api_url}{endpoint}"
        try:
            # Add timeout to prevent hanging
            timeout = 10  # 10 seconds timeout
            
            if method == "GET":
                response = requests.get(url, params=data, timeout=timeout)
            elif method == "POST":
                response = requests.post(url, json=data, timeout=timeout)
            elif method == "DELETE":
                response = requests.delete(url, params=data, timeout=timeout)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            response.raise_for_status()
            return response.json()
        except requests.exceptions.Timeout:
            raise Exception(f"API request timed out after {timeout} seconds: {url}")
        except requests.exceptions.ConnectionError as e:
            raise Exception(f"Failed to connect to API server at {url}. Make sure the server is running.")
        except requests.exceptions.RequestException as e:
            raise Exception(f"API request failed: {e}")
    
    def health_check(self) -> Dict:
        """Check if the API server is online"""
        try:
            response = requests.get(f"{self.base_url}/")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise Exception(f"Server is not available: {e}")
    
    def update_graph(self, nodes: List[Dict], connections: List[Dict]) -> Dict:
        """
        Update the entire graph with new nodes and connections.
        
        Args:
            nodes: List of node dictionaries with required fields:
                - id: str
                - type: str (file, network, registry, process, threat, system, main)
                - label: str
                - x: float
                - y: float
                - connections: List[str] (optional)
                - details: Dict (optional)
            connections: List of connection dictionaries with required fields:
                - id: str
                - sourceId: str
                - targetId: str
                - type: str (optional, default: "direct")
        
        Returns:
            Response from the API
        """
        data = {
            "nodes": nodes,
            "connections": connections,
            "sessionId": self.session_id
        }
        return self._make_request("POST", "/graph/update", data)
    
    def add_node(
        self,
        node_id: str,
        node_type: str,
        label: str,
        x: float,
        y: float,
        connections: Optional[List[str]] = None,
        details: Optional[Dict] = None,
        sha256_hash: Optional[str] = None,
        file_name: Optional[str] = None,
        is_main_node: bool = False
    ) -> Dict:
        """
        Add or update a single node.
        
        Args:
            node_id: Unique identifier for the node
            node_type: Type of node (file, network, registry, process, threat, system, main)
            label: Display label for the node
            x: X coordinate
            y: Y coordinate
            connections: List of connected node IDs
            details: Dictionary with description, riskLevel, and metadata
            sha256_hash: SHA256 hash for file nodes
            file_name: Original file name for file nodes
            is_main_node: Whether this is the main node
        
        Returns:
            Response from the API
        """
        if details is None:
            details = {
                "description": f"Node: {label}",
                "riskLevel": "low",
                "metadata": {}
            }
        
        node = {
            "id": node_id,
            "type": node_type,
            "label": label,
            "x": x,
            "y": y,
            "connections": connections or [],
            "isMainNode": is_main_node,
            "sha256Hash": sha256_hash,
            "fileName": file_name,
            "details": details
        }
        
        data = {
            "node": node,
            "sessionId": self.session_id
        }
        return self._make_request("POST", "/graph/node", data)
    
    def add_connection(
        self,
        connection_id: str,
        source_id: str,
        target_id: str,
        connection_type: str = "direct",
        weight: Optional[float] = None
    ) -> Dict:
        """
        Add or update a connection between nodes.
        
        Args:
            connection_id: Unique identifier for the connection
            source_id: ID of the source node
            target_id: ID of the target node
            connection_type: Type of connection (direct, bidirectional)
            weight: Optional weight for the connection
        
        Returns:
            Response from the API
        """
        connection = {
            "id": connection_id,
            "sourceId": source_id,
            "targetId": target_id,
            "type": connection_type,
            "weight": weight
        }
        
        data = {
            "connection": connection,
            "sessionId": self.session_id
        }
        return self._make_request("POST", "/graph/connection", data)
    
    def delete_node(self, node_id: str) -> Dict:
        """Delete a node from the graph"""
        return self._make_request("DELETE", f"/graph/node/{node_id}", {"session_id": self.session_id})
    
    def delete_connection(self, connection_id: str) -> Dict:
        """Delete a connection from the graph"""
        return self._make_request("DELETE", f"/graph/connection/{connection_id}", {"session_id": self.session_id})
    
    def get_graph(self) -> Dict:
        """Get the current graph state"""
        return self._make_request("GET", f"/graph/{self.session_id}")
    
    def create_malware_analysis_graph(
        self,
        main_file_name: str,
        sha256_hash: str,
        network_connections: Optional[List[Dict]] = None,
        registry_modifications: Optional[List[Dict]] = None,
        file_operations: Optional[List[Dict]] = None,
        threats: Optional[List[Dict]] = None
    ) -> Dict:
        """
        Create a complete malware analysis graph with a main node and related entities.
        
        Args:
            main_file_name: Name of the main file being analyzed
            sha256_hash: SHA256 hash of the file
            network_connections: List of network connection dicts with keys: label, destination, port, protocol
            registry_modifications: List of registry modification dicts with keys: label, path, action, value
            file_operations: List of file operation dicts with keys: label, path, action
            threats: List of threat dicts with keys: label, description, ip, geolocation
        
        Returns:
            Response from the API
        """
        nodes = []
        connections = []
        
        # Create main node
        main_node_id = str(uuid.uuid4())
        nodes.append({
            "id": main_node_id,
            "type": "main",
            "label": main_file_name[:20] + "..." if len(main_file_name) > 20 else main_file_name,
            "x": 300,
            "y": 200,
            "connections": [],
            "isMainNode": True,
            "sha256Hash": sha256_hash,
            "fileName": main_file_name,
            "details": {
                "description": f"Main analysis node for {main_file_name}",
                "riskLevel": "critical",
                "metadata": {
                    "File Name": main_file_name,
                    "SHA256": sha256_hash,
                    "Analysis Time": datetime.now().isoformat()
                }
            }
        })
        
        # Add network connections
        if network_connections:
            y_offset = 100
            for i, net_conn in enumerate(network_connections):
                node_id = str(uuid.uuid4())
                label = net_conn.get("label", f"Network Connection {i+1}")
                nodes.append({
                    "id": node_id,
                    "type": "network",
                    "label": label,
                    "x": 500,
                    "y": y_offset + (i * 80),
                    "connections": [],
                    "details": {
                        "description": f"Network connection: {label}",
                        "riskLevel": net_conn.get("riskLevel", "high"),
                        "metadata": {
                            "Destination": net_conn.get("destination", "Unknown"),
                            "Port": str(net_conn.get("port", "Unknown")),
                            "Protocol": net_conn.get("protocol", "Unknown")
                        }
                    }
                })
                
                # Connect to main node
                conn_id = str(uuid.uuid4())
                connections.append({
                    "id": conn_id,
                    "sourceId": main_node_id,
                    "targetId": node_id,
                    "type": "direct"
                })
        
        # Add registry modifications
        if registry_modifications:
            y_offset = 300
            for i, reg_mod in enumerate(registry_modifications):
                node_id = str(uuid.uuid4())
                label = reg_mod.get("label", f"Registry {i+1}")
                nodes.append({
                    "id": node_id,
                    "type": "registry",
                    "label": label[:40] + "..." if len(label) > 40 else label,
                    "x": 100,
                    "y": y_offset + (i * 80),
                    "connections": [],
                    "details": {
                        "description": f"Registry modification: {label}",
                        "riskLevel": reg_mod.get("riskLevel", "high"),
                        "metadata": {
                            "Path": reg_mod.get("path", "Unknown"),
                            "Action": reg_mod.get("action", "Unknown"),
                            "Value": reg_mod.get("value", "Unknown")
                        }
                    }
                })
                
                # Connect to main node
                conn_id = str(uuid.uuid4())
                connections.append({
                    "id": conn_id,
                    "sourceId": main_node_id,
                    "targetId": node_id,
                    "type": "direct"
                })
        
        # Add file operations
        if file_operations:
            y_offset = 200
            for i, file_op in enumerate(file_operations):
                node_id = str(uuid.uuid4())
                label = file_op.get("label", f"File {i+1}")
                nodes.append({
                    "id": node_id,
                    "type": "file",
                    "label": label[:20] + "..." if len(label) > 20 else label,
                    "x": 200,
                    "y": y_offset + (i * 80),
                    "connections": [],
                    "details": {
                        "description": f"File operation: {label}",
                        "riskLevel": file_op.get("riskLevel", "medium"),
                        "metadata": {
                            "Path": file_op.get("path", "Unknown"),
                            "Action": file_op.get("action", "Unknown")
                        }
                    }
                })
                
                # Connect to main node
                conn_id = str(uuid.uuid4())
                connections.append({
                    "id": conn_id,
                    "sourceId": main_node_id,
                    "targetId": node_id,
                    "type": "direct"
                })
        
        # Add threats
        if threats:
            y_offset = 150
            for i, threat in enumerate(threats):
                node_id = str(uuid.uuid4())
                label = threat.get("label", f"Threat {i+1}")
                nodes.append({
                    "id": node_id,
                    "type": "threat",
                    "label": label,
                    "x": 700,
                    "y": y_offset + (i * 100),
                    "connections": [],
                    "details": {
                        "description": threat.get("description", f"Threat: {label}"),
                        "riskLevel": threat.get("riskLevel", "critical"),
                        "metadata": {
                            "IP": threat.get("ip", "Unknown"),
                            "Geolocation": threat.get("geolocation", "Unknown"),
                            "Known Threat": threat.get("knownThreat", "Unknown")
                        }
                    }
                })
                
                # Connect to network connection if available
                if network_connections and i < len(network_connections):
                    net_node_id = nodes[-len(network_connections) + i]["id"] if network_connections else None
                    if net_node_id:
                        conn_id = str(uuid.uuid4())
                        connections.append({
                            "id": conn_id,
                            "sourceId": net_node_id,
                            "targetId": node_id,
                            "type": "direct"
                        })
        
        return self.update_graph(nodes, connections)


# Example usage and helper functions

def create_example_graph(agent: ChartAgent):
    """Create an example malware analysis graph"""
    return agent.create_malware_analysis_graph(
        main_file_name="suspicious.exe",
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        network_connections=[
            {
                "label": "TCP 443",
                "destination": "185.123.45.67",
                "port": 443,
                "protocol": "HTTPS",
                "riskLevel": "high"
            }
        ],
        registry_modifications=[
            {
                "label": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "path": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "action": "Write",
                "value": "suspicious.exe",
                "riskLevel": "high"
            }
        ],
        file_operations=[
            {
                "label": "temp_file.dll",
                "path": "C:\\Windows\\Temp\\temp_file.dll",
                "action": "Create",
                "riskLevel": "medium"
            }
        ],
        threats=[
            {
                "label": "C&C Server",
                "description": "Command and control server communication",
                "ip": "185.123.45.67",
                "geolocation": "Russia",
                "knownThreat": "APT29",
                "riskLevel": "critical"
            }
        ]
    )


if __name__ == "__main__":
    # Example usage
    agent = ChartAgent(session_id="example_session")
    
    try:
        # Check server health
        print("Checking server health...")
        health = agent.health_check()
        print(f"Server status: {health['status']}")
        
        # Create example graph
        print("\nCreating example malware analysis graph...")
        result = create_example_graph(agent)
        print(f"Graph created: {result['nodes_count']} nodes, {result['connections_count']} connections")
        
        # Get current graph
        print("\nRetrieving current graph...")
        graph = agent.get_graph()
        print(f"Graph retrieved: {len(graph['data']['nodes'])} nodes")
        
    except Exception as e:
        print(f"Error: {e}")
        print("\nMake sure the server is running:")
        print("  python python_agent/server.py")

