"""
Example usage of the Chart Agent
Demonstrates how to use the agent to create and update graphs
"""

from agent import ChartAgent, create_example_graph
import time

def main():
    # Initialize the agent
    print("Initializing Chart Agent...")
    agent = ChartAgent(session_id="example_session")
    
    try:
        # Check server health
        print("\n1. Checking server health...")
        health = agent.health_check()
        print(f"   ✓ Server status: {health['status']}")
        print(f"   ✓ Service: {health['service']}")
        print(f"   ✓ Version: {health['version']}")
        
        # Create example graph
        print("\n2. Creating example malware analysis graph...")
        result = create_example_graph(agent)
        print(f"   ✓ Graph created successfully!")
        print(f"   ✓ Nodes: {result['nodes_count']}")
        print(f"   ✓ Connections: {result['connections_count']}")
        
        # Wait a bit
        time.sleep(1)
        
        # Get current graph
        print("\n3. Retrieving current graph...")
        graph = agent.get_graph()
        print(f"   ✓ Graph retrieved successfully!")
        print(f"   ✓ Nodes in graph: {len(graph['data']['nodes'])}")
        print(f"   ✓ Connections in graph: {len(graph['data']['connections'])}")
        
        # Add a new node
        print("\n4. Adding a new node...")
        new_node_result = agent.add_node(
            node_id="dynamic_node_1",
            node_type="process",
            label="suspicious_process.exe",
            x=400,
            y=350,
            details={
                "description": "Suspicious process detected",
                "riskLevel": "high",
                "metadata": {
                    "PID": "1234",
                    "Parent": "malware.exe",
                    "Command Line": "suspicious_process.exe --stealth"
                }
            }
        )
        print(f"   ✓ Node added: {new_node_result['node']['id']}")
        
        # Add a connection from main node to new node
        print("\n5. Adding connection...")
        # First, find the main node ID
        main_node = next((n for n in graph['data']['nodes'] if n.get('isMainNode')), None)
        if main_node:
            conn_result = agent.add_connection(
                connection_id="conn_main_to_process",
                source_id=main_node['id'],
                target_id="dynamic_node_1",
                connection_type="direct"
            )
            print(f"   ✓ Connection added: {conn_result['connection']['id']}")
        else:
            print("   ⚠ Main node not found, skipping connection")
        
        # Wait a bit
        time.sleep(1)
        
        # Get updated graph
        print("\n6. Retrieving updated graph...")
        updated_graph = agent.get_graph()
        print(f"   ✓ Updated graph retrieved!")
        print(f"   ✓ Total nodes: {len(updated_graph['data']['nodes'])}")
        print(f"   ✓ Total connections: {len(updated_graph['data']['connections'])}")
        
        # Display node summary
        print("\n7. Node Summary:")
        for node in updated_graph['data']['nodes']:
            print(f"   - {node['label']} ({node['type']}) at ({node['x']}, {node['y']})")
        
        print("\n✓ All operations completed successfully!")
        print("\nYou can now view the graph in the frontend if it's connected to the same session.")
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        print("\nMake sure the server is running:")
        print("  python python_agent/server.py")

if __name__ == "__main__":
    main()

