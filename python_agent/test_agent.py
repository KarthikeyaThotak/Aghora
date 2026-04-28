"""
Test script for the malware analysis agent
Tests all components: tools, AI, API, and visualization
"""

import os
import sys
import requests
import json
import time
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Test configuration
BASE_URL = "http://localhost:8000"
TEST_SESSION_ID = "test_session_" + str(int(time.time()))

def print_section(title):
    """Print a formatted section header"""
    print("\n" + "="*80)
    print(f"  {title}")
    print("="*80)

def test_server_health():
    """Test 1: Server health check"""
    print_section("TEST 1: Server Health Check")
    try:
        response = requests.get(f"{BASE_URL}/")
        response.raise_for_status()
        data = response.json()
        print(f"✓ Server is online")
        print(f"  Status: {data.get('status')}")
        print(f"  Service: {data.get('service')}")
        print(f"  Version: {data.get('version')}")
        return True
    except requests.exceptions.ConnectionError:
        print("✗ Server is not running!")
        print("  Start the server with: python server.py")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def test_tools():
    """Test 2: Check if analysis tools are available"""
    print_section("TEST 2: Analysis Tools Availability")
    
    from malware_tools import MalwareAnalysisToolkit
    
    toolkit = MalwareAnalysisToolkit()
    tools_status = {}
    
    for tool_name, tool in toolkit.tools.items():
        if hasattr(tool, 'find_tool'):
            tool_path = tool.find_tool()
            if tool_path:
                print(f"✓ {tool_name}: Found at {tool_path}")
                tools_status[tool_name] = "available"
            else:
                print(f"⚠ {tool_name}: Not found (will be skipped)")
                tools_status[tool_name] = "not_found"
        else:
            print(f"✓ {tool_name}: Always available")
            tools_status[tool_name] = "available"
    
    return tools_status

def test_file_analysis(file_path=None):
    """Test 3: Analyze a test file"""
    print_section("TEST 3: File Analysis")
    
    if not file_path:
        # Create a simple test file
        test_file = "test_file.txt"
        with open(test_file, 'w') as f:
            f.write("This is a test file for malware analysis.\n")
            f.write("Contains some strings: https://example.com\n")
            f.write("IP address: 192.168.1.1\n")
            f.write("Registry key: HKLM\\Software\\Test\n")
        file_path = test_file
        print(f"Created test file: {file_path}")
    
    if not os.path.exists(file_path):
        print(f"✗ File not found: {file_path}")
        return None
    
    try:
        from malware_tools import MalwareAnalysisToolkit
        
        toolkit = MalwareAnalysisToolkit()
        output_dir = f"test_output_{TEST_SESSION_ID}"
        
        print(f"Analyzing file: {file_path}")
        print(f"Output directory: {output_dir}")
        
        results = toolkit.analyze_file(file_path, output_dir, tools=["fileinfo", "strings"])
        
        print(f"\n✓ Analysis complete!")
        print(f"  Tools run: {list(results.get('tools', {}).keys())}")
        
        for tool_name, tool_result in results.get('tools', {}).items():
            status = tool_result.get('status', 'unknown')
            if status == 'success':
                print(f"  ✓ {tool_name}: Success")
            elif status == 'error':
                print(f"  ✗ {tool_name}: Error - {tool_result.get('error', 'Unknown')}")
            else:
                print(f"  ⚠ {tool_name}: {status}")
        
        return results
    except Exception as e:
        print(f"✗ Error during analysis: {e}")
        import traceback
        traceback.print_exc()
        return None

def test_api_upload():
    """Test 4: Test API file upload"""
    print_section("TEST 4: API File Upload")
    
    # Create a test file
    test_file = "test_upload.txt"
    with open(test_file, 'w') as f:
        f.write("Test file for API upload\n")
        f.write("Contains: https://test.com 192.168.1.1\n")
    
    try:
        with open(test_file, 'rb') as f:
            files = {'file': ('test_upload.txt', f, 'text/plain')}
            data = {
                'sessionId': TEST_SESSION_ID,
                'visualize': 'false'  # Skip visualization for faster test
            }
            
            print(f"Uploading file to {BASE_URL}/api/analysis/upload...")
            response = requests.post(
                f"{BASE_URL}/api/analysis/upload",
                files=files,
                data=data,
                timeout=120
            )
            
            response.raise_for_status()
            result = response.json()
            
            print(f"✓ Upload and analysis successful!")
            print(f"  Session ID: {result.get('sessionId')}")
            print(f"  Status: {result.get('status')}")
            
            if 'results' in result:
                ai_analysis = result['results'].get('ai_analysis', {})
                if ai_analysis:
                    print(f"  Threat Level: {ai_analysis.get('threat_level', 'unknown')}")
            
            return result
    except requests.exceptions.Timeout:
        print("✗ Request timed out (this is normal for large files)")
        return None
    except Exception as e:
        print(f"✗ Error: {e}")
        return None
    finally:
        # Cleanup
        if os.path.exists(test_file):
            os.remove(test_file)

def test_api_chat():
    """Test 5: Test AI chat API"""
    print_section("TEST 5: AI Chat API")
    
    # Check for OpenAI API key
    if not os.getenv("OPENAI_API_KEY"):
        print("⚠ OpenAI API key not set. Skipping chat test.")
        print("  Set it with: export OPENAI_API_KEY='your-key'")
        return None
    
    try:
        test_message = "What tools were used in the analysis?"
        
        print(f"Sending message: '{test_message}'")
        print(f"Session ID: {TEST_SESSION_ID}")
        
        response = requests.post(
            f"{BASE_URL}/api/analysis/chat",
            json={
                "message": test_message,
                "sessionId": TEST_SESSION_ID
            },
            timeout=30
        )
        
        response.raise_for_status()
        result = response.json()
        
        print(f"✓ Chat response received!")
        print(f"  Response: {result.get('response', '')[:200]}...")
        
        return result
    except Exception as e:
        print(f"✗ Error: {e}")
        return None

def test_graph_api():
    """Test 6: Test graph API"""
    print_section("TEST 6: Graph API")
    
    try:
        # Test getting graph
        print(f"Getting graph for session: {TEST_SESSION_ID}")
        response = requests.get(f"{BASE_URL}/api/graph/{TEST_SESSION_ID}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"✓ Graph retrieved")
            print(f"  Nodes: {len(result.get('data', {}).get('nodes', []))}")
            print(f"  Connections: {len(result.get('data', {}).get('connections', []))}")
        elif response.status_code == 404:
            print(f"⚠ No graph found (this is OK if no analysis was run)")
        else:
            response.raise_for_status()
        
        # Test updating graph
        test_nodes = [
            {
                "id": "test_node_1",
                "type": "file",
                "label": "Test Node",
                "x": 100,
                "y": 100,
                "connections": [],
                "details": {
                    "description": "Test node",
                    "riskLevel": "low",
                    "metadata": {}
                }
            }
        ]
        
        print(f"Updating graph with test node...")
        response = requests.post(
            f"{BASE_URL}/api/graph/update",
            json={
                "nodes": test_nodes,
                "connections": [],
                "sessionId": TEST_SESSION_ID
            }
        )
        
        response.raise_for_status()
        result = response.json()
        print(f"✓ Graph updated")
        print(f"  Nodes: {result.get('nodes_count')}")
        
        return True
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def test_websocket():
    """Test 7: Test WebSocket connection"""
    print_section("TEST 7: WebSocket Connection")
    
    try:
        import websockets
        import asyncio
        
        async def test_ws():
            ws_url = BASE_URL.replace("http", "ws") + f"/ws/{TEST_SESSION_ID}"
            print(f"Connecting to: {ws_url}")
            
            async with websockets.connect(ws_url) as websocket:
                print("✓ WebSocket connected")
                
                # Send ping
                await websocket.send(json.dumps({"type": "ping"}))
                response = await websocket.recv()
                data = json.loads(response)
                
                if data.get("type") == "pong":
                    print("✓ Ping/Pong successful")
                else:
                    print(f"⚠ Unexpected response: {data}")
                
                # Get graph state
                await websocket.send(json.dumps({"type": "get_graph"}))
                response = await websocket.recv()
                data = json.loads(response)
                
                if data.get("type") == "graph_state":
                    print("✓ Graph state received")
                else:
                    print(f"⚠ Unexpected response: {data}")
        
        asyncio.run(test_ws())
        return True
    except ImportError:
        print("⚠ websockets library not installed. Skipping WebSocket test.")
        print("  Install with: pip install websockets")
        return None
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def run_all_tests(file_path=None):
    """Run all tests"""
    print("\n" + "="*80)
    print("  MALWARE ANALYSIS AGENT - TEST SUITE")
    print("="*80)
    
    results = {
        "server_health": False,
        "tools": {},
        "file_analysis": False,
        "api_upload": False,
        "api_chat": False,
        "graph_api": False,
        "websocket": False
    }
    
    # Test 1: Server health
    results["server_health"] = test_server_health()
    if not results["server_health"]:
        print("\n⚠ Server is not running. Some tests will be skipped.")
        print("  Start server with: python server.py")
        return results
    
    # Test 2: Tools
    results["tools"] = test_tools()
    
    # Test 3: File analysis
    analysis_results = test_file_analysis(file_path)
    results["file_analysis"] = analysis_results is not None
    
    # Test 4: API upload
    upload_results = test_api_upload()
    results["api_upload"] = upload_results is not None
    
    # Test 5: API chat (requires OpenAI key)
    chat_results = test_api_chat()
    results["api_chat"] = chat_results is not None
    
    # Test 6: Graph API
    results["graph_api"] = test_graph_api()
    
    # Test 7: WebSocket
    ws_result = test_websocket()
    results["websocket"] = ws_result if ws_result is not None else None
    
    # Summary
    print_section("TEST SUMMARY")
    
    total_tests = 0
    passed_tests = 0
    
    for test_name, result in results.items():
        if isinstance(result, dict):
            continue
        total_tests += 1
        if result:
            passed_tests += 1
            print(f"✓ {test_name}")
        elif result is None:
            print(f"⚠ {test_name} (skipped)")
        else:
            print(f"✗ {test_name}")
    
    print(f"\nResults: {passed_tests}/{total_tests} tests passed")
    
    if passed_tests == total_tests:
        print("\n🎉 All tests passed!")
    else:
        print("\n⚠ Some tests failed. Check the output above for details.")
    
    return results

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Test the malware analysis agent")
    parser.add_argument(
        "--file",
        type=str,
        help="Path to file to analyze (optional, will create test file if not provided)"
    )
    parser.add_argument(
        "--server-url",
        type=str,
        default="http://localhost:8000",
        help="Base URL of the server (default: http://localhost:8000)"
    )
    
    args = parser.parse_args()
    BASE_URL = args.server_url
    
    run_all_tests(args.file)

