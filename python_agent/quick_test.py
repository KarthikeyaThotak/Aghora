"""
Quick test script - Simple way to test the agent
"""

import os
import sys
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def main():
    print("="*60)
    print("  QUICK TEST - Malware Analysis Agent")
    print("="*60)
    
    # Check server
    print("\n1. Checking server...")
    try:
        import requests
        response = requests.get("http://localhost:8000/", timeout=2)
        if response.status_code == 200:
            print("   ✓ Server is running")
        else:
            print("   ✗ Server returned error")
            return
    except:
        print("   ✗ Server is not running!")
        print("\n   Start the server first:")
        print("   python server.py")
        return
    
    # Check tools
    print("\n2. Checking analysis tools...")
    try:
        from malware_tools import MalwareAnalysisToolkit
        toolkit = MalwareAnalysisToolkit()
        
        available = []
        missing = []
        
        for name, tool in toolkit.tools.items():
            if hasattr(tool, 'find_tool'):
                if tool.find_tool():
                    available.append(name)
                else:
                    missing.append(name)
            else:
                available.append(name)
        
        print(f"   ✓ Available: {', '.join(available)}")
        if missing:
            print(f"   ⚠ Missing: {', '.join(missing)}")
    except Exception as e:
        print(f"   ✗ Error: {e}")
    
    # Check OpenAI
    print("\n3. Checking OpenAI API key...")
    if os.getenv("OPENAI_API_KEY"):
        print("   ✓ OpenAI API key is set")
    else:
        print("   ⚠ OpenAI API key not set (AI chat will not work)")
        print("   Set it with: export OPENAI_API_KEY='your-key'")
    
    # Test file analysis
    print("\n4. Testing file analysis...")
    test_file = "quick_test_file.txt"
    try:
        # Create test file
        with open(test_file, 'w') as f:
            f.write("Test file for quick test\n")
            f.write("Contains: https://test.com 192.168.1.1\n")
        
        from malware_tools import MalwareAnalysisToolkit
        toolkit = MalwareAnalysisToolkit()
        
        results = toolkit.analyze_file(test_file, "quick_test_output", tools=["fileinfo", "strings"])
        
        if results and "tools" in results:
            print("   ✓ File analysis successful")
            for tool_name, tool_result in results["tools"].items():
                status = tool_result.get("status", "unknown")
                if status == "success":
                    print(f"     ✓ {tool_name}")
                else:
                    print(f"     ✗ {tool_name}: {tool_result.get('error', 'Unknown error')}")
        else:
            print("   ✗ File analysis failed")
    except Exception as e:
        print(f"   ✗ Error: {e}")
    finally:
        # Cleanup
        if os.path.exists(test_file):
            os.remove(test_file)
    
    print("\n" + "="*60)
    print("  Quick test complete!")
    print("="*60)
    print("\nFor comprehensive testing, run:")
    print("  python test_agent.py")
    print("\nFor interactive analysis, run:")
    print("  python example_analysis.py")

if __name__ == "__main__":
    main()

