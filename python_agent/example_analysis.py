"""
Example: Complete malware analysis workflow
Demonstrates file analysis, AI chat, and visualization
"""

import os
from dotenv import load_dotenv
from malware_analyzer import MalwareAnalyzer
from agent import ChartAgent

# Load environment variables from .env file
load_dotenv()

def main():
    # Check for OpenAI API key
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("⚠ Warning: OPENAI_API_KEY not set. AI analysis will not work.")
        print("Set it with: export OPENAI_API_KEY='your-key-here'")
        return
    
    # Initialize components
    print("Initializing malware analyzer...")
    chart_agent = ChartAgent(base_url="http://localhost:8000", session_id="example_analysis")
    
    analyzer = MalwareAnalyzer(
        tools_config={
            # Optional: specify tool paths
            # "die": "/path/to/die.exe",
            # "pestudio": "/path/to/pestudio.exe",
            # "strings": "/path/to/strings"
        },
        openai_api_key=api_key,
        chart_agent=chart_agent
    )
    
    # Example: Analyze a file (replace with actual file path)
    file_path = input("Enter path to file to analyze (or press Enter to skip): ").strip()
    
    if not file_path or not os.path.exists(file_path):
        print("\nNo file provided or file not found.")
        print("To analyze a file, run:")
        print("  python example_analysis.py")
        print("  # Then enter a file path when prompted")
        return
    
    session_id = "analysis_" + os.path.basename(file_path).replace(".", "_")
    
    print(f"\nAnalyzing file: {file_path}")
    print(f"Session ID: {session_id}")
    
    # Run analysis
    try:
        results = analyzer.analyze_file(
            file_path=file_path,
            session_id=session_id,
            tools=None,  # Use all available tools
            visualize=True
        )
        
        print("\n" + "="*80)
        print("ANALYSIS COMPLETE")
        print("="*80)
        
        # Display AI analysis
        ai_analysis = results.get("ai_analysis", {})
        print(f"\nThreat Level: {ai_analysis.get('threat_level', 'unknown').upper()}")
        print(f"\nSummary:\n{ai_analysis.get('threat_summary', 'No summary available')}")
        
        print(f"\nKey Findings:")
        for finding in ai_analysis.get("key_findings", []):
            print(f"  - {finding}")
        
        print(f"\nIOCs Found:")
        iocs = ai_analysis.get("iocs", {})
        if iocs.get("ips"):
            print(f"  IPs: {', '.join(iocs['ips'][:5])}")
        if iocs.get("domains"):
            print(f"  Domains: {', '.join(iocs['domains'][:5])}")
        if iocs.get("urls"):
            print(f"  URLs: {len(iocs['urls'])} found")
        
        print(f"\nLog Directory: {results.get('log_directory')}")
        
        # Interactive chat
        print("\n" + "="*80)
        print("AI CHAT - Ask questions about the analysis")
        print("Type 'quit' to exit")
        print("="*80)
        
        while True:
            question = input("\nYour question: ").strip()
            if question.lower() in ['quit', 'exit', 'q']:
                break
            
            if not question:
                continue
            
            print("\nAI: ", end="", flush=True)
            response = analyzer.chat(session_id, question)
            print(response)
        
        print("\n✓ Analysis session complete!")
        
    except Exception as e:
        print(f"\n✗ Error during analysis: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()

