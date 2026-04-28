"""
Malware Analysis Toolkit - Orchestrates multiple analysis tools
"""

import os
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
from .die_tool import DetectItEasyTool
from .pestudio_tool import PEStudioTool
from .strings_tool import StringsTool
from .fileinfo_tool import FileInfoTool


class MalwareAnalysisToolkit:
    """Orchestrates multiple malware analysis tools"""
    
    def __init__(self, tools_config: Optional[Dict[str, str]] = None):
        """
        Initialize toolkit with tool configurations
        
        Args:
            tools_config: Dict mapping tool names to their paths
        """
        self.tools_config = tools_config or {}
        self.tools = {
            "die": DetectItEasyTool(self.tools_config.get("die")),
            "pestudio": PEStudioTool(self.tools_config.get("pestudio")),
            "strings": StringsTool(self.tools_config.get("strings")),
            "fileinfo": FileInfoTool()
        }
    
    def analyze_file(self, file_path: str, output_dir: str, tools: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Run analysis tools on a file
        
        Args:
            file_path: Path to the file to analyze
            output_dir: Directory to save output files
            tools: List of tool names to run (None = all)
        
        Returns:
            Dictionary with results from all tools
        """
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        tools_to_run = tools or list(self.tools.keys())
        results = {
            "file_path": file_path,
            "analysis_timestamp": datetime.now().isoformat(),
            "tools": {}
        }
        
        for tool_name in tools_to_run:
            if tool_name in self.tools:
                print(f"Running {tool_name}...")
                tool_result = self.tools[tool_name].run(file_path, output_dir)
                results["tools"][tool_name] = tool_result
        
        # Save combined results
        results_file = os.path.join(output_dir, "analysis_results.json")
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        results["results_file"] = results_file
        return results


