"""
PE-Studio Tool Wrapper
"""

import subprocess
import json
import os
from typing import Dict, Optional, Any
from .base import MalwareAnalysisTool


class PEStudioTool(MalwareAnalysisTool):
    """Wrapper for PE-Studio tool"""
    
    def __init__(self, tool_path: Optional[str] = None):
        super().__init__(tool_path)
        self.default_paths = [
            "pestudio.exe",
            "pestudio",
            "/usr/bin/pestudio",
            r"C:\Users\karth\Downloads\pestudio\pestudio\pestudio.exe"
        ]
    
    def find_tool(self) -> Optional[str]:
        """Find PE-Studio executable"""
        if self.tool_path and os.path.exists(self.tool_path):
            return self.tool_path
        
        for path in self.default_paths:
            if os.path.exists(path):
                return path
        
        return None
    
    def run(self, file_path: str, output_dir: str) -> Dict[str, Any]:
        """Run PE-Studio on the file"""
        tool_exe = self.find_tool()
        if not tool_exe:
            return {
                "tool": "PE-Studio",
                "status": "error",
                "error": "PE-Studio not found. Please install it or specify the path.",
                "output": ""
            }
        
        try:
            # PE-Studio command line options
            output_file = os.path.join(output_dir, "pestudio_output.json")
            cmd = [tool_exe, "-j", file_path, "-o", output_file]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            output = result.stdout
            error = result.stderr
            
            # Try to read JSON output
            parsed = {}
            if os.path.exists(output_file):
                try:
                    with open(output_file, 'r', encoding='utf-8') as f:
                        parsed = json.load(f)
                except:
                    parsed = self.parse_output(output)
            else:
                parsed = self.parse_output(output)
            
            return {
                "tool": "PE-Studio",
                "status": "success",
                "output_file": output_file,
                "data": parsed,
                "raw_output": output,
                "error": error if error else None
            }
        except subprocess.TimeoutExpired:
            return {
                "tool": "PE-Studio",
                "status": "timeout",
                "error": "Tool execution timed out",
                "output": ""
            }
        except Exception as e:
            return {
                "tool": "PE-Studio",
                "status": "error",
                "error": str(e),
                "output": ""
            }
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse PE-Studio output"""
        return {
            "sections": [],
            "imports": [],
            "exports": [],
            "strings": [],
            "suspicious": []
        }


