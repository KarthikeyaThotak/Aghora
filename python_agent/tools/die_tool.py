"""
Detect-it-Easy (DiE) Tool Wrapper
"""

import subprocess
import json
import os
import re
from typing import Dict, Optional, Any
from .base import MalwareAnalysisTool


class DetectItEasyTool(MalwareAnalysisTool):
    """Wrapper for Detect-it-Easy (DiE) tool"""
    
    def __init__(self, tool_path: Optional[str] = None):
        super().__init__(tool_path)
        # Default paths for Detect-it-Easy
        self.default_paths = [
            "die.exe",
            "die",
            "/usr/bin/die",
            "C:\\Users\\karth\\Downloads\\die_win64_portable_3.10_x64\\die.exe"
        ]
    
    def find_tool(self) -> Optional[str]:
        """Find Detect-it-Easy executable"""
        if self.tool_path and os.path.exists(self.tool_path):
            return self.tool_path
        
        for path in self.default_paths:
            if os.path.exists(path):
                return path
        
        # Try to find in PATH
        try:
            result = subprocess.run(["which", "die"], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        
        return None
    
    def run(self, file_path: str, output_dir: str) -> Dict[str, Any]:
        """Run Detect-it-Easy on the file"""
        tool_exe = self.find_tool()
        if not tool_exe:
            return {
                "tool": "Detect-it-Easy",
                "status": "error",
                "error": "Detect-it-Easy not found. Please install it or specify the path.",
                "output": ""
            }
        
        try:
            # Run DiE with JSON output if available
            cmd = [tool_exe, "-j", file_path]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            output = result.stdout
            error = result.stderr
            
            # Save output to file
            output_file = os.path.join(output_dir, "die_output.json")
            try:
                # Try to parse as JSON
                json_data = json.loads(output)
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(json_data, f, indent=2, ensure_ascii=False)
                parsed = json_data
            except:
                # If not JSON, save as text
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(output)
                parsed = self.parse_output(output)
            
            return {
                "tool": "Detect-it-Easy",
                "status": "success",
                "output_file": output_file,
                "data": parsed,
                "raw_output": output,
                "error": error if error else None
            }
        except subprocess.TimeoutExpired:
            return {
                "tool": "Detect-it-Easy",
                "status": "timeout",
                "error": "Tool execution timed out",
                "output": ""
            }
        except Exception as e:
            return {
                "tool": "Detect-it-Easy",
                "status": "error",
                "error": str(e),
                "output": ""
            }
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse DiE output"""
        parsed = {
            "detections": [],
            "file_type": "",
            "packer": "",
            "compiler": "",
            "languages": []
        }
        
        # Try to extract information from output
        if "PE" in output:
            parsed["file_type"] = "PE"
        if "ELF" in output:
            parsed["file_type"] = "ELF"
        
        # Extract packer information
        packer_match = re.search(r'packer[:\s]+([^\n]+)', output, re.IGNORECASE)
        if packer_match:
            parsed["packer"] = packer_match.group(1).strip()
        
        return parsed


