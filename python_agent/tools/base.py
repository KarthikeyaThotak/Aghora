"""
Base class for malware analysis tools
"""

from typing import Dict, Optional, Any


class MalwareAnalysisTool:
    """Base class for malware analysis tools"""
    
    def __init__(self, tool_path: Optional[str] = None):
        self.tool_path = tool_path
        self.output = ""
        self.error = ""
    
    def run(self, file_path: str, output_dir: str) -> Dict[str, Any]:
        """Run the tool and return results"""
        raise NotImplementedError
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse tool output into structured data"""
        return {"raw_output": output}


