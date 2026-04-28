"""
File Information Tool - Basic file metadata
"""

import os
import json
import hashlib
from typing import Dict, Any
from datetime import datetime
from .base import MalwareAnalysisTool


class FileInfoTool(MalwareAnalysisTool):
    """Basic file information tool"""
    
    def run(self, file_path: str, output_dir: str) -> Dict[str, Any]:
        """Get basic file information"""
        try:
            stat = os.stat(file_path)
            file_size = stat.st_size
            
            # Calculate hash (simple implementation)
            sha256_hash = ""
            try:
                with open(file_path, 'rb') as f:
                    sha256_hash = hashlib.sha256(f.read()).hexdigest()
            except:
                pass
            
            info = {
                "file_name": os.path.basename(file_path),
                "file_path": file_path,
                "file_size": file_size,
                "file_size_mb": round(file_size / (1024 * 1024), 2),
                "sha256": sha256_hash,
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "extension": os.path.splitext(file_path)[1].lower()
            }
            
            # Save to file
            output_file = os.path.join(output_dir, "file_info.json")
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(info, f, indent=2)
            
            return {
                "tool": "FileInfo",
                "status": "success",
                "output_file": output_file,
                "data": info
            }
        except Exception as e:
            return {
                "tool": "FileInfo",
                "status": "error",
                "error": str(e),
                "output": ""
            }

