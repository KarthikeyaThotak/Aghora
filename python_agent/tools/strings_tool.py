"""
Strings Tool Wrapper - Extract strings from binary files
"""

import subprocess
import os
import re
from typing import Dict, List, Optional, Any
from .base import MalwareAnalysisTool


class StringsTool(MalwareAnalysisTool):
    """Wrapper for Strings tool (extract strings from binary)"""
    
    def __init__(self, tool_path: Optional[str] = None):
        super().__init__(tool_path)
        # Strings is usually available as 'strings' on Linux/Mac
        # On Windows, might need Sysinternals strings.exe
        self.default_paths = [
            "strings",
            "strings.exe",
            "/usr/bin/strings",
            "C:\\Users\\karth\\Downloads\\Strings\\strings.exe"
        ]
    
    def find_tool(self) -> Optional[str]:
        """Find Strings executable"""
        if self.tool_path and os.path.exists(self.tool_path):
            return self.tool_path
        
        for path in self.default_paths:
            if os.path.exists(path):
                return path
        
        # Try which/where
        try:
            if os.name == 'nt':
                result = subprocess.run(["where", "strings"], capture_output=True, text=True)
            else:
                result = subprocess.run(["which", "strings"], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        
        return None
    
    def run(self, file_path: str, output_dir: str, min_length: int = 4) -> Dict[str, Any]:
        """Extract strings from the file"""
        tool_exe = self.find_tool()
        if not tool_exe:
            return {
                "tool": "Strings",
                "status": "error",
                "error": "Strings tool not found. Please install it or specify the path.",
                "output": ""
            }
        
        try:
            # Run strings with minimum length
            cmd = [tool_exe, "-n", str(min_length), file_path]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            output = result.stdout
            error = result.stderr
            
            # Save output
            output_file = os.path.join(output_dir, "strings_output.txt")
            with open(output_file, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(output)
            
            # Parse strings
            strings_list = [s.strip() for s in output.split('\n') if s.strip()]
            
            # Analyze strings for suspicious patterns
            suspicious = self.analyze_strings(strings_list)
            
            return {
                "tool": "Strings",
                "status": "success",
                "output_file": output_file,
                "data": {
                    "total_strings": len(strings_list),
                    "strings": strings_list[:1000],  # Limit to first 1000
                    "suspicious_patterns": suspicious
                },
                "raw_output": output,
                "error": error if error else None
            }
        except subprocess.TimeoutExpired:
            return {
                "tool": "Strings",
                "status": "timeout",
                "error": "Tool execution timed out",
                "output": ""
            }
        except Exception as e:
            return {
                "tool": "Strings",
                "status": "error",
                "error": str(e),
                "output": ""
            }
    
    def analyze_strings(self, strings: List[str]) -> Dict[str, Any]:
        """Analyze strings for suspicious patterns"""
        suspicious = {
            "urls": [],
            "ips": [],
            "domains": [],
            "file_paths": [],
            "registry_keys": [],
            "api_calls": [],
            "suspicious_keywords": []
        }
        
        # URL pattern
        url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE)
        # IP pattern
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        # Domain pattern
        domain_pattern = re.compile(r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+\b')
        # Registry key pattern
        registry_pattern = re.compile(r'(HKEY_|HKLM|HKCU|HKCR|HKU|HKCC)[\\][^\s]+', re.IGNORECASE)
        # File path pattern
        file_path_pattern = re.compile(r'[A-Z]:[\\][^\s]+|/[^\s]+', re.IGNORECASE)
        
        suspicious_keywords = [
            'malware', 'trojan', 'virus', 'backdoor', 'keylog', 'stealer',
            'ransom', 'crypt', 'encrypt', 'decrypt', 'cmd.exe', 'powershell',
            'reg add', 'reg delete', 'net user', 'net localgroup'
        ]
        
        for s in strings:
            # URLs
            urls = url_pattern.findall(s)
            suspicious["urls"].extend(urls)
            
            # IPs
            ips = ip_pattern.findall(s)
            suspicious["ips"].extend(ips)
            
            # Domains
            domains = domain_pattern.findall(s)
            suspicious["domains"].extend(domains)
            
            # Registry keys
            reg_keys = registry_pattern.findall(s)
            suspicious["registry_keys"].extend(reg_keys)
            
            # File paths
            paths = file_path_pattern.findall(s)
            suspicious["file_paths"].extend(paths)
            
            # Suspicious keywords
            s_lower = s.lower()
            for keyword in suspicious_keywords:
                if keyword in s_lower:
                    suspicious["suspicious_keywords"].append(s)
                    break
        
        # Remove duplicates
        for key in suspicious:
            suspicious[key] = list(set(suspicious[key]))[:50]  # Limit to 50 each
        
        return suspicious


