"""
Subprocess executor for running reconnaissance tools safely
With Python-based fallbacks for Windows compatibility
"""

import subprocess
import shlex
import shutil
import time
import os
from typing import Tuple, Optional, List, Dict, Any
from app.core.config import settings


class ToolExecutor:
    """Safely execute reconnaissance tools with timeout and error handling"""
    
    # Track which CLI tools are available
    _cli_tools_available: Dict[str, bool] = {}
    
    @classmethod
    def is_tool_available(cls, tool_name: str) -> bool:
        """Check if a CLI tool is available on the system"""
        if tool_name not in cls._cli_tools_available:
            cls._cli_tools_available[tool_name] = shutil.which(tool_name) is not None
        return cls._cli_tools_available[tool_name]
    
    @staticmethod
    def execute(
        command: List[str],
        timeout: Optional[int] = None
    ) -> Tuple[str, str, int, float]:
        """
        Execute a command safely with timeout
        
        Args:
            command: List of command arguments (never use shell=True)
            timeout: Timeout in seconds (default from settings)
            
        Returns:
            Tuple of (stdout, stderr, return_code, execution_time)
        """
        if timeout is None:
            timeout = settings.DEFAULT_TIMEOUT
        
        # Enforce max timeout
        timeout = min(timeout, settings.MAX_TIMEOUT)
        
        start_time = time.time()
        
        try:
            # Execute without shell for security
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                text=True
            )
            
            # Wait with timeout
            stdout, stderr = process.communicate(timeout=timeout)
            return_code = process.returncode
            
        except subprocess.TimeoutExpired:
            # Kill process if timeout
            process.kill()
            stdout, stderr = process.communicate()
            return_code = -1
            stderr = f"Execution timed out after {timeout} seconds\n{stderr}"
            
        except FileNotFoundError:
            # Tool not found
            tool_name = command[0] if command else "unknown"
            return (
                "",
                f"CLI_TOOL_NOT_FOUND:{tool_name}",
                127,
                0.0
            )
            
        except Exception as e:
            return (
                "",
                f"Execution error: {str(e)}",
                1,
                0.0
            )
        
        execution_time = time.time() - start_time
        
        return stdout, stderr, return_code, execution_time
    
    @staticmethod
    def build_command(tool_path: str, args: List[str]) -> List[str]:
        """
        Build a command list from tool path and arguments
        
        Args:
            tool_path: Path or name of the tool
            args: List of arguments
            
        Returns:
            Complete command as list
        """
        command = [tool_path]
        command.extend(args)
        return command
    
    @staticmethod
    def parse_command_string(command_string: str) -> List[str]:
        """
        Safely parse a command string into arguments
        Uses shlex to properly handle quotes and escaping
        
        Args:
            command_string: Command string to parse
            
        Returns:
            List of command arguments
        """
        return shlex.split(command_string)
    

