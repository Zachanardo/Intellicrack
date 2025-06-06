"""Common process execution helper functions."""

import subprocess
from typing import List, Optional, Tuple

def run_process_with_output(cmd: List[str], encoding: str = 'utf-8', 
                          timeout: Optional[int] = None) -> Tuple[int, str, str]:
    """Run a process and capture stdout/stderr.
    
    Args:
        cmd: Command list to execute
        encoding: Text encoding for output
        timeout: Optional timeout in seconds
        
    Returns:
        tuple: (return_code, stdout, stderr)
    """
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding=encoding,
            errors='replace'
        )
        
        stdout, stderr = process.communicate(timeout=timeout)
        return process.returncode, stdout, stderr
        
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        return -1, stdout, "Process timed out"
    except Exception as e:
        return -1, "", str(e)

def run_ghidra_process(cmd: List[str]) -> Tuple[int, str, str]:
    """Run Ghidra subprocess with standard configuration.
    
    Args:
        cmd: Ghidra command list
        
    Returns:
        tuple: (return_code, stdout, stderr)
    """
    return run_process_with_output(cmd, encoding='utf-8')