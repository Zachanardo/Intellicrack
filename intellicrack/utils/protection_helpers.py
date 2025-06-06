"""Common protection bypass helper functions."""

from typing import Dict, List, Any

def create_bypass_result() -> Dict[str, Any]:
    """Create standard bypass result structure.
    
    Returns:
        dict: Standard result dictionary for bypass operations
    """
    return {
        "success": False,
        "methods_applied": [],
        "errors": []
    }

def add_bypass_method(result: Dict[str, Any], method_name: str) -> None:
    """Add a successful bypass method to results.
    
    Args:
        result: Bypass result dictionary
        method_name: Name of the bypass method
    """
    if "methods_applied" not in result:
        result["methods_applied"] = []
    result["methods_applied"].append(method_name)

def add_bypass_error(result: Dict[str, Any], error: str) -> None:
    """Add an error to bypass results.
    
    Args:
        result: Bypass result dictionary
        error: Error message
    """
    if "errors" not in result:
        result["errors"] = []
    result["errors"].append(error)

def finalize_bypass_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """Finalize bypass result by setting success flag.
    
    Args:
        result: Bypass result dictionary
        
    Returns:
        dict: Finalized result dictionary
    """
    result["success"] = len(result.get("methods_applied", [])) > 0
    return result