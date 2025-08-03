"""
Ghidra Bridge-Based Integration Module

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import logging
import os
import tempfile
from typing import Any, Dict, List, Tuple, Optional
from pathlib import Path

from ..core.analysis.ghidra_bridge_manager import GhidraBridgeManager, GhidraBridgeError

logger = logging.getLogger(__name__)


def run_ghidra_plugin(ghidra_path: str,
                     project_dir: str,
                     project_name: str,
                     binary_path: str,
                     script_dir: str,
                     script_name: str,
                     app: Any = None,
                     overwrite: bool = True,
                     timeout: int = 300) -> Tuple[int, str, str]:
    """
    Run a Ghidra plugin using bridge-based approach.
    
    This function maintains API compatibility while using the new bridge backend.

    Args:
        ghidra_path: Path to Ghidra executable
        project_dir: Directory for Ghidra project
        project_name: Name of the Ghidra project
        binary_path: Path to binary to analyze
        script_dir: Directory containing the script
        script_name: Name of the script to run
        app: Application instance for logging
        overwrite: Whether to overwrite existing project
        timeout: Timeout in seconds

    Returns:
        Tuple of (return_code, stdout, stderr)
    """
    try:
        if app:
            app.update_output.emit(f"[Ghidra Bridge] Starting analysis of {Path(binary_path).name}")

        logger.info(f"Running Ghidra analysis via bridge: {binary_path}")
        
        # Use bridge manager for analysis
        bridge_manager = GhidraBridgeManager(ghidra_path)
        
        with bridge_manager:
            # Load program
            if not bridge_manager.load_program(binary_path, project_dir):
                error_msg = f"Failed to load program: {binary_path}"
                logger.error(error_msg)
                return 1, "", error_msg
                
            # Perform comprehensive analysis
            results = bridge_manager.analyze_license_patterns()
            functions = bridge_manager.get_functions()
            strings = bridge_manager.get_strings()
            imports = bridge_manager.get_imports()
            
            # Create output summary
            stdout = f"""Ghidra Bridge Analysis Results:
Program: {Path(binary_path).name}
Functions analyzed: {len(functions)}
Strings extracted: {len(strings)}
Imports found: {len(imports)}
License functions: {len(results.get('license_functions', []))}
License strings: {len(results.get('license_strings', []))}
Crypto functions: {len(results.get('crypto_functions', []))}

Analysis completed successfully.
"""
            
            if app:
                app.update_output.emit(f"[Ghidra Bridge] Analysis completed: {len(functions)} functions analyzed")
                
            logger.info(f"Ghidra bridge analysis completed successfully")
            return 0, stdout, ""
            
    except GhidraBridgeError as e:
        error_msg = f"Ghidra bridge error: {e}"
        logger.error(error_msg)
        if app:
            app.update_output.emit(f"[Ghidra Bridge] Error: {error_msg}")
        return 1, "", error_msg
        
    except Exception as e:
        error_msg = f"Ghidra analysis failed: {e}"
        logger.error(error_msg)
        if app:
            app.update_output.emit(f"[Ghidra Bridge] Error: {error_msg}")
        return 1, "", error_msg


def create_ghidra_analysis_script(analysis_type: str = "basic") -> str:
    """
    Create a Ghidra analysis script.
    
    Note: Bridge-based approach doesn't use standalone scripts,
    but this function is maintained for API compatibility.

    Args:
        analysis_type: Type of analysis to perform

    Returns:
        Script content as string
    """
    logger.info(f"Creating analysis configuration for type: {analysis_type}")
    
    # Return a configuration dictionary as string for bridge use
    if analysis_type == "license_analysis":
        return "license_focused_analysis"
    elif analysis_type == "function_analysis":
        return "function_focused_analysis"
    elif analysis_type == "string_analysis":
        return "string_focused_analysis"
    else:
        return "basic_analysis"


def save_ghidra_script(script_content: str, script_name: str, output_dir: str) -> str:
    """
    Save a Ghidra script to file.
    
    Bridge-based approach doesn't need standalone scripts,
    but this function is maintained for compatibility.

    Args:
        script_content: Content of the script
        script_name: Name of the script file
        output_dir: Directory to save the script

    Returns:
        Path to the saved script file
    """
    try:
        os.makedirs(output_dir, exist_ok=True)
        
        # Create a configuration file instead of script
        if not script_name.endswith('.json'):
            script_name = script_name.replace('.java', '.json')
            
        script_path = os.path.join(output_dir, script_name)
        
        # Save as configuration
        config = {
            "analysis_type": script_content,
            "created_by": "intellicrack_bridge",
            "bridge_based": True
        }
        
        import json
        with open(script_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)

        logger.info(f"Ghidra analysis config saved to: {script_path}")
        return script_path

    except Exception as e:
        logger.error(f"Failed to save Ghidra config: {e}")
        raise


def get_ghidra_project_info(project_dir: str, project_name: str) -> Dict[str, Any]:
    """
    Get information about a Ghidra project.

    Args:
        project_dir: Directory containing the project
        project_name: Name of the project

    Returns:
        Dictionary with project information
    """
    info = {
        'exists': False,
        'project_dir': project_dir,
        'project_name': project_name,
        'files': [],
        'size': 0,
        'bridge_based': True
    }

    try:
        # Check if project directory exists
        if os.path.exists(project_dir):
            info['exists'] = True
            info['project_dir'] = project_dir
            
            # List project files
            project_files = []
            for file in os.listdir(project_dir):
                if os.path.isfile(os.path.join(project_dir, file)):
                    project_files.append(file)
                    info['size'] += os.path.getsize(os.path.join(project_dir, file))
                    
            info['files'] = project_files
            
            if project_files:
                info['modified'] = max(
                    os.path.getmtime(os.path.join(project_dir, f)) 
                    for f in project_files
                )

    except Exception as e:
        logger.debug(f"Failed to get project info: {e}")

    return info


def cleanup_ghidra_project(project_dir: str, project_name: str) -> bool:
    """
    Clean up a Ghidra project directory.

    Args:
        project_dir: Directory containing the project
        project_name: Name of the project

    Returns:
        True if cleanup was successful
    """
    try:
        if not os.path.exists(project_dir):
            return True

        # Remove all files in project directory
        import shutil
        shutil.rmtree(project_dir, ignore_errors=True)

        logger.info(f"Cleaned up Ghidra project directory: {project_dir}")
        return True

    except Exception as e:
        logger.error(f"Failed to cleanup Ghidra project: {e}")
        return False


def analyze_binary_with_bridge(binary_path: str, ghidra_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Analyze a binary using Ghidra Bridge.
    
    Args:
        binary_path: Path to binary file
        ghidra_path: Optional path to Ghidra installation
        
    Returns:
        Complete analysis results
    """
    try:
        bridge_manager = GhidraBridgeManager(ghidra_path)
        
        with bridge_manager:
            # Load program
            if not bridge_manager.load_program(binary_path):
                return {'error': f'Failed to load program: {binary_path}'}
                
            # Perform comprehensive analysis
            results = {
                'binary_path': binary_path,
                'functions': bridge_manager.get_functions(),
                'strings': bridge_manager.get_strings(),
                'imports': bridge_manager.get_imports(),
                'license_analysis': bridge_manager.analyze_license_patterns(),
                'memory_info': bridge_manager.get_memory_info()
            }
            
            # Add summary statistics
            results['summary'] = {
                'total_functions': len(results['functions']),
                'total_strings': len(results['strings']),
                'total_imports': len(results['imports']),
                'license_functions_found': len(results['license_analysis'].get('license_functions', [])),
                'license_strings_found': len(results['license_analysis'].get('license_strings', [])),
                'crypto_functions_found': len(results['license_analysis'].get('crypto_functions', []))
            }
            
            return results
            
    except Exception as e:
        logger.error(f"Bridge analysis failed: {e}")
        return {'error': str(e)}


def decompile_function_with_bridge(binary_path: str, function_name: str, ghidra_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Decompile a specific function using Ghidra Bridge.
    
    Args:
        binary_path: Path to binary file
        function_name: Name or address of function to decompile
        ghidra_path: Optional path to Ghidra installation
        
    Returns:
        Decompilation results
    """
    try:
        bridge_manager = GhidraBridgeManager(ghidra_path)
        
        with bridge_manager:
            # Load program
            if not bridge_manager.load_program(binary_path):
                return {'error': f'Failed to load program: {binary_path}'}
                
            # Decompile function
            result = bridge_manager.decompile_function(function_name)
            
            if result:
                return result
            else:
                return {'error': f'Failed to decompile function: {function_name}'}
                
    except Exception as e:
        logger.error(f"Function decompilation failed: {e}")
        return {'error': str(e)}


# Export commonly used functions for backwards compatibility
__all__ = [
    'run_ghidra_plugin',
    'create_ghidra_analysis_script', 
    'save_ghidra_script',
    'get_ghidra_project_info',
    'cleanup_ghidra_project',
    'analyze_binary_with_bridge',
    'decompile_function_with_bridge'
]