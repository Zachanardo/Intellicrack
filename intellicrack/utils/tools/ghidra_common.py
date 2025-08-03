"""
Bridge-Based Ghidra Plugin Execution Utilities

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

import os
import logging
from typing import Tuple, Any, Optional, List

from ...core.analysis.ghidra_bridge_manager import GhidraBridgeManager, GhidraBridgeError
from ..logger import get_logger

logger = get_logger(__name__)


def run_ghidra_plugin(ghidra_path: str, 
                     temp_dir: str, 
                     project_name: str, 
                     binary_path: str, 
                     plugin_dir: str, 
                     plugin_file: str, 
                     app: Any = None, 
                     overwrite: bool = True) -> Tuple[int, str, str]:
    """
    Run a Ghidra plugin using bridge-based approach.
    
    Maintains API compatibility while using modern bridge backend.

    Args:
        ghidra_path: Path to Ghidra executable
        temp_dir: Temporary directory for project
        project_name: Name of the Ghidra project
        binary_path: Path to the binary to analyze
        plugin_dir: Directory containing the plugin
        plugin_file: Plugin filename
        app: Optional app instance for UI updates
        overwrite: Whether to overwrite existing project

    Returns:
        tuple: (returncode, stdout, stderr)
    """
    try:
        if app:
            app.update_output.emit(log_message("[Bridge] Setting up Ghidra bridge session..."))

        logger.info(f"Running Ghidra plugin via bridge: {plugin_file}")
        
        # Initialize bridge manager
        bridge_manager = GhidraBridgeManager(ghidra_path)
        
        with bridge_manager:
            if app:
                app.update_output.emit(log_message("[Bridge] Loading program into Ghidra..."))
                
            # Load program
            if not bridge_manager.load_program(binary_path, temp_dir):
                error_msg = f"Failed to load program: {binary_path}"
                logger.error(error_msg)
                return 1, "", error_msg
                
            if app:
                app.update_output.emit(log_message("[Bridge] Running analysis..."))
                
            # Determine analysis type from plugin file
            analysis_type = _determine_analysis_type(plugin_file)
            
            # Perform analysis based on plugin type
            if analysis_type == "license":
                results = bridge_manager.analyze_license_patterns()
                stdout = _format_license_results(results)
            elif analysis_type == "functions":
                functions = bridge_manager.get_functions()
                stdout = _format_function_results(functions)
            elif analysis_type == "strings":
                strings = bridge_manager.get_strings()
                stdout = _format_string_results(strings)
            else:
                # General analysis
                functions = bridge_manager.get_functions()
                strings = bridge_manager.get_strings()
                imports = bridge_manager.get_imports()
                license_analysis = bridge_manager.analyze_license_patterns()
                
                stdout = _format_general_results(functions, strings, imports, license_analysis)
                
            if app:
                app.update_output.emit(log_message("[Bridge] Analysis completed successfully"))
                
            logger.info("Ghidra bridge plugin execution completed successfully")
            return 0, stdout, ""
            
    except GhidraBridgeError as e:
        error_msg = f"Ghidra bridge error: {e}"
        logger.error(error_msg)
        if app:
            app.update_output.emit(log_message(f"[Bridge] Error: {error_msg}"))
        return 1, "", error_msg
        
    except Exception as e:
        error_msg = f"Plugin execution failed: {e}"
        logger.error(error_msg)
        if app:
            app.update_output.emit(log_message(f"[Bridge] Error: {error_msg}"))
        return 1, "", error_msg


def _determine_analysis_type(plugin_file: str) -> str:
    """Determine analysis type from plugin filename."""
    plugin_lower = plugin_file.lower()
    
    if any(keyword in plugin_lower for keyword in ['license', 'activation', 'registration']):
        return "license"
    elif any(keyword in plugin_lower for keyword in ['function', 'decompile']):
        return "functions"
    elif any(keyword in plugin_lower for keyword in ['string', 'text']):
        return "strings"
    else:
        return "general"


def _format_license_results(results: dict) -> str:
    """Format license analysis results."""
    output = ["=== License Analysis Results ==="]
    
    license_funcs = results.get('license_functions', [])
    license_strings = results.get('license_strings', [])
    crypto_funcs = results.get('crypto_functions', [])
    
    output.append(f"License-related functions found: {len(license_funcs)}")
    for func_info in license_funcs[:10]:  # Show first 10
        func = func_info.get('function', {})
        keyword = func_info.get('matched_keyword', '')
        confidence = func_info.get('confidence', 0)
        output.append(f"  - {func.get('name', 'Unknown')} @ {func.get('address', 'Unknown')} (keyword: {keyword}, confidence: {confidence:.2f})")
        
    if len(license_funcs) > 10:
        output.append(f"  ... and {len(license_funcs) - 10} more functions")
    
    output.append(f"\nLicense-related strings found: {len(license_strings)}")
    for string_info in license_strings[:10]:  # Show first 10
        output.append(f"  - {string_info.get('value', 'Unknown')[:50]}{'...' if len(string_info.get('value', '')) > 50 else ''} @ {string_info.get('address', 'Unknown')}")
        
    if len(license_strings) > 10:
        output.append(f"  ... and {len(license_strings) - 10} more strings")
    
    output.append(f"\nCrypto-related functions found: {len(crypto_funcs)}")
    for func in crypto_funcs[:10]:  # Show first 10
        output.append(f"  - {func.get('name', 'Unknown')} @ {func.get('address', 'Unknown')}")
        
    if len(crypto_funcs) > 10:
        output.append(f"  ... and {len(crypto_funcs) - 10} more functions")
    
    return "\n".join(output)


def _format_function_results(functions: list) -> str:
    """Format function analysis results."""
    output = ["=== Function Analysis Results ==="]
    
    output.append(f"Total functions found: {len(functions)}")
    
    # Categorize by size
    small = [f for f in functions if f.get('size', 0) < 50]
    medium = [f for f in functions if 50 <= f.get('size', 0) < 200]
    large = [f for f in functions if f.get('size', 0) >= 200]
    
    output.append(f"Small functions (< 50 instructions): {len(small)}")
    output.append(f"Medium functions (50-200 instructions): {len(medium)}")
    output.append(f"Large functions (>= 200 instructions): {len(large)}")
    
    # Show largest functions
    largest = sorted(functions, key=lambda x: x.get('size', 0), reverse=True)[:10]
    output.append("\nLargest functions:")
    for func in largest:
        output.append(f"  - {func.get('name', 'Unknown')} @ {func.get('address', 'Unknown')} (size: {func.get('size', 0)})")
    
    return "\n".join(output)


def _format_string_results(strings: list) -> str:
    """Format string analysis results."""
    output = ["=== String Analysis Results ==="]
    
    output.append(f"Total strings found: {len(strings)}")
    
    # Categorize strings
    categories = {}
    for string_info in strings:
        category = string_info.get('category', 'other')
        categories[category] = categories.get(category, 0) + 1
    
    output.append("\nString categories:")
    for category, count in categories.items():
        output.append(f"  - {category}: {count}")
    
    # Show interesting strings
    interesting = [s for s in strings if s.get('category') in ['url', 'license_related', 'error_message']]
    output.append(f"\nInteresting strings ({len(interesting)}):")
    for string_info in interesting[:10]:
        value = string_info.get('value', '')
        if len(value) > 50:
            value = value[:50] + "..."
        output.append(f"  - {value} @ {string_info.get('address', 'Unknown')} ({string_info.get('category', 'unknown')})")
        
    if len(interesting) > 10:
        output.append(f"  ... and {len(interesting) - 10} more strings")
    
    return "\n".join(output)


def _format_general_results(functions: list, strings: list, imports: list, license_analysis: dict) -> str:
    """Format general analysis results."""
    output = ["=== General Analysis Results ==="]
    
    output.append(f"Functions analyzed: {len(functions)}")
    output.append(f"Strings extracted: {len(strings)}")
    output.append(f"Imports found: {len(imports)}")
    
    # License analysis summary
    license_funcs = license_analysis.get('license_functions', [])
    license_strings = license_analysis.get('license_strings', [])
    crypto_funcs = license_analysis.get('crypto_functions', [])
    
    output.append(f"\nLicense Analysis:")
    output.append(f"  - License functions: {len(license_funcs)}")
    output.append(f"  - License strings: {len(license_strings)}")
    output.append(f"  - Crypto functions: {len(crypto_funcs)}")
    
    # Top license functions
    if license_funcs:
        output.append("\nTop license functions:")
        for func_info in license_funcs[:5]:
            func = func_info.get('function', {})
            confidence = func_info.get('confidence', 0)
            output.append(f"  - {func.get('name', 'Unknown')} (confidence: {confidence:.2f})")
    
    # Import libraries
    if imports:
        libraries = {}
        for imp in imports:
            lib = imp.get('library', 'Unknown')
            libraries[lib] = libraries.get(lib, 0) + 1
            
        output.append(f"\nTop imported libraries:")
        sorted_libs = sorted(libraries.items(), key=lambda x: x[1], reverse=True)
        for lib, count in sorted_libs[:10]:
            output.append(f"  - {lib}: {count} imports")
    
    output.append("\nAnalysis completed successfully.")
    
    return "\n".join(output)


def get_ghidra_output_messages(returncode: int, stdout: str, stderr: str, app: Any = None) -> List[str]:
    """
    Process and format Ghidra output messages.

    Args:
        returncode: Process return code
        stdout: Standard output
        stderr: Standard error
        app: Optional app instance for UI updates

    Returns:
        list: List of formatted messages
    """
    messages = []

    if returncode == 0:
        messages.append("[Bridge] Ghidra analysis completed successfully")
        if stdout:
            # Truncate long output
            output_preview = stdout[:500] + ('...' if len(stdout) > 500 else '')
            messages.append(f"[Bridge] Results: {output_preview}")
    else:
        messages.append(f"[Bridge] Ghidra analysis failed with code {returncode}")
        if stderr:
            error_preview = stderr[:500] + ('...' if len(stderr) > 500 else '')
            messages.append(f"[Bridge] Error: {error_preview}")

    # Emit messages if app provided
    if app:
        for message in messages:
            app.update_output.emit(log_message(message))

    return messages


def log_message(message: str) -> str:
    """Format log message for consistent output."""
    return f"[{message.split(']')[0][1:]}] {message.split('] ', 1)[1] if '] ' in message else message}"


__all__ = ['run_ghidra_plugin', 'get_ghidra_output_messages', 'log_message']