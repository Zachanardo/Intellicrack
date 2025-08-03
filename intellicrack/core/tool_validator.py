"""
Tool Validation and Verification System for Intellicrack

Provides comprehensive validation of external tools required for binary analysis
and defensive security research. Validates tool presence, versions, and functionality.

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

import json
import logging
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)


@dataclass
class ToolValidationResult:
    """Result of tool validation check."""
    tool_name: str
    is_valid: bool
    path: Optional[str] = None
    version: Optional[str] = None
    error_message: Optional[str] = None
    warnings: List[str] = None
    required_version: Optional[str] = None
    
    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []


class ExternalToolValidator:
    """
    Validates external tools required by Intellicrack for defensive security research.
    
    This validator ensures all external analysis tools are properly installed,
    configured, and functional before allowing Intellicrack operations.
    """
    
    # Minimum required versions for each tool
    REQUIRED_VERSIONS = {
        'ghidra': '11.0.0',
        'radare2': '5.8.0', 
        'qemu': '8.0.0',
        'die': '3.0.0',
        'java': '11.0.0'
    }
    
    # Critical tools that must be present for core functionality
    CRITICAL_TOOLS = {'ghidra', 'radare2', 'java'}
    
    # Optional tools that enhance functionality but aren't required
    OPTIONAL_TOOLS = {'qemu', 'die'}
    
    def __init__(self, config_manager=None):
        """Initialize tool validator."""
        self.config_manager = config_manager
        self.validation_results: Dict[str, ToolValidationResult] = {}
        
    def validate_all_tools(self) -> Dict[str, ToolValidationResult]:
        """
        Validate all external tools required by Intellicrack.
        
        Returns:
            Dictionary mapping tool names to validation results
        """
        logger.info("Starting comprehensive tool validation...")
        
        # Clear previous results
        self.validation_results.clear()
        
        # Validate each tool
        tools_to_validate = self.CRITICAL_TOOLS | self.OPTIONAL_TOOLS
        
        for tool_name in tools_to_validate:
            try:
                result = self._validate_tool(tool_name)
                self.validation_results[tool_name] = result
                
                if result.is_valid:
                    logger.info(f"✓ {tool_name} validation passed: {result.version} at {result.path}")
                else:
                    level = logging.ERROR if tool_name in self.CRITICAL_TOOLS else logging.WARNING
                    logger.log(level, f"✗ {tool_name} validation failed: {result.error_message}")
                    
            except Exception as e:
                error_msg = f"Unexpected error validating {tool_name}: {str(e)}"
                logger.error(error_msg)
                self.validation_results[tool_name] = ToolValidationResult(
                    tool_name=tool_name,
                    is_valid=False,
                    error_message=error_msg
                )
        
        # Generate summary report
        self._log_validation_summary()
        
        return self.validation_results
    
    def _validate_tool(self, tool_name: str) -> ToolValidationResult:
        """Validate a specific tool."""
        validation_method = getattr(self, f'_validate_{tool_name}', None)
        
        if validation_method is None:
            return ToolValidationResult(
                tool_name=tool_name,
                is_valid=False,
                error_message=f"No validation method defined for {tool_name}"
            )
        
        return validation_method()
    
    def _validate_ghidra(self) -> ToolValidationResult:
        """Validate Ghidra installation and functionality."""
        tool_name = 'ghidra'
        
        # Check for Ghidra in multiple locations
        ghidra_paths = self._get_ghidra_search_paths()
        
        for ghidra_dir in ghidra_paths:
            if not os.path.exists(ghidra_dir):
                continue
                
            # Look for Ghidra executable
            if sys.platform == "win32":
                ghidra_run = os.path.join(ghidra_dir, 'ghidraRun.bat')
                analyze_headless = os.path.join(ghidra_dir, 'support', 'analyzeHeadless.bat')
            else:
                ghidra_run = os.path.join(ghidra_dir, 'ghidraRun')
                analyze_headless = os.path.join(ghidra_dir, 'support', 'analyzeHeadless')
            
            if os.path.exists(ghidra_run) and os.path.exists(analyze_headless):
                # Try to get version
                version = self._get_ghidra_version(ghidra_dir)
                
                # Validate Java dependency
                java_result = self._validate_java()
                warnings = []
                if not java_result.is_valid:
                    warnings.append("Java 11+ required for Ghidra but not found")
                
                return ToolValidationResult(
                    tool_name=tool_name,
                    is_valid=True,
                    path=ghidra_dir,
                    version=version,
                    required_version=self.REQUIRED_VERSIONS.get(tool_name),
                    warnings=warnings
                )
        
        return ToolValidationResult(
            tool_name=tool_name,
            is_valid=False,
            error_message="Ghidra not found. Install from https://ghidra-sre.org/ or run setup_external_tools.bat",
            required_version=self.REQUIRED_VERSIONS.get(tool_name)
        )
    
    def _validate_radare2(self) -> ToolValidationResult:
        """Validate Radare2 installation and functionality."""
        tool_name = 'radare2'
        
        # Try to find radare2/r2 executable
        r2_executable = shutil.which('r2') or shutil.which('radare2')
        
        if not r2_executable:
            # Check common installation paths
            r2_paths = self._get_radare2_search_paths()
            for r2_path in r2_paths:
                r2_exe = os.path.join(r2_path, 'r2.exe' if sys.platform == "win32" else 'r2')
                if os.path.exists(r2_exe):
                    r2_executable = r2_exe
                    break
        
        if not r2_executable:
            return ToolValidationResult(
                tool_name=tool_name,
                is_valid=False,
                error_message="Radare2 not found. Install from https://rada.re or run setup_external_tools.bat",
                required_version=self.REQUIRED_VERSIONS.get(tool_name)
            )
        
        # Get version
        try:
            result = subprocess.run([r2_executable, '-v'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                version_line = result.stdout.strip().split('\n')[0]
                version = self._extract_version_from_string(version_line)
            else:
                version = "unknown"
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            version = "unknown"
        
        return ToolValidationResult(
            tool_name=tool_name,
            is_valid=True,
            path=r2_executable,
            version=version,
            required_version=self.REQUIRED_VERSIONS.get(tool_name)
        )
    
    def _validate_qemu(self) -> ToolValidationResult:
        """Validate QEMU installation and functionality."""
        tool_name = 'qemu'
        
        # Try to find QEMU executable
        qemu_executable = shutil.which('qemu-system-x86_64')
        
        if not qemu_executable:
            # Check common installation paths
            qemu_paths = self._get_qemu_search_paths()
            for qemu_path in qemu_paths:
                qemu_exe = os.path.join(qemu_path, 'qemu-system-x86_64.exe' if sys.platform == "win32" else 'qemu-system-x86_64')
                if os.path.exists(qemu_exe):
                    qemu_executable = qemu_exe
                    break
        
        if not qemu_executable:
            return ToolValidationResult(
                tool_name=tool_name,
                is_valid=False,
                error_message="QEMU not found. Install from https://www.qemu.org/ or run setup_external_tools.bat",
                required_version=self.REQUIRED_VERSIONS.get(tool_name)
            )
        
        # Get version
        try:
            result = subprocess.run([qemu_executable, '--version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                version_line = result.stdout.strip().split('\n')[0]
                version = self._extract_version_from_string(version_line)
            else:
                version = "unknown"
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            version = "unknown"
        
        return ToolValidationResult(
            tool_name=tool_name,
            is_valid=True,
            path=qemu_executable,
            version=version,
            required_version=self.REQUIRED_VERSIONS.get(tool_name)
        )
    
    def _validate_die(self) -> ToolValidationResult:
        """Validate DIE (Detect It Easy) installation."""
        tool_name = 'die'
        
        # Try to find DIE executable
        die_executable = shutil.which('diec') or shutil.which('die')
        
        if not die_executable:
            # Check common installation paths
            die_paths = self._get_die_search_paths()
            for die_path in die_paths:
                die_exe = os.path.join(die_path, 'diec.exe' if sys.platform == "win32" else 'diec')
                if os.path.exists(die_exe):
                    die_executable = die_exe
                    break
        
        if not die_executable:
            return ToolValidationResult(
                tool_name=tool_name,
                is_valid=False,
                error_message="DIE not found. Install from https://github.com/horsicq/DIE-engine or run setup_external_tools.bat",
                required_version=self.REQUIRED_VERSIONS.get(tool_name)
            )
        
        # Get version and check JSON support
        version = "unknown"
        json_supported = False
        
        try:
            # Check version
            result = subprocess.run([die_executable, '--version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                version_line = result.stdout.strip()
                version = self._extract_version_from_string(version_line)
            
            # Check for JSON output support
            help_result = subprocess.run([die_executable, '--help'], 
                                       capture_output=True, text=True, timeout=10)
            if help_result.returncode == 0:
                json_supported = '--json' in help_result.stdout.lower()
                
        except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
            logger.warning(f"DIE validation error: {e}")
        
        # Validate JSON support
        if not json_supported:
            return ToolValidationResult(
                tool_name=tool_name,
                is_valid=False,
                path=die_executable,
                version=version,
                error_message="DIE executable found but does not support --json output. Please update to a newer version.",
                required_version=self.REQUIRED_VERSIONS.get(tool_name)
            )
        
        return ToolValidationResult(
            tool_name=tool_name,
            is_valid=True,
            path=die_executable,
            version=version,
            required_version=self.REQUIRED_VERSIONS.get(tool_name),
            additional_info={"json_supported": True}
        )
    
    def _validate_java(self) -> ToolValidationResult:
        """Validate Java installation (required for Ghidra)."""
        tool_name = 'java'
        
        # Try to find Java executable
        java_executable = shutil.which('java')
        
        if not java_executable:
            return ToolValidationResult(
                tool_name=tool_name,
                is_valid=False,
                error_message="Java not found. Install Java 11+ from https://adoptium.net/",
                required_version=self.REQUIRED_VERSIONS.get(tool_name)
            )
        
        # Get version
        try:
            result = subprocess.run([java_executable, '-version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                # Java version is in stderr
                version_output = result.stderr if result.stderr else result.stdout
                version = self._extract_java_version(version_output)
            else:
                version = "unknown"
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            version = "unknown"
        
        # Check if version meets minimum requirement
        if version != "unknown":
            major_version = self._extract_java_major_version(version)
            if major_version and major_version < 11:
                return ToolValidationResult(
                    tool_name=tool_name,
                    is_valid=False,
                    path=java_executable,
                    version=version,
                    error_message=f"Java {major_version} found but Java 11+ required for Ghidra",
                    required_version=self.REQUIRED_VERSIONS.get(tool_name)
                )
        
        return ToolValidationResult(
            tool_name=tool_name,
            is_valid=True,
            path=java_executable,
            version=version,
            required_version=self.REQUIRED_VERSIONS.get(tool_name)
        )
    
    def _get_ghidra_search_paths(self) -> List[str]:
        """Get platform-specific Ghidra search paths."""
        paths = []
        
        if sys.platform == "win32":
            paths.extend([
                r'C:\Program Files\ghidra',
                r'C:\ghidra',
                r'C:\Tools\ghidra',
                os.path.expanduser(r'~\ghidra'),
                # Check our tools directory from setup script
                os.path.join(os.path.dirname(os.path.dirname(__file__)), 'tools', 'ghidra*')
            ])
        else:
            paths.extend([
                '/opt/ghidra',
                '/usr/local/ghidra',
                '/usr/share/ghidra',
                os.path.expanduser('~/ghidra')
            ])
        
        # Expand glob patterns
        expanded_paths = []
        for path in paths:
            if '*' in path:
                import glob
                expanded_paths.extend(glob.glob(path))
            else:
                expanded_paths.append(path)
        
        return expanded_paths
    
    def _get_radare2_search_paths(self) -> List[str]:
        """Get platform-specific Radare2 search paths."""
        paths = []
        
        if sys.platform == "win32":
            paths.extend([
                r'C:\Program Files\radare2\bin',
                r'C:\radare2\bin',
                r'C:\Tools\radare2\bin',
                os.path.expanduser(r'~\radare2\bin'),
                # Check our tools directory from setup script
                os.path.join(os.path.dirname(os.path.dirname(__file__)), 'tools', 'radare2', 'bin')
            ])
        else:
            paths.extend([
                '/usr/bin',
                '/usr/local/bin',
                '/opt/radare2/bin'
            ])
        
        return paths
    
    def _get_qemu_search_paths(self) -> List[str]:
        """Get platform-specific QEMU search paths."""
        paths = []
        
        if sys.platform == "win32":
            paths.extend([
                r'C:\Program Files\qemu',
                r'C:\qemu',
                os.path.join(os.environ.get('PROGRAMFILES', ''), 'qemu'),
                # Check our tools directory from setup script
                os.path.join(os.path.dirname(os.path.dirname(__file__)), 'tools', 'qemu')
            ])
        else:
            paths.extend([
                '/usr/bin',
                '/usr/local/bin',
                '/opt/qemu/bin'
            ])
        
        return paths
    
    def _get_die_search_paths(self) -> List[str]:
        """Get platform-specific DIE search paths."""
        paths = []
        
        if sys.platform == "win32":
            paths.extend([
                r'C:\Program Files\die',
                r'C:\die',
                r'C:\Tools\die',
                os.path.expanduser(r'~\die'),
                # Check our tools directory from setup script
                os.path.join(os.path.dirname(os.path.dirname(__file__)), 'tools', 'die')
            ])
        else:
            paths.extend([
                '/usr/bin',
                '/usr/local/bin',
                '/opt/die'
            ])
        
        return paths
    
    def _get_ghidra_version(self, ghidra_dir: str) -> str:
        """Extract Ghidra version from installation directory."""
        try:
            # Try to read version from application.properties
            props_file = os.path.join(ghidra_dir, 'Ghidra', 'application.properties')
            if os.path.exists(props_file):
                with open(props_file, 'r') as f:
                    for line in f:
                        if line.startswith('application.version='):
                            return line.split('=')[1].strip()
            
            # Fallback: try to parse from directory name
            dir_name = os.path.basename(ghidra_dir)
            if 'ghidra' in dir_name.lower():
                version = self._extract_version_from_string(dir_name)
                if version:
                    return version
        except Exception as e:
            logger.debug(f"Error extracting Ghidra version: {e}")
        
        return "unknown"
    
    def _extract_version_from_string(self, text: str) -> str:
        """Extract version number from text using regex."""
        import re
        
        # Common version patterns
        patterns = [
            r'(\d+\.\d+\.\d+)',  # x.y.z
            r'(\d+\.\d+)',       # x.y
            r'version\s+(\d+\.\d+\.\d+)',  # version x.y.z
            r'v(\d+\.\d+\.\d+)'  # vx.y.z
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return "unknown"
    
    def _extract_java_version(self, version_output: str) -> str:
        """Extract Java version from java -version output."""
        import re
        
        # Java version patterns
        patterns = [
            r'version "(\d+\.\d+\.\d+[^"]*)"',  # Java 8 and earlier
            r'version "(\d+[^"]*)"',           # Java 9+
        ]
        
        for pattern in patterns:
            match = re.search(pattern, version_output)
            if match:
                return match.group(1)
        
        return "unknown"
    
    def _extract_java_major_version(self, version_string: str) -> Optional[int]:
        """Extract major version number from Java version string."""
        try:
            if version_string.startswith('1.'):
                # Java 8 and earlier (1.8.0_xxx format)
                return int(version_string.split('.')[1])
            else:
                # Java 9+ (9.x.x, 11.x.x format)
                return int(version_string.split('.')[0])
        except (ValueError, IndexError):
            return None
    
    def _log_validation_summary(self):
        """Log a summary of tool validation results."""
        total_tools = len(self.validation_results)
        valid_tools = sum(1 for result in self.validation_results.values() if result.is_valid)
        invalid_critical = [name for name, result in self.validation_results.items() 
                          if not result.is_valid and name in self.CRITICAL_TOOLS]
        
        logger.info(f"Tool Validation Summary: {valid_tools}/{total_tools} tools validated successfully")
        
        if invalid_critical:
            logger.error(f"CRITICAL TOOLS MISSING: {', '.join(invalid_critical)}")
            logger.error("Intellicrack cannot function without these critical tools!")
        
        # Log warnings for all invalid tools
        for name, result in self.validation_results.items():
            if not result.is_valid:
                tool_type = "CRITICAL" if name in self.CRITICAL_TOOLS else "OPTIONAL"
                logger.warning(f"{tool_type} tool {name}: {result.error_message}")
    
    def get_missing_critical_tools(self) -> List[str]:
        """Get list of missing critical tools."""
        return [name for name, result in self.validation_results.items() 
                if not result.is_valid and name in self.CRITICAL_TOOLS]
    
    def is_ready_for_operation(self) -> bool:
        """Check if all critical tools are available for operation."""
        missing_critical = self.get_missing_critical_tools()
        return len(missing_critical) == 0
    
    def generate_setup_instructions(self) -> str:
        """Generate setup instructions for missing tools."""
        missing_tools = [name for name, result in self.validation_results.items() 
                        if not result.is_valid]
        
        if not missing_tools:
            return "All tools are properly configured!"
        
        instructions = ["Missing Tools Setup Instructions:", ""]
        
        if 'ghidra' in missing_tools:
            instructions.extend([
                "• Ghidra:",
                "  - Download from: https://ghidra-sre.org/",
                "  - Or run: setup\\setup_external_tools.bat",
                "  - Requires Java 11+",
                ""
            ])
        
        if 'radare2' in missing_tools:
            instructions.extend([
                "• Radare2:",
                "  - Download from: https://rada.re/",
                "  - Or run: setup\\setup_external_tools.bat",
                ""
            ])
        
        if 'qemu' in missing_tools:
            instructions.extend([
                "• QEMU:",
                "  - Download from: https://www.qemu.org/",
                "  - Or run: setup\\setup_external_tools.bat",
                ""
            ])
        
        if 'die' in missing_tools:
            instructions.extend([
                "• DIE (Detect It Easy):",
                "  - Download from: https://github.com/horsicq/DIE-engine",
                "  - Or run: setup\\setup_external_tools.bat",
                ""
            ])
        
        if 'java' in missing_tools:
            instructions.extend([
                "• Java 11+:",
                "  - Download from: https://adoptium.net/",
                "  - Required for Ghidra functionality",
                ""
            ])
        
        instructions.extend([
            "After installation, restart Intellicrack to re-validate tools.",
            "For automated setup, run: setup\\setup_external_tools.bat"
        ])
        
        return "\n".join(instructions)


def validate_startup_tools() -> Tuple[bool, Dict[str, ToolValidationResult]]:
    """
    Validate all external tools required for Intellicrack startup.
    
    Returns:
        Tuple of (is_ready, validation_results)
    """
    validator = ExternalToolValidator()
    results = validator.validate_all_tools()
    is_ready = validator.is_ready_for_operation()
    
    return is_ready, results