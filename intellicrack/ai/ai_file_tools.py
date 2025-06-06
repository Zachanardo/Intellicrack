"""
AI File System Tools

This module provides AI-accessible file system tools with user approval mechanisms.
These tools allow the AI to search for licensing-related files and read them for analysis.
"""

import fnmatch
import logging
import os
from pathlib import Path
from typing import Any, Dict, List

from ..ui.common_imports import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
)

logger = logging.getLogger(__name__)

__all__ = ['AIFileTools', 'FileSearchTool', 'FileReadTool', 'create_approval_dialog']


class FileApprovalDialog(QDialog):
    """Dialog for requesting user approval for AI file operations."""

    def __init__(self, operation_type: str, details: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"AI File {operation_type} Request")
        self.setMinimumSize(600, 400)

        layout = QVBoxLayout()

        # Header
        header = QLabel(f"The AI wants to {operation_type.lower()} files:")
        header.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(header)

        # Details
        details_text = QTextEdit()
        details_text.setPlainText(details)
        details_text.setReadOnly(True)
        details_text.setMaximumHeight(200)
        layout.addWidget(details_text)

        # Warning
        warning = QLabel("⚠️ Only approve if you trust the AI's analysis purpose.")
        warning.setStyleSheet("color: orange; font-weight: bold;")
        layout.addWidget(warning)

        # Buttons
        button_layout = QHBoxLayout()

        self.approve_btn = QPushButton("Approve")
        self.approve_btn.setStyleSheet("background-color: #4CAF50; color: white;")
        self.approve_btn.clicked.connect(self.accept)

        self.deny_btn = QPushButton("Deny")
        self.deny_btn.setStyleSheet("background-color: #f44336; color: white;")
        self.deny_btn.clicked.connect(self.reject)

        button_layout.addWidget(self.deny_btn)
        button_layout.addWidget(self.approve_btn)

        layout.addLayout(button_layout)
        self.setLayout(layout)


def create_approval_dialog(operation_type: str, details: str, parent=None) -> bool:
    """Create and show approval dialog for AI file operations."""
    dialog = FileApprovalDialog(operation_type, details, parent)
    return dialog.exec_() == QDialog.Accepted


class FileSearchTool:
    """Tool for AI to search the file system for licensing-related files."""

    def __init__(self, app_instance=None):
        self.app_instance = app_instance
        self.common_license_patterns = [
            "*license*", "*licensing*", "*lic*", "*auth*", "*activation*",
            "*register*", "*serial*", "*key*", "*crack*", "*patch*",
            "*trial*", "*demo*", "*evaluation*", "*expire*", "*validity*",
            "*.cfg", "*.ini", "*.conf", "*.reg", "*.dat", "*.db", "*.sqlite"
        ]

    def search_license_files(self, search_path: str, custom_patterns: List[str] = None) -> Dict[str, Any]:
        """
        Search for license-related files in the specified path.

        Args:
            search_path: Directory to search in
            custom_patterns: Additional file patterns to search for

        Returns:
            Dictionary with search results and metadata
        """
        # Request user approval
        details = f"""Search Path: {search_path}

Patterns to search for:
{chr(10).join(self.common_license_patterns + (custom_patterns or []))}

Purpose: Find licensing-related files for analysis to identify protection mechanisms."""

        if not create_approval_dialog("Search", details, self.app_instance):
            return {"status": "denied", "message": "User denied file search request"}

        try:
            results = {
                "status": "success",
                "search_path": search_path,
                "files_found": [],
                "directories_scanned": 0,
                "total_files_checked": 0
            }

            patterns = self.common_license_patterns + (custom_patterns or [])
            search_root = Path(search_path)

            if not search_root.exists():
                return {"status": "error", "message": f"Path does not exist: {search_path}"}

            # Search recursively
            for root, dirs, files in os.walk(search_root):
                results["directories_scanned"] += 1

                for file in files:
                    results["total_files_checked"] += 1
                    file_path = Path(root) / file

                    # Check against patterns
                    for pattern in patterns:
                        if fnmatch.fnmatch(file.lower(), pattern.lower()):
                            file_info = {
                                "path": str(file_path),
                                "name": file,
                                "size": file_path.stat().st_size if file_path.exists() else 0,
                                "matched_pattern": pattern,
                                "directory": str(Path(root))
                            }
                            results["files_found"].append(file_info)
                            break

                # Limit search depth for performance
                if len(str(Path(root)).split(os.sep)) - len(str(search_root).split(os.sep)) > 5:
                    dirs.clear()  # Don't descend further

            # Log results
            if self.app_instance and hasattr(self.app_instance, 'update_output'):
                self.app_instance.update_output.emit(
                    f"[AI File Search] Found {len(results['files_found'])} license-related files"
                )

            return results

        except Exception as e:
            logger.error("Error in file search: %s", e)
            return {"status": "error", "message": str(e)}

    def quick_license_scan(self, program_directory: str) -> Dict[str, Any]:
        """
        Quick scan for obvious license files in a program's directory.

        Args:
            program_directory: Main program directory to scan

        Returns:
            Dictionary with found license files
        """
        high_priority_patterns = [
            "license.txt", "license.dat", "license.key", "serial.txt",
            "activation.dat", "auth.cfg", "registration.ini", "*.lic"
        ]

        return self.search_license_files(program_directory, high_priority_patterns)


class FileReadTool:
    """Tool for AI to read files with user approval."""

    def __init__(self, app_instance=None):
        self.app_instance = app_instance
        self.max_file_size = 10 * 1024 * 1024  # 10MB limit

    def read_file_content(self, file_path: str, purpose: str = "License analysis") -> Dict[str, Any]:
        """
        Read the content of a file with user approval.

        Args:
            file_path: Path to the file to read
            purpose: Explanation of why the AI wants to read this file

        Returns:
            Dictionary with file content and metadata
        """
        file_path = Path(file_path)

        # Check if file exists and get info
        if not file_path.exists():
            return {"status": "error", "message": f"File does not exist: {file_path}"}

        file_size = file_path.stat().st_size

        # Check file size limit
        if file_size > self.max_file_size:
            return {
                "status": "error",
                "message": f"File too large: {file_size} bytes (limit: {self.max_file_size})"
            }

        # Request user approval
        details = f"""File Path: {file_path}
File Size: {file_size:,} bytes
Purpose: {purpose}

The AI wants to read this file to analyze licensing mechanisms and identify potential bypass locations."""

        if not create_approval_dialog("Read", details, self.app_instance):
            return {"status": "denied", "message": "User denied file read request"}

        try:
            # Try to read as text first
            content = None
            encoding = "utf-8"

            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
            except UnicodeDecodeError:
                # Try common encodings
                for enc in ['latin-1', 'cp1252', 'ascii']:
                    try:
                        with open(file_path, 'r', encoding=enc) as f:
                            content = f.read()
                            encoding = enc
                            break
                    except UnicodeDecodeError:
                        continue

            if content is None:
                # Read as binary if text fails
                with open(file_path, 'rb') as f:
                    binary_content = f.read()
                content = f"[Binary file - {len(binary_content)} bytes]"
                encoding = "binary"

            result = {
                "status": "success",
                "file_path": str(file_path),
                "content": content,
                "size": file_size,
                "encoding": encoding,
                "is_binary": encoding == "binary"
            }

            # Log the read operation
            if self.app_instance and hasattr(self.app_instance, 'update_output'):
                self.app_instance.update_output.emit(
                    f"[AI File Read] Read {file_path.name} ({file_size:,} bytes)"
                )

            return result

        except Exception as e:
            logger.error("Error reading file %s: %s", file_path, e)
            return {"status": "error", "message": str(e)}

    def read_multiple_files(self, file_paths: List[str], purpose: str = "License analysis") -> Dict[str, Any]:
        """
        Read multiple files with a single approval request.

        Args:
            file_paths: List of file paths to read
            purpose: Explanation of why the AI wants to read these files

        Returns:
            Dictionary with results for each file
        """
        # Calculate total size
        total_size = 0
        valid_paths = []

        for path in file_paths:
            file_path = Path(path)
            if file_path.exists():
                size = file_path.stat().st_size
                if size <= self.max_file_size:
                    total_size += size
                    valid_paths.append(file_path)

        # Request approval for batch read
        details = f"""Files to read: {len(valid_paths)}
Total size: {total_size:,} bytes
Purpose: {purpose}

Files:
{chr(10).join([f"- {p.name} ({p.stat().st_size:,} bytes)" for p in valid_paths[:10]])}
{f"... and {len(valid_paths) - 10} more" if len(valid_paths) > 10 else ""}"""

        if not create_approval_dialog("Read Multiple", details, self.app_instance):
            return {"status": "denied", "message": "User denied batch file read request"}

        results = {
            "status": "success",
            "files_read": [],
            "total_files": len(valid_paths),
            "total_size": total_size
        }

        for file_path in valid_paths:
            file_result = self.read_file_content(str(file_path), f"{purpose} (batch)")
            if file_result["status"] == "success":
                results["files_read"].append(file_result)

        return results


class AIFileTools:
    """Main class providing file system tools for AI analysis."""

    def __init__(self, app_instance=None):
        self.app_instance = app_instance
        self.search_tool = FileSearchTool(app_instance)
        self.read_tool = FileReadTool(app_instance)

    def search_for_license_files(self, base_path: str, custom_patterns: List[str] = None) -> Dict[str, Any]:
        """Search for license-related files."""
        return self.search_tool.search_license_files(base_path, custom_patterns)

    def read_file(self, file_path: str, purpose: str = "License analysis") -> Dict[str, Any]:
        """Read a single file."""
        return self.read_tool.read_file_content(file_path, purpose)

    def read_multiple_files(self, file_paths: List[str], purpose: str = "License analysis") -> Dict[str, Any]:
        """Read multiple files."""
        return self.read_tool.read_multiple_files(file_paths, purpose)

    def analyze_program_directory(self, program_path: str) -> Dict[str, Any]:
        """
        Comprehensive analysis of a program's directory structure for licensing.

        Args:
            program_path: Path to the main program executable

        Returns:
            Dictionary with comprehensive analysis results
        """
        program_path = Path(program_path)
        program_dir = program_path.parent

        # First, do a quick license file scan
        license_scan = self.search_tool.quick_license_scan(str(program_dir))

        if license_scan["status"] != "success":
            return license_scan

        analysis = {
            "status": "success",
            "program_path": str(program_path),
            "program_directory": str(program_dir),
            "license_files_found": license_scan["files_found"],
            "file_contents": {},
            "analysis_summary": {}
        }

        # If we found potential license files, offer to read them
        if license_scan["files_found"]:
            file_paths = [f["path"] for f in license_scan["files_found"][:5]]  # Limit to first 5

            read_results = self.read_multiple_files(
                file_paths,
                f"Analyze licensing mechanism in {program_path.name}"
            )

            if read_results["status"] == "success":
                for file_data in read_results["files_read"]:
                    analysis["file_contents"][file_data["file_path"]] = file_data["content"]

        # Generate analysis summary
        analysis["analysis_summary"] = {
            "license_files_count": len(license_scan["files_found"]),
            "files_analyzed": len(analysis["file_contents"]),
            "program_name": program_path.stem,
            "directory_scanned": str(program_dir)
        }

        return analysis


def get_ai_file_tools(app_instance=None) -> AIFileTools:
    """Factory function to create AI file tools instance."""
    return AIFileTools(app_instance)
