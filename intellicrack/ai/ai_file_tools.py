"""AI File System Tools.

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import fnmatch
import logging
import os
from pathlib import Path
from typing import Any, TypedDict

from ..handlers.pyqt6_handler import QDialog, QDialogButtonBox, QHBoxLayout, QLabel, QPushButton, QTextEdit, QVBoxLayout


logger = logging.getLogger(__name__)

MAX_SEARCH_DEPTH = 5
MAX_FILES_TO_DISPLAY = 10
DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024


class SearchResult(TypedDict):
    """Type definition for file search results."""

    status: str
    search_path: str
    files_found: list[dict[str, Any]]
    directories_scanned: int
    total_files_checked: int


class FileReadResult(TypedDict):
    """Type definition for file read results."""

    status: str
    file_path: str
    content: str
    size: int
    encoding: str
    is_binary: bool


class BatchReadResult(TypedDict):
    """Type definition for batch file read results."""

    status: str
    files_read: list[FileReadResult]
    total_files: int
    total_size: int


DEFAULT_PURPOSE = "License analysis"

__all__ = [
    "AIFileTools",
    "FileReadTool",
    "FileSearchTool",
    "create_approval_dialog",
]


class _ConsoleApprovalDialog:
    """Console-based approval dialog fallback."""

    def __init__(self, operation_type: str, details: str, _parent: Any = None) -> None:
        """Initialize console-based approval dialog."""
        self.operation_type = operation_type
        self.details = details
        self.approved = False

    def exec(self) -> int:
        """Display console approval prompt and return user choice."""
        print("\n" + "=" * 70)
        print(f"AI FILE {self.operation_type.upper()} REQUEST")
        print("=" * 70)
        print(self.details)
        print("\n" + "-" * 70)
        print("WARNING: Only approve if you trust the AI's analysis purpose.")
        print("-" * 70)

        while True:
            try:
                response = input("\nApprove this operation? (y/n): ").strip().lower()
                if response in ("y", "yes"):
                    self.approved = True
                    return 1
                elif response in ("n", "no"):
                    self.approved = False
                    return 0
                else:
                    print("Invalid input. Please enter 'y' or 'n'.")
            except (KeyboardInterrupt, EOFError):
                print("\nOperation cancelled by user.")
                self.approved = False
                return 0


if QDialog is not None:

    class FileApprovalDialog(QDialog):
        """Dialog for requesting user approval for AI file operations."""

        def __init__(self, operation_type: str, details: str, parent: Any = None) -> None:
            """Initialize file operation confirmation dialog."""
            super().__init__(parent)
            self.setWindowTitle(f"AI File {operation_type} Request")
            self.setMinimumSize(600, 400)

            layout = QVBoxLayout()

            header = QLabel(f"The AI wants to {operation_type.lower()} files:")
            header.setStyleSheet("font-weight: bold; font-size: 14px;")
            layout.addWidget(header)

            details_text = QTextEdit()
            details_text.setPlainText(details)
            details_text.setReadOnly(True)
            details_text.setMaximumHeight(200)
            layout.addWidget(details_text)

            warning = QLabel("WARNING️ Only approve if you trust the AI's analysis purpose.")
            warning.setStyleSheet("color: orange; font-weight: bold;")
            layout.addWidget(warning)

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

else:
    FileApprovalDialog = _ConsoleApprovalDialog  # type: ignore[unreachable, misc]


def create_approval_dialog(operation_type: str, details: str, parent: Any = None) -> bool:
    """Create and show approval dialog for AI file operations."""
    dialog = FileApprovalDialog(operation_type, details, parent)
    if QDialog is not None:
        return dialog.exec() == QDialog.DialogCode.Accepted
    else:
        return dialog.exec() == 1  # type: ignore[unreachable]


class FileSearchTool:
    """Tool for AI to search the file system for licensing-related files."""

    def __init__(self, app_instance: Any = None) -> None:
        """Initialize file search tool with app instance."""
        self.app_instance = app_instance
        self.common_license_patterns = [
            "*license*",
            "*licensing*",
            "*lic*",
            "*auth*",
            "*activation*",
            "*register*",
            "*serial*",
            "*key*",
            "*crack*",
            "*patch*",
            "*trial*",
            "*demo*",
            "*evaluation*",
            "*expire*",
            "*validity*",
            "*.cfg",
            "*.ini",
            "*.conf",
            "*.reg",
            "*.dat",
            "*.db",
            "*.sqlite",
        ]

    def search_license_files(self, search_path: str, custom_patterns: list[str] | None = None) -> dict[str, Any]:
        """Search for license-related files in the specified path."""
        if not self._request_search_approval(search_path, custom_patterns):
            return {"status": "denied", "message": "User denied file search request"}

        try:
            return self._perform_file_search(search_path, custom_patterns)
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error in file search")
            return {"status": "error", "message": str(e)}

    def _request_search_approval(self, search_path: str, custom_patterns: list[str] | None) -> bool:
        """Request user approval for the search operation."""
        details = f"""Search Path: {search_path}

Patterns to search for:
{chr(10).join(self.common_license_patterns + (custom_patterns or []))}

Purpose: Find licensing-related files for analysis to identify protection mechanisms."""
        return create_approval_dialog("Search", details, self.app_instance)

    def _perform_file_search(self, search_path: str, custom_patterns: list[str] | None) -> dict[str, Any]:
        """Perform the actual file search."""
        results: dict[str, Any] = {
            "status": "success",
            "search_path": search_path,
            "files_found": [],
            "directories_scanned": 0,
            "total_files_checked": 0,
        }

        patterns = self.common_license_patterns + (custom_patterns or [])
        search_root = Path(search_path)

        if not search_root.exists():
            return {"status": "error", "message": f"Path does not exist: {search_path}"}

        if not search_root.is_dir():
            return {"status": "error", "message": f"Path is not a directory: {search_path}"}

        for root, dirs, files in os.walk(search_root):
            results["directories_scanned"] += 1
            self._process_files_in_directory(root, files, patterns, results)

            # Limit search depth for performance using Path methods
            try:
                rel_parts = Path(root).resolve().relative_to(search_root.resolve()).parts
                if len(rel_parts) > MAX_SEARCH_DEPTH:
                    dirs.clear()
            except ValueError:
                # root is not under search_root (e.g., due to symlinks); skip limiting in this case
                pass

        self._log_search_results(results)
        return results

    def _process_files_in_directory(self, root: str, files: list[str], patterns: list[str], results: dict[str, Any]) -> None:
        """Process files in a directory and update results."""
        for file in files:
            total_checked = results["total_files_checked"]
            if isinstance(total_checked, int):
                results["total_files_checked"] = total_checked + 1
            file_path = Path(root) / file

            for pattern in patterns:
                if fnmatch.fnmatch(file.lower(), pattern.lower()):
                    file_info: dict[str, Any] = {
                        "path": str(file_path),
                        "name": file,
                        "size": file_path.stat().st_size if file_path.exists() else 0,
                        "matched_pattern": pattern,
                        "directory": str(Path(root)),
                    }
                    files_found = results["files_found"]
                    if isinstance(files_found, list):
                        files_found.append(file_info)
                    break

    def _log_search_results(self, results: dict[str, Any]) -> None:
        """Log the results of the file search."""
        if self.app_instance and hasattr(self.app_instance, "update_output"):
            files_found = results.get("files_found", [])
            if isinstance(files_found, list):
                self.app_instance.update_output.emit(
                    f"[AI File Search] Found {len(files_found)} license-related files",
                )

    def quick_license_scan(self, program_directory: str) -> dict[str, Any]:
        """Quick scan for obvious license files in a program's directory.

        Args:
            program_directory: Main program directory to scan

        Returns:
            Dictionary with found license files

        """
        high_priority_patterns = [
            "license.txt",
            "license.dat",
            "license.key",
            "serial.txt",
            "activation.dat",
            "auth.cfg",
            "registration.ini",
            "*.lic",
        ]

        return self.search_license_files(program_directory, high_priority_patterns)


class FileReadTool:
    """Tool for AI to read files with user approval."""

    def __init__(self, app_instance: Any = None, max_file_size: int = DEFAULT_MAX_FILE_SIZE) -> None:
        """Initialize file read tool with app instance and optional max file size.

        Args:
            app_instance: Optional Qt application instance for UI updates
            max_file_size: Maximum file size limit in bytes (default: 10MB)

        """
        self.app_instance = app_instance
        self.max_file_size = max_file_size

    def set_max_file_size(self, max_file_size: int) -> None:
        """Set the maximum file size limit for reading files.

        Args:
            max_file_size: Maximum file size in bytes

        """
        if max_file_size <= 0:
            raise ValueError("Max file size must be positive")
        self.max_file_size = max_file_size

    def read_file_content(self, file_path: str, purpose: str = DEFAULT_PURPOSE) -> dict[str, Any]:
        """Read the content of a file with user approval.

        Args:
            file_path: Path to the file to read
            purpose: Explanation of why the AI wants to read this file

        Returns:
            Dictionary with file content and metadata

        """
        file_path_obj = Path(file_path)

        if not file_path_obj.exists():
            return {"status": "error", "message": f"File does not exist: {file_path}"}

        file_size: int = file_path_obj.stat().st_size

        if file_size > self.max_file_size:
            return {
                "status": "error",
                "message": f"File too large: {file_size} bytes (limit: {self.max_file_size})",
            }

        details = f"""File Path: {file_path}
File Size: {file_size:,} bytes
Purpose: {purpose}

The AI wants to read this file to analyze licensing mechanisms and identify potential bypass locations."""

        if not create_approval_dialog("Read", details, self.app_instance):
            return {"status": "denied", "message": "User denied file read request"}

        try:
            content: str | None = None
            encoding = "utf-8"

            try:
                with open(file_path_obj, encoding="utf-8") as f:
                    content = f.read()
            except UnicodeDecodeError:
                logger.exception("UnicodeDecodeError in ai_file_tools")
                for enc in ["latin-1", "cp1252", "ascii"]:
                    try:
                        with open(file_path_obj, encoding=enc) as f:
                            content = f.read()
                            encoding = enc
                            break
                    except UnicodeDecodeError:
                        logger.exception("UnicodeDecodeError in ai_file_tools with encoding %s", enc)
                        continue

            if content is None:
                with open(file_path_obj, "rb") as f:
                    binary_content = f.read()
                content = f"[Binary file - {len(binary_content)} bytes]"
                encoding = "binary"

            result: dict[str, Any] = {
                "status": "success",
                "file_path": str(file_path_obj),
                "content": content,
                "size": file_size,
                "encoding": encoding,
                "is_binary": encoding == "binary",
            }

            if self.app_instance and hasattr(self.app_instance, "update_output"):
                self.app_instance.update_output.emit(
                    f"[AI File Read] Read {file_path_obj.name} ({file_size:,} bytes)",
                )

            return result

        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error reading file %s", file_path)
            return {"status": "error", "message": str(e)}

    def read_multiple_files(self, file_paths: list[str], purpose: str = DEFAULT_PURPOSE) -> dict[str, Any]:
        """Read multiple files with a single approval request.

        Args:
            file_paths: List of file paths to read
            purpose: Explanation of why the AI wants to read these files

        Returns:
            Dictionary with results for each file

        """
        total_size = 0
        valid_paths: list[Path] = []

        for path in file_paths:
            file_path_obj = Path(path)
            if file_path_obj.exists():
                size = file_path_obj.stat().st_size
                if size <= self.max_file_size:
                    total_size += size
                    valid_paths.append(file_path_obj)

        file_list_str = "\n".join([f"- {p.name} ({p.stat().st_size:,} bytes)" for p in valid_paths[:MAX_FILES_TO_DISPLAY]])
        additional_files = f"... and {len(valid_paths) - MAX_FILES_TO_DISPLAY} more" if len(valid_paths) > MAX_FILES_TO_DISPLAY else ""

        details = f"""Files to read: {len(valid_paths)}
Total size: {total_size:,} bytes
Purpose: {purpose}

Files:
{file_list_str}
{additional_files}"""

        if not create_approval_dialog("Read Multiple", details, self.app_instance):
            return {"status": "denied", "message": "User denied batch file read request"}

        results: dict[str, Any] = {
            "status": "success",
            "files_read": [],
            "total_files": len(valid_paths),
            "total_size": total_size,
        }

        for file_path_obj_ in valid_paths:
            file_result = self.read_file_content(str(file_path_obj_), f"{purpose} (batch)")
            if file_result.get("status") == "success":
                files_read_list = results["files_read"]
                if isinstance(files_read_list, list):
                    files_read_list.append(file_result)

        return results


class AIFileTools:
    """Run class providing file system tools for AI analysis."""

    def __init__(self, app_instance: Any = None, max_file_size: int = DEFAULT_MAX_FILE_SIZE) -> None:
        """Initialize AI file tools with app instance and optional max file size.

        Args:
            app_instance: Optional Qt application instance for UI updates
            max_file_size: Maximum file size limit in bytes (default: 10MB)

        """
        self.app_instance = app_instance
        self.search_tool = FileSearchTool(app_instance)
        self.read_tool = FileReadTool(app_instance, max_file_size)

    def search_for_license_files(self, base_path: str, custom_patterns: list[str] | None = None) -> dict[str, Any]:
        """Search for license-related files."""
        return self.search_tool.search_license_files(base_path, custom_patterns)

    def read_file(self, file_path: str, purpose: str = DEFAULT_PURPOSE) -> dict[str, Any]:
        """Read a single file."""
        return self.read_tool.read_file_content(file_path, purpose)

    def read_multiple_files(self, file_paths: list[str], purpose: str = DEFAULT_PURPOSE) -> dict[str, Any]:
        """Read multiple files."""
        return self.read_tool.read_multiple_files(file_paths, purpose)

    def analyze_program_directory(self, program_path: str) -> dict[str, Any]:
        """Comprehensive analysis of a program's directory structure for licensing.

        Args:
            program_path: Path to the main program executable

        Returns:
            Dictionary with comprehensive analysis results

        """
        program_path_obj = Path(program_path)
        program_dir_obj = program_path_obj.parent

        license_scan = self.search_tool.quick_license_scan(str(program_dir_obj))

        if license_scan.get("status") != "success":
            return license_scan

        analysis: dict[str, Any] = {
            "status": "success",
            "program_path": str(program_path_obj),
            "program_directory": str(program_dir_obj),
            "license_files_found": license_scan.get("files_found", []),
            "file_contents": {},
            "analysis_summary": {},
        }

        files_found = license_scan.get("files_found", [])
        if isinstance(files_found, list) and files_found:
            file_paths = [str(f.get("path", "")) for f in files_found[:5] if isinstance(f, dict)]

            read_results = self.read_multiple_files(
                file_paths,
                f"Analyze licensing mechanism in {program_path_obj.name}",
            )

            if read_results.get("status") == "success":
                files_read = read_results.get("files_read", [])
                if isinstance(files_read, list):
                    for file_data in files_read:
                        if isinstance(file_data, dict):
                            file_path_key = file_data.get("file_path", "")
                            file_content = file_data.get("content", "")
                            if isinstance(analysis["file_contents"], dict):
                                analysis["file_contents"][file_path_key] = file_content

        file_contents = analysis.get("file_contents", {})
        file_contents_len = len(file_contents) if isinstance(file_contents, dict) else 0
        files_found_len = len(files_found) if isinstance(files_found, list) else 0

        analysis["analysis_summary"] = {
            "license_files_count": files_found_len,
            "files_analyzed": file_contents_len,
            "program_name": program_path_obj.stem,
            "directory_scanned": str(program_dir_obj),
        }

        return analysis


def get_ai_file_tools(app_instance: Any = None, max_file_size: int = DEFAULT_MAX_FILE_SIZE) -> AIFileTools:
    """Create AI file tools instance.

    Args:
        app_instance: Optional application instance for UI updates
        max_file_size: Maximum file size limit in bytes (default: 10MB)

    Returns:
        AIFileTools: Configured AI file tools instance

    """
    return AIFileTools(app_instance, max_file_size)
