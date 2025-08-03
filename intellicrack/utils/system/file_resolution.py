"""
Enhanced file resolution utilities for Intellicrack.

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
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)

# Platform detection
IS_WINDOWS = sys.platform.startswith('win')
IS_LINUX = sys.platform.startswith('linux')
IS_MACOS = sys.platform.startswith('darwin')

# Windows COM interface imports (for fallback only)
if IS_WINDOWS:
    try:
        import pythoncom
        import win32com.client
        from win32com.shell import shell, shellcon
        HAS_WIN32 = True
    except ImportError:
        # Windows COM libraries not available - use pure Python parser only
        HAS_WIN32 = False
        pythoncom = win32com = shell = shellcon = None
else:
    HAS_WIN32 = False
    pythoncom = win32com = shell = shellcon = None


class FileTypeInfo:
    """Information about a file type and its analysis capabilities."""

    def __init__(self, extension: str, description: str, category: str,
                 supported: bool = True, analyzer_hint: str = None):
        """Initialize file type information.

        Args:
            extension: File extension (e.g., '.exe')
            description: Human-readable description of file type
            category: Category of file (e.g., 'executable', 'library')
            supported: Whether this file type is supported for analysis
            analyzer_hint: Hint for which analyzer to use
        """
        self.extension = extension.lower()
        self.description = description
        self.category = category
        self.supported = supported
        self.analyzer_hint = analyzer_hint or "generic"


class FileResolver:
    """Enhanced file resolution with support for shortcuts, installers, and multiple formats."""

    # Comprehensive file type registry
    FILE_TYPES = {
        # Windows Executables
        '.exe': FileTypeInfo('.exe', 'Windows Executable', 'executable', True, 'pe'),
        '.dll': FileTypeInfo('.dll', 'Windows Dynamic Library', 'library', True, 'pe'),
        '.sys': FileTypeInfo('.sys', 'Windows System Driver', 'driver', True, 'pe'),
        '.scr': FileTypeInfo('.scr', 'Windows Screen Saver', 'executable', True, 'pe'),
        '.cpl': FileTypeInfo('.cpl', 'Control Panel Item', 'executable', True, 'pe'),
        '.ocx': FileTypeInfo('.ocx', 'ActiveX Control', 'library', True, 'pe'),

        # Windows Shortcuts and Links
        '.lnk': FileTypeInfo('.lnk', 'Windows Shortcut', 'shortcut', True, 'shortcut'),
        '.url': FileTypeInfo('.url', 'Internet Shortcut', 'shortcut', True, 'url'),

        # Windows Installers
        '.msi': FileTypeInfo('.msi', 'Windows Installer Package', 'installer', True, 'msi'),
        '.msp': FileTypeInfo('.msp', 'Windows Installer Patch', 'installer', True, 'msi'),
        '.msm': FileTypeInfo('.msm', 'Windows Installer Merge Module', 'installer', True, 'msi'),
        '.cab': FileTypeInfo('.cab', 'Cabinet Archive', 'archive', True, 'cabinet'),

        # Linux/Unix Executables
        '.so': FileTypeInfo('.so', 'Shared Object Library', 'library', True, 'elf'),
        '.o': FileTypeInfo('.o', 'Object File', 'object', True, 'elf'),
        '.a': FileTypeInfo('.a', 'Static Library Archive', 'library', True, 'ar'),

        # Linux Packages
        '.deb': FileTypeInfo('.deb', 'Debian Package', 'installer', True, 'deb'),
        '.rpm': FileTypeInfo('.rpm', 'Red Hat Package', 'installer', True, 'rpm'),
        '.snap': FileTypeInfo('.snap', 'Snap Package', 'installer', True, 'snap'),
        '.flatpak': FileTypeInfo('.flatpak', 'Flatpak Package', 'installer', True, 'flatpak'),
        '.appimage': FileTypeInfo('.appimage', 'AppImage Package', 'installer', True, 'appimage'),

        # macOS Executables and Packages
        '.app': FileTypeInfo('.app', 'macOS Application Bundle', 'executable', True, 'macho_bundle'),
        '.dylib': FileTypeInfo('.dylib', 'macOS Dynamic Library', 'library', True, 'macho'),
        '.bundle': FileTypeInfo('.bundle', 'macOS Bundle', 'library', True, 'macho_bundle'),
        '.framework': FileTypeInfo('.framework', 'macOS Framework', 'library', True, 'macho_framework'),
        '.pkg': FileTypeInfo('.pkg', 'macOS Installer Package', 'installer', True, 'pkg'),
        '.dmg': FileTypeInfo('.dmg', 'macOS Disk Image', 'installer', True, 'dmg'),

        # Cross-platform formats
        '.dat': FileTypeInfo('.dat', 'Data File', 'data', True, 'generic'),
        '.img': FileTypeInfo('.img', 'Disk Image', 'image', True, 'generic'),
        '.iso': FileTypeInfo('.iso', 'ISO Disk Image', 'image', True, 'iso'),

        # Archive formats
        '.zip': FileTypeInfo('.zip', 'ZIP Archive', 'archive', True, 'zip'),
        '.rar': FileTypeInfo('.rar', 'RAR Archive', 'archive', True, 'rar'),
        '.7z': FileTypeInfo('.7z', '7-Zip Archive', 'archive', True, '7z'),
        '.tar': FileTypeInfo('.tar', 'TAR Archive', 'archive', True, 'tar'),
        '.gz': FileTypeInfo('.gz', 'GZip Archive', 'archive', True, 'gzip'),

        # Firmware and embedded
        '.bin': FileTypeInfo('.bin', 'Firmware Binary', 'firmware', True, 'firmware'),
        '.hex': FileTypeInfo('.hex', 'Intel HEX File', 'firmware', True, 'intel_hex'),
        '.elf': FileTypeInfo('.elf', 'ELF Binary', 'executable', True, 'elf'),
    }

    def __init__(self):
        """Initialize the file resolver."""
        self.logger = logger
        self._msi_extractor = None
        self._extracted_msi_cache = {}

    def resolve_file_path(self, file_path: Union[str, Path]) -> Tuple[str, Dict[str, any]]:
        """
        Resolve a file path, handling shortcuts and returning target information.

        Args:
            file_path: Path to resolve (may be shortcut or direct file)

        Returns:
            Tuple of (resolved_path, metadata_dict)
        """
        file_path = Path(file_path)

        if not file_path.exists():
            return str(file_path), {"error": f"File not found: {file_path}"}

        metadata = {
            "original_path": str(file_path),
            "file_type": self.get_file_type_info(file_path),
            "size": file_path.stat().st_size,
            "is_shortcut": False,
            "resolution_method": "direct"
        }

        # Handle shortcuts
        if file_path.suffix.lower() == '.lnk':
            resolved_path, shortcut_info = self._resolve_windows_shortcut(file_path)
            if resolved_path:
                metadata.update(shortcut_info)
                metadata["is_shortcut"] = True
                metadata["resolution_method"] = "windows_shortcut"
                return resolved_path, metadata
        elif file_path.suffix.lower() == '.url':
            resolved_path, url_info = self._resolve_url_shortcut(file_path)
            if resolved_path:
                metadata.update(url_info)
                metadata["is_shortcut"] = True
                metadata["resolution_method"] = "url_shortcut"
                return resolved_path, metadata

        # Handle macOS aliases
        if IS_MACOS and self._is_macos_alias(file_path):
            resolved_path = self._resolve_macos_alias(file_path)
            if resolved_path:
                metadata["is_shortcut"] = True
                metadata["resolution_method"] = "macos_alias"
                return resolved_path, metadata

        # Handle symbolic links
        if file_path.is_symlink():
            resolved_path = str(file_path.resolve())
            metadata["is_shortcut"] = True
            metadata["resolution_method"] = "symlink"
            metadata["target_path"] = resolved_path
            return resolved_path, metadata

        # Handle MSI files - extract and resolve to main executable
        if file_path.suffix.lower() in ['.msi', '.msp', '.msm']:
            self.logger.info(f"Detected MSI installer: {file_path}")
            exe_path, msi_info = self.resolve_msi_executable(file_path)
            if exe_path:
                metadata.update(msi_info)
                metadata["is_installer"] = True
                metadata["resolution_method"] = "msi_extraction"
                return exe_path, metadata
            else:
                # Return the MSI itself if extraction failed
                metadata["msi_extraction_failed"] = True
                metadata["extraction_error"] = msi_info.get('error', 'Unknown error')

        return str(file_path), metadata

    def get_file_type_info(self, file_path: Union[str, Path]) -> FileTypeInfo:
        """Get file type information for a given path."""
        file_path = Path(file_path)
        extension = file_path.suffix.lower()

        # Check if it's a directory (like .app bundles)
        if file_path.is_dir():
            if extension == '.app':
                return self.FILE_TYPES.get('.app', FileTypeInfo(extension, 'Unknown Directory', 'directory'))
            elif extension == '.framework':
                return self.FILE_TYPES.get('.framework', FileTypeInfo(extension, 'Framework Directory', 'directory'))
            else:
                return FileTypeInfo(extension, 'Directory', 'directory', False)

        return self.FILE_TYPES.get(extension, FileTypeInfo(extension, 'Unknown File Type', 'unknown', False))

    def get_supported_file_filters(self) -> str:
        """Generate Qt file dialog filter string for all supported types."""
        categories = {}

        # Group by category
        for file_type in self.FILE_TYPES.values():
            if file_type.supported:
                category = file_type.category
                if category not in categories:
                    categories[category] = []
                categories[category].append(f"*{file_type.extension}")

        # Build filter string
        filters = []

        # All supported files first
        all_supported = []
        for exts in categories.values():
            all_supported.extend(exts)
        filters.append(f"All Supported Files ({' '.join(sorted(set(all_supported)))})")

        # Category-specific filters
        category_names = {
            'executable': 'Executable Files',
            'library': 'Library Files',
            'installer': 'Installer Packages',
            'shortcut': 'Shortcuts and Links',
            'archive': 'Archive Files',
            'firmware': 'Firmware Files',
            'binary': 'Binary Files',
            'data': 'Data Files',
            'image': 'Disk Images'
        }

        for category, exts in sorted(categories.items()):
            category_name = category_names.get(category, category.title() + ' Files')
            filters.append(f"{category_name} ({' '.join(sorted(exts))})")

        # All files last
        filters.append("All Files (*)")

        return ";;".join(filters)

    def _resolve_windows_shortcut(self, lnk_path: Path) -> Tuple[Optional[str], Dict[str, any]]:
        """Resolve Windows .lnk shortcut file using pure Python parser."""
        try:
            # Import pure Python .lnk parser
            from intellicrack.utils.system.lnk_parser import LnkParser, LnkParseError

            parser = LnkParser()
            lnk_info = parser.parse_lnk_file(lnk_path)

            # Convert to dictionary for easier handling
            shortcut_data = lnk_info.to_dict()

            # Determine the target path
            target_path = lnk_info.target_path

            # If no absolute target path, try to resolve using relative path and working directory
            if not target_path and lnk_info.relative_path:
                if lnk_info.working_directory:
                    target_path = os.path.join(lnk_info.working_directory, lnk_info.relative_path)
                else:
                    # Try relative to shortcut location
                    target_path = os.path.join(str(lnk_path.parent), lnk_info.relative_path)

            # Expand environment variables if present
            if target_path:
                target_path = os.path.expandvars(target_path)

            # Check if target exists
            if target_path and os.path.exists(target_path):
                return target_path, {
                    "target_path": target_path,
                    "working_directory": lnk_info.working_directory,
                    "arguments": lnk_info.command_line_arguments,
                    "description": lnk_info.name or lnk_info.description,
                    "icon_location": lnk_info.icon_location,
                    "shortcut_type": "windows_lnk",
                    "parser_type": "pure_python",
                    "relative_path": lnk_info.relative_path,
                    "creation_time": shortcut_data.get("creation_time"),
                    "write_time": shortcut_data.get("write_time"),
                    "access_time": shortcut_data.get("access_time"),
                    "file_size": lnk_info.file_size,
                    "icon_index": lnk_info.icon_index,
                    "show_command": lnk_info.show_command,
                    "hotkey": lnk_info.hotkey,
                    "file_attributes": parser.get_file_attributes_description(lnk_info.file_attributes),
                    "show_command_desc": parser.get_show_command_description(lnk_info.show_command),
                    "is_unicode": lnk_info.is_unicode,
                    "parse_errors": lnk_info.parse_errors
                }
            else:
                # Fallback to Windows COM if pure Python parsing fails and COM is available
                if IS_WINDOWS and HAS_WIN32:
                    self.logger.info(f"Pure Python parser found target {target_path} but file doesn't exist, trying COM fallback")
                    return self._resolve_windows_shortcut_com(lnk_path)
                else:
                    return None, {
                        "error": f"Shortcut target not found: {target_path}",
                        "parser_type": "pure_python",
                        "parsed_data": shortcut_data
                    }

        except LnkParseError as e:
            self.logger.error(f"Error parsing .lnk file {lnk_path}: {e}")
            
            # Fallback to Windows COM if pure Python parsing fails and COM is available
            if IS_WINDOWS and HAS_WIN32:
                self.logger.info(f"Pure Python .lnk parser failed, trying COM fallback")
                return self._resolve_windows_shortcut_com(lnk_path)
            else:
                return None, {"error": f"Failed to parse .lnk file: {str(e)}"}

        except Exception as e:
            self.logger.error(f"Unexpected error resolving Windows shortcut {lnk_path}: {e}")
            
            # Fallback to Windows COM if pure Python parsing fails and COM is available
            if IS_WINDOWS and HAS_WIN32:
                self.logger.info(f"Pure Python .lnk parser had unexpected error, trying COM fallback")
                return self._resolve_windows_shortcut_com(lnk_path)
            else:
                return None, {"error": f"Failed to resolve shortcut: {str(e)}"}

    def _resolve_windows_shortcut_com(self, lnk_path: Path) -> Tuple[Optional[str], Dict[str, any]]:
        """Resolve Windows .lnk shortcut file using Windows COM interface (fallback)."""
        if not IS_WINDOWS or not HAS_WIN32:
            return None, {"error": "Windows COM not available for shortcut resolution"}

        try:
            # Initialize COM if available
            if hasattr(pythoncom, 'CoInitialize'):
                pythoncom.CoInitialize()

            shell_link = win32com.client.Dispatch("WScript.Shell")
            shortcut = shell_link.CreateShortCut(str(lnk_path))

            target_path = shortcut.Targetpath
            working_directory = shortcut.WorkingDirectory
            arguments = shortcut.Arguments
            description = shortcut.Description
            icon_location = shortcut.IconLocation

            # Uninitialize COM if it was initialized
            if hasattr(pythoncom, 'CoUninitialize'):
                pythoncom.CoUninitialize()

            if target_path and os.path.exists(target_path):
                return target_path, {
                    "target_path": target_path,
                    "working_directory": working_directory,
                    "arguments": arguments,
                    "description": description,
                    "icon_location": icon_location,
                    "shortcut_type": "windows_lnk",
                    "parser_type": "windows_com"
                }
            else:
                return None, {"error": f"Shortcut target not found: {target_path}"}

        except Exception as e:
            self.logger.error(f"Error resolving Windows shortcut with COM {lnk_path}: {e}")
            return None, {"error": f"Failed to resolve shortcut with COM: {str(e)}"}

    def _resolve_url_shortcut(self, url_path: Path) -> Tuple[Optional[str], Dict[str, any]]:
        """Resolve Windows .url internet shortcut file."""
        try:
            # .url files are INI-style text files
            with open(url_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Look for URL= line
            for line in content.splitlines():
                if line.startswith('URL='):
                    url = line[4:].strip()
                    return url, {
                        "target_url": url,
                        "shortcut_type": "internet_url"
                    }

            return None, {"error": "No URL found in internet shortcut"}

        except Exception as e:
            self.logger.error(f"Error resolving URL shortcut {url_path}: {e}")
            return None, {"error": f"Failed to resolve URL shortcut: {str(e)}"}

    def _is_macos_alias(self, file_path: Path) -> bool:
        """Check if file is a macOS alias."""
        if not IS_MACOS:
            return False

        try:
            # Check for alias resource fork or extended attributes
            # This is a simplified check - real alias detection is more complex
            import subprocess
            result = subprocess.run(
                ['file', str(file_path)],
                capture_output=True,
                text=True,
                timeout=5
            )
            return 'alias' in result.stdout.lower()
        except Exception as e:
            self.logger.debug(f"Error checking macOS alias for {file_path}: {e}")
            return False

    def _resolve_macos_alias(self, alias_path: Path) -> Optional[str]:
        """Resolve macOS alias to target path."""
        if not IS_MACOS:
            return None

        try:
            import subprocess

            # Use osascript to resolve alias
            script = f'''
            tell application "Finder"
                set aliasFile to POSIX file "{alias_path}" as alias
                set originalFile to original item of aliasFile
                return POSIX path of originalFile
            end tell
            '''

            result = subprocess.run(
                ['osascript', '-e', script],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                return result.stdout.strip()

        except Exception as e:
            self.logger.error(f"Error resolving macOS alias {alias_path}: {e}")

        return None

    def get_file_metadata(self, file_path: Union[str, Path]) -> Dict[str, any]:
        """Get comprehensive metadata for a file."""
        file_path = Path(file_path)

        if not file_path.exists():
            return {"error": f"File not found: {file_path}"}

        try:
            stat = file_path.stat()
            file_type = self.get_file_type_info(file_path)

            metadata = {
                "path": str(file_path),
                "name": file_path.name,
                "stem": file_path.stem,
                "extension": file_path.suffix,
                "size": stat.st_size,
                "size_human": self._format_bytes(stat.st_size),
                "created": stat.st_ctime,
                "modified": stat.st_mtime,
                "accessed": stat.st_atime,
                "is_file": file_path.is_file(),
                "is_dir": file_path.is_dir(),
                "is_symlink": file_path.is_symlink(),
                "file_type": {
                    "extension": file_type.extension,
                    "description": file_type.description,
                    "category": file_type.category,
                    "supported": file_type.supported,
                    "analyzer_hint": file_type.analyzer_hint
                }
            }

            # Add platform-specific metadata
            if IS_WINDOWS:
                metadata.update(self._get_windows_metadata(file_path))
            elif IS_LINUX:
                metadata.update(self._get_linux_metadata(file_path))
            elif IS_MACOS:
                metadata.update(self._get_macos_metadata(file_path))

            return metadata

        except Exception as e:
            self.logger.error(f"Error getting metadata for {file_path}: {e}")
            return {"error": f"Failed to get metadata: {str(e)}"}

    def _format_bytes(self, bytes_size: int) -> str:
        """Format bytes into human readable string."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.1f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.1f} PB"

    def _get_windows_metadata(self, file_path: Path) -> Dict[str, any]:
        """Get Windows-specific file metadata."""
        metadata = {}

        try:
            # Get file version info if available
            if HAS_WIN32:
                try:
                    import win32api

                    try:
                        version_info = win32api.GetFileVersionInfo(str(file_path), "\\")
                        metadata["version_info"] = version_info
                    except Exception as e:
                        self.logger.debug(f"Failed to get version info for {file_path}: {e}")
                except ImportError as e:
                    self.logger.error("Import error in file_resolution: %s", e)

            # Check if it's a PE file
            if file_path.suffix.lower() in ['.exe', '.dll', '.sys']:
                metadata["is_pe"] = True
                metadata["format_hint"] = "pe"

        except Exception as e:
            self.logger.debug(f"Error getting Windows metadata: {e}")

        return metadata

    def _get_linux_metadata(self, file_path: Path) -> Dict[str, any]:
        """Get Linux-specific file metadata."""
        metadata = {}

        try:
            # Check if it's an ELF file
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                if magic == b'\x7fELF':
                    metadata["is_elf"] = True
                    metadata["format_hint"] = "elf"

            # Get file command output
            import subprocess
            result = subprocess.run(
                ['file', str(file_path)],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                metadata["file_command"] = result.stdout.strip()

        except Exception as e:
            self.logger.debug(f"Error getting Linux metadata: {e}")

        return metadata

    def _get_macos_metadata(self, file_path: Path) -> Dict[str, any]:
        """Get macOS-specific file metadata."""
        metadata = {}

        try:
            # Check for Mach-O format
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                if magic in [b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe',
                           b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe']:
                    metadata["is_macho"] = True
                    metadata["format_hint"] = "macho"

            # Get extended attributes
            try:
                import xattr
                attrs = list(xattr.xattr(file_path))
                if attrs:
                    metadata["extended_attributes"] = attrs
            except ImportError as e:
                self.logger.error("Import error in file_resolution: %s", e)

        except Exception as e:
            self.logger.debug(f"Error getting macOS metadata: {e}")

        return metadata

    def extract_msi_contents(self, msi_path: Union[str, Path], target_dir: Optional[Union[str, Path]] = None) -> Dict[str, any]:
        """
        Extract contents from an MSI installer file.

        Args:
            msi_path: Path to the MSI file
            target_dir: Optional target directory for extraction

        Returns:
            Dictionary with extraction results and file information
        """
        msi_path = Path(msi_path)
        
        # Check if we've already extracted this MSI
        cache_key = str(msi_path.absolute())
        if cache_key in self._extracted_msi_cache and not target_dir:
            cached_result = self._extracted_msi_cache[cache_key]
            # Verify the extraction directory still exists
            if Path(cached_result['output_dir']).exists():
                self.logger.debug(f"Using cached MSI extraction for {msi_path}")
                return cached_result

        # Lazy import MSI extractor
        if self._msi_extractor is None:
            try:
                from intellicrack.utils.extraction import MSIExtractor
                self._msi_extractor = MSIExtractor()
            except ImportError as e:
                self.logger.error(f"Failed to import MSI extractor: {e}")
                return {
                    'success': False,
                    'error': 'MSI extraction module not available',
                    'msi_path': str(msi_path)
                }

        # Extract the MSI
        result = self._msi_extractor.extract(msi_path, target_dir)
        
        if result['success'] and not target_dir:
            # Cache successful extractions to temp directories
            self._extracted_msi_cache[cache_key] = result
        
        return result

    def resolve_msi_executable(self, msi_path: Union[str, Path]) -> Tuple[Optional[str], Dict[str, any]]:
        """
        Extract MSI and resolve to the main executable.

        Args:
            msi_path: Path to the MSI file

        Returns:
            Tuple of (executable_path, metadata)
        """
        # Extract MSI contents
        extraction_result = self.extract_msi_contents(msi_path)
        
        if not extraction_result['success']:
            return None, extraction_result

        # Find main executable
        if self._msi_extractor:
            main_exe = self._msi_extractor.find_main_executable(
                extraction_result['extracted_files']
            )
            
            if main_exe:
                exe_path = main_exe['full_path']
                metadata = {
                    'original_msi': str(msi_path),
                    'extraction_dir': extraction_result['output_dir'],
                    'executable_info': main_exe,
                    'total_files': extraction_result['file_count'],
                    'msi_metadata': extraction_result.get('metadata', {})
                }
                return exe_path, metadata

        return None, {
            'error': 'No main executable found in MSI',
            'extraction_result': extraction_result
        }

    def cleanup_extracted_msi(self, msi_path: Union[str, Path]):
        """Clean up extracted MSI contents for a specific MSI file."""
        cache_key = str(Path(msi_path).absolute())
        
        if cache_key in self._extracted_msi_cache:
            cached_result = self._extracted_msi_cache[cache_key]
            output_dir = cached_result.get('output_dir')
            
            if output_dir and Path(output_dir).exists():
                try:
                    import shutil
                    shutil.rmtree(output_dir)
                    self.logger.debug(f"Cleaned up extracted MSI directory: {output_dir}")
                except Exception as e:
                    self.logger.warning(f"Failed to cleanup MSI extraction: {e}")
            
            del self._extracted_msi_cache[cache_key]

    def cleanup_all_extracted_msi(self):
        """Clean up all cached MSI extractions."""
        if self._msi_extractor:
            self._msi_extractor.cleanup()
        
        # Clean up any cached extractions
        for msi_path in list(self._extracted_msi_cache.keys()):
            self.cleanup_extracted_msi(msi_path)


# Create singleton instance
file_resolver = FileResolver()
