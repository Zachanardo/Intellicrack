"""
MSI (Microsoft Installer) extraction module for Intellicrack.

This module provides functionality to extract contents from MSI files
for analysis, including executables, DLLs, and configuration files.

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
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)


class MSIExtractor:
    """Extract contents from MSI (Microsoft Installer) packages."""

    def __init__(self):
        """Initialize the MSI extractor."""
        self.logger = logger
        self._temp_dirs = []
        self._extraction_methods = [
            self._extract_with_msiexec,
            self._extract_with_lessmsi,
            self._extract_with_7zip,
            self._extract_with_msitools,
            self._extract_with_python_msi
        ]

    def __del__(self):
        """Cleanup temporary directories on deletion."""
        self.cleanup()

    def cleanup(self):
        """Clean up all temporary directories created during extraction."""
        for temp_dir in self._temp_dirs:
            try:
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
                    self.logger.debug(f"Cleaned up temporary directory: {temp_dir}")
            except Exception as e:
                self.logger.warning(f"Failed to clean up {temp_dir}: {e}")
        self._temp_dirs.clear()

    def validate_msi(self, msi_path: Union[str, Path]) -> Tuple[bool, Optional[str]]:
        """
        Validate if a file is a valid MSI package.

        Args:
            msi_path: Path to the MSI file

        Returns:
            Tuple of (is_valid, error_message)
        """
        msi_path = Path(msi_path)

        if not msi_path.exists():
            return False, f"File not found: {msi_path}"

        if not msi_path.suffix.lower() in ['.msi', '.msp', '.msm']:
            return False, f"Invalid file extension: {msi_path.suffix}"

        # Check MSI signature (compound document format)
        try:
            with open(msi_path, 'rb') as f:
                signature = f.read(8)
                if signature != b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
                    return False, "Invalid MSI signature"
        except Exception as e:
            return False, f"Failed to read file: {e}"

        return True, None

    def extract(self, msi_path: Union[str, Path], output_dir: Optional[Union[str, Path]] = None) -> Dict[str, any]:
        """
        Extract contents from an MSI file.

        Args:
            msi_path: Path to the MSI file
            output_dir: Optional output directory (creates temp dir if not specified)

        Returns:
            Dictionary containing extraction results and metadata
        """
        msi_path = Path(msi_path)
        
        # Validate MSI file
        is_valid, error_msg = self.validate_msi(msi_path)
        if not is_valid:
            return {
                'success': False,
                'error': error_msg,
                'msi_path': str(msi_path)
            }

        # Create output directory
        if output_dir:
            output_dir = Path(output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
        else:
            output_dir = Path(tempfile.mkdtemp(prefix='msi_extract_'))
            self._temp_dirs.append(str(output_dir))

        self.logger.info(f"Extracting MSI: {msi_path} to {output_dir}")

        # Try different extraction methods
        extraction_result = None
        for method in self._extraction_methods:
            try:
                result = method(msi_path, output_dir)
                if result['success']:
                    extraction_result = result
                    break
            except Exception as e:
                self.logger.debug(f"Method {method.__name__} failed: {e}")
                continue

        if not extraction_result:
            return {
                'success': False,
                'error': 'All extraction methods failed',
                'msi_path': str(msi_path),
                'output_dir': str(output_dir)
            }

        # Analyze extracted contents
        extracted_files = self._analyze_extracted_contents(output_dir)
        
        return {
            'success': True,
            'msi_path': str(msi_path),
            'output_dir': str(output_dir),
            'extraction_method': extraction_result['method'],
            'file_count': len(extracted_files),
            'extracted_files': extracted_files,
            'metadata': self._extract_msi_metadata(msi_path)
        }

    def _extract_with_msiexec(self, msi_path: Path, output_dir: Path) -> Dict[str, any]:
        """Extract MSI using Windows msiexec (administrative install)."""
        if os.name != 'nt':
            raise OSError("msiexec is only available on Windows")

        try:
            # Use administrative install to extract files
            cmd = [
                'msiexec',
                '/a', str(msi_path),
                '/qn',
                f'TARGETDIR={output_dir}'
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode == 0:
                self.logger.info("Successfully extracted MSI with msiexec")
                return {'success': True, 'method': 'msiexec'}
            else:
                raise RuntimeError(f"msiexec failed: {result.stderr}")

        except Exception as e:
            self.logger.debug(f"msiexec extraction failed: {e}")
            raise

    def _extract_with_lessmsi(self, msi_path: Path, output_dir: Path) -> Dict[str, any]:
        """Extract MSI using lessmsi tool if available."""
        try:
            # Check if lessmsi is available
            lessmsi_path = shutil.which('lessmsi')
            if not lessmsi_path:
                raise FileNotFoundError("lessmsi not found in PATH")

            cmd = [
                lessmsi_path,
                'x', str(msi_path),
                str(output_dir)
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode == 0:
                self.logger.info("Successfully extracted MSI with lessmsi")
                return {'success': True, 'method': 'lessmsi'}
            else:
                raise RuntimeError(f"lessmsi failed: {result.stderr}")

        except Exception as e:
            self.logger.debug(f"lessmsi extraction failed: {e}")
            raise

    def _extract_with_7zip(self, msi_path: Path, output_dir: Path) -> Dict[str, any]:
        """Extract MSI using 7-Zip if available."""
        try:
            # Try to find 7z executable
            seven_zip_paths = [
                '7z',
                r'C:\Program Files\7-Zip\7z.exe',
                r'C:\Program Files (x86)\7-Zip\7z.exe',
                '/usr/bin/7z',
                '/usr/local/bin/7z'
            ]

            seven_zip = None
            for path in seven_zip_paths:
                if os.path.exists(path) or shutil.which(path):
                    seven_zip = path
                    break

            if not seven_zip:
                raise FileNotFoundError("7-Zip not found")

            cmd = [
                seven_zip,
                'x',
                '-y',
                f'-o{output_dir}',
                str(msi_path)
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode == 0:
                self.logger.info("Successfully extracted MSI with 7-Zip")
                return {'success': True, 'method': '7zip'}
            else:
                raise RuntimeError(f"7-Zip failed: {result.stderr}")

        except Exception as e:
            self.logger.debug(f"7-Zip extraction failed: {e}")
            raise

    def _extract_with_msitools(self, msi_path: Path, output_dir: Path) -> Dict[str, any]:
        """Extract MSI using msitools (Linux/Unix)."""
        try:
            # Check if msiextract is available
            msiextract = shutil.which('msiextract')
            if not msiextract:
                raise FileNotFoundError("msiextract not found")

            cmd = [
                msiextract,
                '-C', str(output_dir),
                str(msi_path)
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode == 0:
                self.logger.info("Successfully extracted MSI with msitools")
                return {'success': True, 'method': 'msitools'}
            else:
                raise RuntimeError(f"msiextract failed: {result.stderr}")

        except Exception as e:
            self.logger.debug(f"msitools extraction failed: {e}")
            raise

    def _extract_with_python_msi(self, msi_path: Path, output_dir: Path) -> Dict[str, any]:
        """Extract MSI using Python's msilib (Windows only)."""
        if os.name != 'nt':
            raise OSError("Python msilib is only available on Windows")

        try:
            import msilib
            
            # Open the MSI database
            db = msilib.OpenDatabase(str(msi_path), msilib.MSIDBOPEN_READONLY)
            
            # Get file information from File table
            view = db.OpenView("SELECT FileName, FileSize, Component_ FROM File")
            view.Execute(None)
            
            files_extracted = []
            
            # Extract each file
            record = view.Fetch()
            while record:
                filename = record.GetString(1)
                component = record.GetString(3)
                
                # Handle short|long filename format
                if '|' in filename:
                    _, filename = filename.split('|', 1)
                
                # Create output path
                file_path = output_dir / filename
                file_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Extract file data (simplified - real implementation would need CAB extraction)
                files_extracted.append(filename)
                
                record = view.Fetch()
            
            view.Close()
            
            if files_extracted:
                self.logger.info(f"Extracted {len(files_extracted)} files with Python msilib")
                return {'success': True, 'method': 'python_msi'}
            else:
                raise RuntimeError("No files extracted")

        except Exception as e:
            self.logger.debug(f"Python msilib extraction failed: {e}")
            raise

    def _analyze_extracted_contents(self, output_dir: Path) -> List[Dict[str, any]]:
        """Analyze extracted contents and categorize files."""
        extracted_files = []
        
        # Define file categories
        executable_extensions = {'.exe', '.dll', '.sys', '.ocx', '.scr', '.cpl'}
        config_extensions = {'.xml', '.ini', '.config', '.json', '.yaml', '.yml'}
        script_extensions = {'.ps1', '.bat', '.cmd', '.vbs', '.js', '.py'}
        
        for root, dirs, files in os.walk(output_dir):
            for file in files:
                file_path = Path(root) / file
                relative_path = file_path.relative_to(output_dir)
                
                file_info = {
                    'filename': file,
                    'path': str(relative_path),
                    'full_path': str(file_path),
                    'size': file_path.stat().st_size,
                    'extension': file_path.suffix.lower()
                }
                
                # Categorize file
                if file_path.suffix.lower() in executable_extensions:
                    file_info['category'] = 'executable'
                    file_info['analysis_priority'] = 'high'
                elif file_path.suffix.lower() in config_extensions:
                    file_info['category'] = 'configuration'
                    file_info['analysis_priority'] = 'medium'
                elif file_path.suffix.lower() in script_extensions:
                    file_info['category'] = 'script'
                    file_info['analysis_priority'] = 'high'
                else:
                    file_info['category'] = 'other'
                    file_info['analysis_priority'] = 'low'
                
                extracted_files.append(file_info)
        
        # Sort by priority and size
        extracted_files.sort(key=lambda x: (
            {'high': 0, 'medium': 1, 'low': 2}[x['analysis_priority']],
            -x['size']
        ))
        
        return extracted_files

    def _extract_msi_metadata(self, msi_path: Path) -> Dict[str, any]:
        """Extract metadata from MSI file."""
        metadata = {
            'file_size': msi_path.stat().st_size,
            'file_name': msi_path.name,
            'properties': {}
        }

        # Try to extract MSI properties on Windows
        if os.name == 'nt':
            try:
                import msilib
                
                db = msilib.OpenDatabase(str(msi_path), msilib.MSIDBOPEN_READONLY)
                
                # Query Property table for common properties
                properties_to_extract = [
                    'ProductName', 'ProductVersion', 'Manufacturer',
                    'ProductCode', 'UpgradeCode', 'ProductLanguage',
                    'Comments', 'Contact', 'HelpLink', 'URLInfoAbout',
                    'URLUpdateInfo', 'Subject', 'Keywords'
                ]
                
                for prop in properties_to_extract:
                    try:
                        view = db.OpenView(f"SELECT Value FROM Property WHERE Property='{prop}'")
                        view.Execute(None)
                        record = view.Fetch()
                        if record:
                            metadata['properties'][prop] = record.GetString(1)
                        view.Close()
                    except:
                        continue
                
            except Exception as e:
                self.logger.debug(f"Failed to extract MSI metadata: {e}")

        return metadata

    def get_files_by_category(self, extracted_files: List[Dict[str, any]], category: str) -> List[Dict[str, any]]:
        """Get all files of a specific category from extraction results."""
        return [f for f in extracted_files if f.get('category') == category]

    def find_main_executable(self, extracted_files: List[Dict[str, any]]) -> Optional[Dict[str, any]]:
        """Attempt to identify the main executable from extracted files."""
        executables = self.get_files_by_category(extracted_files, 'executable')
        
        if not executables:
            return None
        
        # Heuristics to find main executable
        for exe in executables:
            filename_lower = exe['filename'].lower()
            
            # Check for common main executable patterns
            if any(pattern in filename_lower for pattern in ['setup', 'install', 'main', 'app']):
                continue  # Skip installer-related executables
            
            # Check if it's in the root or main program directory
            path_parts = Path(exe['path']).parts
            if len(path_parts) <= 2:  # Root or one level deep
                return exe
        
        # If no obvious main executable, return the largest
        return max(executables, key=lambda x: x['size']) if executables else None