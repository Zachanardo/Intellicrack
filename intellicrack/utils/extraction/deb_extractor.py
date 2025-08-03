"""
DEB (Debian Package) extraction module for Intellicrack.

This module provides functionality to extract contents from DEB files
for analysis, including executables, libraries, and configuration files.

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

import gzip
import logging
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)


class DEBExtractor:
    """Extract contents from DEB (Debian Package) archives."""

        def __init__(self):
        """Initialize the DEB extractor."""
        self.logger = logger
        self._temp_dirs = []
        self._extraction_methods = [
            self._extract_with_dpkg_deb,
            self._extract_with_ar,
            self._extract_with_python_ar,
            self._extract_with_7zip
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

    def validate_deb(self, deb_path: Union[str, Path]) -> Tuple[bool, Optional[str]]:
        """
        Validate if a file is a valid DEB package.

        Args:
            deb_path: Path to the DEB file

        Returns:
            Tuple of (is_valid, error_message)
        """
        deb_path = Path(deb_path)

        if not deb_path.exists():
            return False, f"File not found: {deb_path}"

        if not deb_path.suffix.lower() in ['.deb', '.udeb']:
            return False, f"Invalid file extension: {deb_path.suffix}"

        # Check DEB signature (ar archive format)
        try:
            with open(deb_path, 'rb') as f:
                signature = f.read(8)
                if signature != b'!<arch>\n':
                    return False, "Invalid DEB signature (not an ar archive)"
        except Exception as e:
            return False, f"Failed to read file: {e}"

        return True, None

    def extract(self, deb_path: Union[str, Path], output_dir: Optional[Union[str, Path]] = None) -> Dict[str, any]:
        """
        Extract contents from a DEB file.

        Args:
            deb_path: Path to the DEB file
            output_dir: Optional output directory (creates temp dir if not specified)

        Returns:
            Dictionary containing extraction results and metadata
        """
        deb_path = Path(deb_path)
        
        # Validate DEB file
        is_valid, error_msg = self.validate_deb(deb_path)
        if not is_valid:
            return {
                'success': False,
                'error': error_msg,
                'deb_path': str(deb_path)
            }

        # Create output directory
        if output_dir:
            output_dir = Path(output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
        else:
            output_dir = Path(tempfile.mkdtemp(prefix='deb_extract_'))
            self._temp_dirs.append(str(output_dir))

        self.logger.info(f"Extracting DEB: {deb_path} to {output_dir}")

        # Try different extraction methods
        extraction_result = None
        for method in self._extraction_methods:
            try:
                result = method(deb_path, output_dir)
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
                'deb_path': str(deb_path),
                'output_dir': str(output_dir)
            }

        # Analyze extracted contents
        extracted_files = self._analyze_extracted_contents(output_dir)
        
        # Extract package metadata
        metadata = self._extract_deb_metadata(output_dir)
        
        return {
            'success': True,
            'deb_path': str(deb_path),
            'output_dir': str(output_dir),
            'extraction_method': extraction_result['method'],
            'file_count': len(extracted_files),
            'extracted_files': extracted_files,
            'metadata': metadata
        }

    def _extract_with_dpkg_deb(self, deb_path: Path, output_dir: Path) -> Dict[str, any]:
        """Extract DEB using dpkg-deb (Debian/Ubuntu systems)."""
        try:
            # Check if dpkg-deb is available
            dpkg_deb = shutil.which('dpkg-deb')
            if not dpkg_deb:
                raise FileNotFoundError("dpkg-deb not found in PATH")

            # Extract the entire package
            cmd = [
                dpkg_deb,
                '-x',  # Extract files
                str(deb_path),
                str(output_dir)
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode == 0:
                # Also extract control information
                control_dir = output_dir / 'DEBIAN'
                control_dir.mkdir(exist_ok=True)
                
                control_cmd = [
                    dpkg_deb,
                    '-e',  # Extract control files
                    str(deb_path),
                    str(control_dir)
                ]
                
                subprocess.run(control_cmd, capture_output=True, text=True, timeout=60)
                
                self.logger.info("Successfully extracted DEB with dpkg-deb")
                return {'success': True, 'method': 'dpkg-deb'}
            else:
                raise RuntimeError(f"dpkg-deb failed: {result.stderr}")

        except Exception as e:
            self.logger.debug(f"dpkg-deb extraction failed: {e}")
            raise

    def _extract_with_ar(self, deb_path: Path, output_dir: Path) -> Dict[str, any]:
        """Extract DEB using ar command (Unix/Linux systems)."""
        try:
            # Check if ar is available
            ar_cmd = shutil.which('ar')
            if not ar_cmd:
                raise FileNotFoundError("ar not found in PATH")

            # Create temporary directory for ar extraction
            temp_ar_dir = output_dir / 'ar_temp'
            temp_ar_dir.mkdir(exist_ok=True)

            # Extract ar archive
            cmd = [
                ar_cmd,
                'x',  # Extract
                str(deb_path)
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(temp_ar_dir),
                timeout=300
            )

            if result.returncode != 0:
                raise RuntimeError(f"ar failed: {result.stderr}")

            # Extract control.tar.* and data.tar.*
            self._extract_deb_components(temp_ar_dir, output_dir)
            
            # Clean up temp directory
            shutil.rmtree(temp_ar_dir)
            
            self.logger.info("Successfully extracted DEB with ar")
            return {'success': True, 'method': 'ar'}

        except Exception as e:
            self.logger.debug(f"ar extraction failed: {e}")
            raise

    def _extract_with_python_ar(self, deb_path: Path, output_dir: Path) -> Dict[str, any]:
        """Extract DEB using pure Python implementation."""
        try:
            # Read the ar archive manually
            with open(deb_path, 'rb') as f:
                # Verify ar signature
                signature = f.read(8)
                if signature != b'!<arch>\n':
                    raise ValueError("Not a valid ar archive")

                # Create temporary directory for ar extraction
                temp_ar_dir = output_dir / 'ar_temp'
                temp_ar_dir.mkdir(exist_ok=True)

                # Parse ar archive
                while True:
                    # Read file header
                    header = f.read(60)
                    if not header or len(header) < 60:
                        break

                    # Parse header fields
                    name = header[0:16].strip().decode('ascii', errors='ignore')
                    size = int(header[48:58].strip())

                    # Read file data
                    data = f.read(size)

                    # Skip padding byte if size is odd
                    if size % 2:
                        f.read(1)

                    # Save the file
                    if name and not name.startswith('/'):
                        file_path = temp_ar_dir / name
                        with open(file_path, 'wb') as out_f:
                            out_f.write(data)

            # Extract control.tar.* and data.tar.*
            self._extract_deb_components(temp_ar_dir, output_dir)
            
            # Clean up temp directory
            shutil.rmtree(temp_ar_dir)
            
            self.logger.info("Successfully extracted DEB with Python ar parser")
            return {'success': True, 'method': 'python_ar'}

        except Exception as e:
            self.logger.debug(f"Python ar extraction failed: {e}")
            raise

    def _extract_with_7zip(self, deb_path: Path, output_dir: Path) -> Dict[str, any]:
        """Extract DEB using 7-Zip if available."""
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

            # Extract to temporary directory first
            temp_dir = output_dir / '7zip_temp'
            temp_dir.mkdir(exist_ok=True)

            # Extract the ar archive
            cmd = [
                seven_zip,
                'x',
                '-y',
                f'-o{temp_dir}',
                str(deb_path)
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode != 0:
                raise RuntimeError(f"7-Zip failed: {result.stderr}")

            # Extract control.tar.* and data.tar.*
            self._extract_deb_components(temp_dir, output_dir)
            
            # Clean up temp directory
            shutil.rmtree(temp_dir)
            
            self.logger.info("Successfully extracted DEB with 7-Zip")
            return {'success': True, 'method': '7zip'}

        except Exception as e:
            self.logger.debug(f"7-Zip extraction failed: {e}")
            raise

    def _extract_deb_components(self, ar_dir: Path, output_dir: Path):
        """Extract control.tar.* and data.tar.* from ar extraction directory."""
        # Find and extract control archive
        control_files = list(ar_dir.glob('control.tar*'))
        if control_files:
            control_dir = output_dir / 'DEBIAN'
            control_dir.mkdir(exist_ok=True)
            self._extract_tar_archive(control_files[0], control_dir)

        # Find and extract data archive
        data_files = list(ar_dir.glob('data.tar*'))
        if data_files:
            self._extract_tar_archive(data_files[0], output_dir)

    def _extract_tar_archive(self, archive_path: Path, output_dir: Path):
        """Extract a tar archive (possibly compressed)."""
        try:
            # Determine compression type
            if archive_path.suffix == '.gz':
                mode = 'r:gz'
            elif archive_path.suffix == '.bz2':
                mode = 'r:bz2'
            elif archive_path.suffix == '.xz':
                mode = 'r:xz'
            elif archive_path.suffix == '.zst':
                # zstandard compression - try to handle it
                try:
                    import zstandard as zstd
                    with open(archive_path, 'rb') as f:
                        dctx = zstd.ZstdDecompressor()
                        with dctx.stream_reader(f) as reader:
                            with tarfile.open(fileobj=reader, mode='r|') as tar:
                                tar.extractall(output_dir, filter='data')
                    return
                except ImportError:
                    self.logger.warning("zstandard module not available, trying subprocess")
                    # Try using external zstd command
                    if shutil.which('zstd'):
                        temp_tar = archive_path.with_suffix('')
                        subprocess.run(['zstd', '-d', str(archive_path), '-o', str(temp_tar)], check=True)
                        with tarfile.open(temp_tar, 'r') as tar:
                            tar.extractall(output_dir, filter='data')
                        temp_tar.unlink()
                        return
                    else:
                        raise RuntimeError("Cannot extract .zst archive - zstandard not available")
            else:
                mode = 'r'

            # Extract the archive
            with tarfile.open(archive_path, mode) as tar:
                tar.extractall(output_dir, filter='data')

        except Exception as e:
            self.logger.error(f"Failed to extract tar archive {archive_path}: {e}")
            raise

    def _analyze_extracted_contents(self, output_dir: Path) -> List[Dict[str, any]]:
        """Analyze extracted contents and categorize files."""
        extracted_files = []
        
        # Define file categories
        executable_extensions = {'.so', '.ko', '.a'}
        binary_patterns = ['bin/', 'sbin/', 'usr/bin/', 'usr/sbin/', 'usr/local/bin/']
        config_extensions = {'.conf', '.cfg', '.config', '.ini', '.json', '.yaml', '.yml'}
        config_paths = ['etc/', 'usr/etc/', 'usr/local/etc/']
        script_extensions = {'.sh', '.py', '.pl', '.rb', '.lua'}
        doc_paths = ['usr/share/doc/', 'usr/share/man/', 'usr/share/info/']
        
        for root, dirs, files in os.walk(output_dir):
            # Skip DEBIAN control directory for file listing
            if 'DEBIAN' in Path(root).parts:
                continue
                
            for file in files:
                file_path = Path(root) / file
                relative_path = file_path.relative_to(output_dir)
                
                file_info = {
                    'filename': file,
                    'path': str(relative_path),
                    'full_path': str(file_path),
                    'size': file_path.stat().st_size if file_path.exists() else 0,
                    'extension': file_path.suffix.lower()
                }
                
                # Check if it's executable by permissions
                is_executable = os.access(file_path, os.X_OK)
                
                # Categorize file
                relative_str = str(relative_path).replace('\\', '/')
                
                if is_executable or any(relative_str.startswith(p) for p in binary_patterns):
                    file_info['category'] = 'executable'
                    file_info['analysis_priority'] = 'high'
                elif file_path.suffix.lower() in executable_extensions:
                    file_info['category'] = 'library'
                    file_info['analysis_priority'] = 'high'
                elif (file_path.suffix.lower() in config_extensions or 
                      any(relative_str.startswith(p) for p in config_paths)):
                    file_info['category'] = 'configuration'
                    file_info['analysis_priority'] = 'medium'
                elif file_path.suffix.lower() in script_extensions:
                    file_info['category'] = 'script'
                    file_info['analysis_priority'] = 'high'
                elif any(relative_str.startswith(p) for p in doc_paths):
                    file_info['category'] = 'documentation'
                    file_info['analysis_priority'] = 'low'
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

    def _extract_deb_metadata(self, output_dir: Path) -> Dict[str, any]:
        """Extract metadata from DEB control files."""
        metadata = {
            'control': {},
            'scripts': {},
            'dependencies': {}
        }

        control_dir = output_dir / 'DEBIAN'
        if not control_dir.exists():
            return metadata

        # Parse control file
        control_file = control_dir / 'control'
        if control_file.exists():
            try:
                with open(control_file, 'r', encoding='utf-8') as f:
                    current_field = None
                    current_value = []
                    
                    for line in f:
                        line = line.rstrip('\n')
                        
                        # Check if it's a continuation line
                        if line.startswith(' ') or line.startswith('\t'):
                            if current_field:
                                current_value.append(line.strip())
                        else:
                            # Save previous field
                            if current_field:
                                metadata['control'][current_field] = '\n'.join(current_value)
                            
                            # Parse new field
                            if ':' in line:
                                field, value = line.split(':', 1)
                                current_field = field.strip()
                                current_value = [value.strip()]
                    
                    # Save last field
                    if current_field:
                        metadata['control'][current_field] = '\n'.join(current_value)
                
                # Extract dependency information
                dep_fields = ['Depends', 'Pre-Depends', 'Recommends', 'Suggests', 'Conflicts', 'Breaks', 'Replaces']
                for field in dep_fields:
                    if field in metadata['control']:
                        deps = [d.strip() for d in metadata['control'][field].split(',')]
                        metadata['dependencies'][field.lower()] = deps
                
            except Exception as e:
                self.logger.error(f"Failed to parse control file: {e}")

        # Check for maintainer scripts
        script_names = ['preinst', 'postinst', 'prerm', 'postrm', 'config']
        for script in script_names:
            script_path = control_dir / script
            if script_path.exists():
                metadata['scripts'][script] = {
                    'present': True,
                    'size': script_path.stat().st_size,
                    'executable': os.access(script_path, os.X_OK)
                }

        # Check for md5sums
        md5sums_file = control_dir / 'md5sums'
        if md5sums_file.exists():
            metadata['md5sums_present'] = True

        # Check for conffiles
        conffiles_file = control_dir / 'conffiles'
        if conffiles_file.exists():
            try:
                with open(conffiles_file, 'r') as f:
                    metadata['conffiles'] = [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.logger.error(f"Failed to read conffiles: {e}")

        return metadata

    def get_files_by_category(self, extracted_files: List[Dict[str, any]], category: str) -> List[Dict[str, any]]:
        """Get all files of a specific category from extraction results."""
        return [f for f in extracted_files if f.get('category') == category]

    def find_main_executable(self, extracted_files: List[Dict[str, any]], metadata: Dict[str, any]) -> Optional[Dict[str, any]]:
        """Attempt to identify the main executable from extracted files."""
        executables = self.get_files_by_category(extracted_files, 'executable')
        
        if not executables:
            return None
        
        # Try to use package name from metadata
        package_name = metadata.get('control', {}).get('Package', '').lower()
        
        if package_name:
            # Look for executable matching package name
            for exe in executables:
                if package_name in exe['filename'].lower():
                    return exe
        
        # Look for executables in standard binary directories
        for exe in executables:
            path_str = exe['path'].replace('\\', '/')
            if any(path_str.startswith(p) for p in ['usr/bin/', 'bin/', 'usr/local/bin/']):
                # Prefer non-helper executables
                if not any(helper in exe['filename'].lower() for helper in ['helper', 'daemon', 'service']):
                    return exe
        
        # If no obvious main executable, return the largest
        return max(executables, key=lambda x: x['size']) if executables else None