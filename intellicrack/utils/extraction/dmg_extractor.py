"""
DMG (Apple Disk Image) extraction module for Intellicrack.

This module provides functionality to extract contents from DMG files
for analysis, including macOS applications, frameworks, and resources.

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
import plistlib
import shutil
import struct
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)


class DMGExtractor:
    """Extract contents from DMG (Apple Disk Image) files."""

    def __init__(self):
        """Initialize the DMG extractor."""
        self.logger = logger
        self._temp_dirs = []
        self._mounted_volumes = []
        self._extraction_methods = [
            self._extract_with_hdiutil,
            self._extract_with_7zip,
            self._extract_with_dmg2img,
            self._extract_with_python_parser
        ]

    def __del__(self):
        """Cleanup temporary directories and mounted volumes on deletion."""
        self.cleanup()

    def cleanup(self):
        """Clean up all temporary directories and unmount volumes."""
        # Unmount any mounted DMG volumes
        for volume in self._mounted_volumes:
            try:
                if os.name == 'posix' and os.path.exists(volume):
                    if shutil.which('hdiutil'):
                        subprocess.run(['hdiutil', 'detach', volume], capture_output=True)
                    elif shutil.which('umount'):
                        subprocess.run(['umount', volume], capture_output=True)
                self.logger.debug(f"Unmounted volume: {volume}")
            except Exception as e:
                self.logger.warning(f"Failed to unmount {volume}: {e}")
        self._mounted_volumes.clear()

        # Clean up temporary directories
        for temp_dir in self._temp_dirs:
            try:
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
                    self.logger.debug(f"Cleaned up temporary directory: {temp_dir}")
            except Exception as e:
                self.logger.warning(f"Failed to clean up {temp_dir}: {e}")
        self._temp_dirs.clear()

    def validate_dmg(self, dmg_path: Union[str, Path]) -> Tuple[bool, Optional[str]]:
        """
        Validate if a file is a valid DMG file.

        Args:
            dmg_path: Path to the DMG file

        Returns:
            Tuple of (is_valid, error_message)
        """
        dmg_path = Path(dmg_path)

        if not dmg_path.exists():
            return False, f"File not found: {dmg_path}"

        if not dmg_path.suffix.lower() in ['.dmg', '.smi', '.img', '.sparseimage']:
            return False, f"Invalid file extension: {dmg_path.suffix}"

        # Check DMG signatures
        try:
            with open(dmg_path, 'rb') as f:
                # Read first few bytes for magic signatures
                header = f.read(512)
                
                # Check for various DMG format signatures
                if header.startswith(b'encrcdsa'):  # Encrypted DMG
                    return True, None
                elif header.startswith(b'cdsaencr'):  # Another encrypted format
                    return True, None
                elif b'koly' in header[:512]:  # UDIF trailer signature
                    return True, None
                
                # Check at end of file for koly trailer (UDIF format)
                f.seek(-512, 2)
                trailer = f.read(512)
                if b'koly' in trailer:
                    return True, None
                
                # Check for other disk image formats
                f.seek(0)
                if header.startswith(b'<?xml'):  # XML plist header (sparse bundle)
                    return True, None
                elif header[0:2] == b'BZ':  # bzip2 compressed
                    return True, None
                elif header[0:3] == b'\x1f\x8b\x08':  # gzip compressed
                    return True, None
                    
        except Exception as e:
            return False, f"Failed to read file: {e}"

        # If no recognized signature, still might be valid DMG
        return True, None

    def extract(self, dmg_path: Union[str, Path], output_dir: Optional[Union[str, Path]] = None) -> Dict[str, any]:
        """
        Extract contents from a DMG file.

        Args:
            dmg_path: Path to the DMG file
            output_dir: Optional output directory (creates temp dir if not specified)

        Returns:
            Dictionary containing extraction results and metadata
        """
        dmg_path = Path(dmg_path)
        
        # Validate DMG file
        is_valid, error_msg = self.validate_dmg(dmg_path)
        if not is_valid:
            return {
                'success': False,
                'error': error_msg,
                'dmg_path': str(dmg_path)
            }

        # Create output directory
        if output_dir:
            output_dir = Path(output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
        else:
            output_dir = Path(tempfile.mkdtemp(prefix='dmg_extract_'))
            self._temp_dirs.append(str(output_dir))

        self.logger.info(f"Extracting DMG: {dmg_path} to {output_dir}")

        # Try different extraction methods
        extraction_result = None
        for method in self._extraction_methods:
            try:
                result = method(dmg_path, output_dir)
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
                'dmg_path': str(dmg_path),
                'output_dir': str(output_dir)
            }

        # Analyze extracted contents
        extracted_files = self._analyze_extracted_contents(output_dir)
        
        # Parse app bundles if found
        app_bundles = self._find_app_bundles(output_dir)
        
        return {
            'success': True,
            'dmg_path': str(dmg_path),
            'output_dir': str(output_dir),
            'extraction_method': extraction_result['method'],
            'file_count': len(extracted_files),
            'extracted_files': extracted_files,
            'app_bundles': app_bundles,
            'metadata': self._extract_dmg_metadata(dmg_path)
        }

    def _extract_with_hdiutil(self, dmg_path: Path, output_dir: Path) -> Dict[str, any]:
        """Extract DMG using hdiutil (macOS native tool)."""
        if not shutil.which('hdiutil'):
            raise FileNotFoundError("hdiutil not found (macOS only)")

        try:
            # Create a temporary mount point
            mount_point = Path(tempfile.mkdtemp(prefix='dmg_mount_'))
            self._mounted_volumes.append(str(mount_point))

            # Mount the DMG
            mount_cmd = [
                'hdiutil', 'attach',
                str(dmg_path),
                '-mountpoint', str(mount_point),
                '-nobrowse',  # Don't show in Finder
                '-readonly',  # Mount read-only
                '-noverify'   # Skip verification for speed
            ]

            result = subprocess.run(
                mount_cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode != 0:
                raise RuntimeError(f"Failed to mount DMG: {result.stderr}")

            # Copy contents to output directory
            for item in mount_point.iterdir():
                dest = output_dir / item.name
                if item.is_dir():
                    shutil.copytree(item, dest, symlinks=True)
                else:
                    shutil.copy2(item, dest)

            # Unmount
            subprocess.run(['hdiutil', 'detach', str(mount_point)], capture_output=True)
            self._mounted_volumes.remove(str(mount_point))

            self.logger.info("Successfully extracted DMG with hdiutil")
            return {'success': True, 'method': 'hdiutil'}

        except Exception as e:
            self.logger.debug(f"hdiutil extraction failed: {e}")
            raise

    def _extract_with_7zip(self, dmg_path: Path, output_dir: Path) -> Dict[str, any]:
        """Extract DMG using 7-Zip if available."""
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

            # 7-Zip can extract DMG files directly
            cmd = [
                seven_zip,
                'x',
                '-y',
                f'-o{output_dir}',
                str(dmg_path)
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # DMGs can be large
            )

            if result.returncode == 0:
                self.logger.info("Successfully extracted DMG with 7-Zip")
                
                # 7-Zip might extract to numbered folders, consolidate them
                self._consolidate_7zip_output(output_dir)
                
                return {'success': True, 'method': '7zip'}
            else:
                raise RuntimeError(f"7-Zip failed: {result.stderr}")

        except Exception as e:
            self.logger.debug(f"7-Zip extraction failed: {e}")
            raise

    def _extract_with_dmg2img(self, dmg_path: Path, output_dir: Path) -> Dict[str, any]:
        """Extract DMG using dmg2img + mount (Linux/Unix)."""
        try:
            # Check if dmg2img is available
            dmg2img = shutil.which('dmg2img')
            if not dmg2img:
                raise FileNotFoundError("dmg2img not found")

            # Convert DMG to raw image
            img_path = output_dir / 'converted.img'
            convert_cmd = [
                dmg2img,
                str(dmg_path),
                str(img_path)
            ]

            result = subprocess.run(
                convert_cmd,
                capture_output=True,
                text=True,
                timeout=600
            )

            if result.returncode != 0:
                raise RuntimeError(f"dmg2img conversion failed: {result.stderr}")

            # Mount the converted image
            mount_point = Path(tempfile.mkdtemp(prefix='dmg_mount_'))
            self._mounted_volumes.append(str(mount_point))

            # Try to mount (requires sudo on most systems)
            mount_cmd = ['mount', '-o', 'loop,ro', str(img_path), str(mount_point)]
            
            # First try without sudo
            result = subprocess.run(mount_cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                # Try with sudo if available
                if shutil.which('sudo'):
                    mount_cmd.insert(0, 'sudo')
                    result = subprocess.run(mount_cmd, capture_output=True, text=True)

            if result.returncode == 0:
                # Copy contents
                for item in mount_point.iterdir():
                    dest = output_dir / item.name
                    if item.is_dir():
                        shutil.copytree(item, dest, symlinks=True)
                    else:
                        shutil.copy2(item, dest)

                # Unmount
                umount_cmd = ['umount', str(mount_point)]
                if shutil.which('sudo'):
                    umount_cmd.insert(0, 'sudo')
                subprocess.run(umount_cmd, capture_output=True)

            # Clean up converted image
            img_path.unlink(missing_ok=True)

            self.logger.info("Successfully extracted DMG with dmg2img")
            return {'success': True, 'method': 'dmg2img'}

        except Exception as e:
            self.logger.debug(f"dmg2img extraction failed: {e}")
            raise

    def _extract_with_python_parser(self, dmg_path: Path, output_dir: Path) -> Dict[str, any]:
        """Pure Python DMG parser for basic uncompressed DMGs."""
        try:
            with open(dmg_path, 'rb') as f:
                # Read UDIF trailer (last 512 bytes)
                f.seek(-512, 2)
                trailer_data = f.read(512)
                
                # Look for 'koly' signature
                koly_offset = trailer_data.find(b'koly')
                if koly_offset == -1:
                    raise ValueError("Not a UDIF format DMG")
                
                # Parse koly block (UDIF trailer)
                trailer_start = koly_offset
                if len(trailer_data) - trailer_start < 512:
                    f.seek(-512 - (512 - len(trailer_data) + trailer_start), 2)
                    trailer_data = f.read(512)
                    trailer_start = 0
                
                # Extract key values from trailer
                # Format: 4s signature, 4s version, 4s header_size, ...
                koly = trailer_data[trailer_start:trailer_start + 512]
                
                if len(koly) < 200:  # Minimum koly size
                    raise ValueError("Invalid koly block")
                
                # Parse data fork offset and length (at offset 0x28 and 0x30)
                data_fork_offset = struct.unpack('>Q', koly[0x28:0x30])[0]
                data_fork_length = struct.unpack('>Q', koly[0x30:0x38])[0]
                
                # Parse resource fork (contains partition info)
                rsrc_fork_offset = struct.unpack('>Q', koly[0x48:0x50])[0]
                rsrc_fork_length = struct.unpack('>Q', koly[0x50:0x58])[0]
                
                # Try to extract data fork content
                if data_fork_length > 0:
                    f.seek(data_fork_offset)
                    
                    # Create a basic extraction for uncompressed data
                    extracted_file = output_dir / 'data_fork.bin'
                    chunk_size = 1024 * 1024  # 1MB chunks
                    
                    with open(extracted_file, 'wb') as out:
                        remaining = data_fork_length
                        while remaining > 0:
                            chunk = f.read(min(chunk_size, remaining))
                            if not chunk:
                                break
                            out.write(chunk)
                            remaining -= len(chunk)
                    
                    self.logger.info("Extracted data fork with Python parser")
                    return {'success': True, 'method': 'python_parser'}
                
                raise ValueError("No extractable data found")

        except Exception as e:
            self.logger.debug(f"Python parser extraction failed: {e}")
            raise

    def _consolidate_7zip_output(self, output_dir: Path):
        """Consolidate 7-Zip output which might be in numbered folders."""
        # 7-Zip sometimes extracts HFS+ partitions to folders like "1", "2", etc.
        numbered_dirs = []
        for item in output_dir.iterdir():
            if item.is_dir() and item.name.isdigit():
                numbered_dirs.append(item)
        
        if numbered_dirs:
            # Move contents of numbered directories to root
            for num_dir in sorted(numbered_dirs, key=lambda x: int(x.name)):
                for item in num_dir.iterdir():
                    dest = output_dir / item.name
                    if not dest.exists():
                        shutil.move(str(item), str(dest))
                # Remove empty numbered directory
                try:
                    num_dir.rmdir()
                except:
                    pass

    def _analyze_extracted_contents(self, output_dir: Path) -> List[Dict[str, any]]:
        """Analyze extracted contents and categorize files."""
        extracted_files = []
        
        # Define file categories for macOS
        executable_extensions = {'.app', '.framework', '.dylib', '.so', '.bundle', '.plugin', '.kext'}
        macho_magic = {
            b'\xfe\xed\xfa\xce',  # Mach-O 32-bit
            b'\xfe\xed\xfa\xcf',  # Mach-O 64-bit
            b'\xce\xfa\xed\xfe',  # Mach-O 32-bit (swapped)
            b'\xcf\xfa\xed\xfe',  # Mach-O 64-bit (swapped)
            b'\xca\xfe\xba\xbe',  # Mach-O Fat Binary
            b'\xbe\xba\xfe\xca'   # Mach-O Fat Binary (swapped)
        }
        
        for root, dirs, files in os.walk(output_dir):
            # Check directories for .app bundles
            for dir_name in dirs:
                if dir_name.endswith('.app'):
                    app_path = Path(root) / dir_name
                    relative_path = app_path.relative_to(output_dir)
                    
                    file_info = {
                        'filename': dir_name,
                        'path': str(relative_path),
                        'full_path': str(app_path),
                        'size': self._get_directory_size(app_path),
                        'extension': '.app',
                        'category': 'application_bundle',
                        'analysis_priority': 'critical',
                        'is_directory': True
                    }
                    extracted_files.append(file_info)
            
            # Check files
            for file in files:
                file_path = Path(root) / file
                relative_path = file_path.relative_to(output_dir)
                
                file_info = {
                    'filename': file,
                    'path': str(relative_path),
                    'full_path': str(file_path),
                    'size': file_path.stat().st_size if file_path.exists() else 0,
                    'extension': file_path.suffix.lower(),
                    'is_directory': False
                }
                
                # Check if it's a Mach-O binary by magic bytes
                is_macho = False
                try:
                    with open(file_path, 'rb') as f:
                        magic = f.read(4)
                        if magic in macho_magic:
                            is_macho = True
                except:
                    pass
                
                # Categorize file
                if is_macho or not file_path.suffix and os.access(file_path, os.X_OK):
                    file_info['category'] = 'macho_executable'
                    file_info['analysis_priority'] = 'critical'
                elif file_path.suffix.lower() in executable_extensions:
                    file_info['category'] = 'executable'
                    file_info['analysis_priority'] = 'high'
                elif file_path.suffix.lower() in ['.plist', '.xml', '.json']:
                    file_info['category'] = 'configuration'
                    file_info['analysis_priority'] = 'medium'
                elif file_path.suffix.lower() in ['.nib', '.xib', '.storyboard']:
                    file_info['category'] = 'interface'
                    file_info['analysis_priority'] = 'low'
                elif file_path.suffix.lower() in ['.strings', '.lproj']:
                    file_info['category'] = 'localization'
                    file_info['analysis_priority'] = 'low'
                else:
                    file_info['category'] = 'resource'
                    file_info['analysis_priority'] = 'low'
                
                extracted_files.append(file_info)
        
        # Sort by priority and size
        extracted_files.sort(key=lambda x: (
            {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}[x['analysis_priority']],
            -x['size']
        ))
        
        return extracted_files

    def _get_directory_size(self, path: Path) -> int:
        """Calculate total size of a directory."""
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(path):
            for filename in filenames:
                filepath = Path(dirpath) / filename
                if filepath.exists() and not filepath.is_symlink():
                    total_size += filepath.stat().st_size
        return total_size

    def _find_app_bundles(self, output_dir: Path) -> List[Dict[str, any]]:
        """Find and analyze macOS .app bundles."""
        app_bundles = []
        
        for root, dirs, files in os.walk(output_dir):
            for dir_name in dirs:
                if dir_name.endswith('.app'):
                    app_path = Path(root) / dir_name
                    app_info = self._analyze_app_bundle(app_path)
                    if app_info:
                        app_bundles.append(app_info)
        
        return app_bundles

    def _analyze_app_bundle(self, app_path: Path) -> Optional[Dict[str, any]]:
        """Analyze a macOS .app bundle structure."""
        try:
            app_info = {
                'name': app_path.name,
                'path': str(app_path),
                'bundle_id': None,
                'version': None,
                'executable': None,
                'frameworks': [],
                'plugins': [],
                'resources': []
            }
            
            # Parse Info.plist
            info_plist_path = app_path / 'Contents' / 'Info.plist'
            if info_plist_path.exists():
                try:
                    with open(info_plist_path, 'rb') as f:
                        plist_data = plistlib.load(f)
                        
                    app_info['bundle_id'] = plist_data.get('CFBundleIdentifier')
                    app_info['version'] = plist_data.get('CFBundleShortVersionString')
                    app_info['executable_name'] = plist_data.get('CFBundleExecutable')
                    app_info['minimum_os'] = plist_data.get('LSMinimumSystemVersion')
                    app_info['category'] = plist_data.get('LSApplicationCategoryType')
                    
                    # Find main executable
                    if app_info['executable_name']:
                        exec_path = app_path / 'Contents' / 'MacOS' / app_info['executable_name']
                        if exec_path.exists():
                            app_info['executable'] = str(exec_path)
                except Exception as e:
                    self.logger.debug(f"Failed to parse Info.plist: {e}")
            
            # Find frameworks
            frameworks_dir = app_path / 'Contents' / 'Frameworks'
            if frameworks_dir.exists():
                for item in frameworks_dir.iterdir():
                    if item.suffix == '.framework':
                        app_info['frameworks'].append({
                            'name': item.name,
                            'path': str(item)
                        })
            
            # Find plugins
            plugins_dir = app_path / 'Contents' / 'PlugIns'
            if plugins_dir.exists():
                for item in plugins_dir.iterdir():
                    if item.suffix in ['.bundle', '.plugin', '.appex']:
                        app_info['plugins'].append({
                            'name': item.name,
                            'path': str(item)
                        })
            
            # Count resources
            resources_dir = app_path / 'Contents' / 'Resources'
            if resources_dir.exists():
                resource_count = sum(1 for _ in resources_dir.rglob('*') if _.is_file())
                app_info['resource_count'] = resource_count
            
            return app_info
            
        except Exception as e:
            self.logger.error(f"Failed to analyze app bundle {app_path}: {e}")
            return None

    def _extract_dmg_metadata(self, dmg_path: Path) -> Dict[str, any]:
        """Extract metadata from DMG file."""
        metadata = {
            'file_size': dmg_path.stat().st_size,
            'file_name': dmg_path.name,
            'format': 'unknown',
            'compressed': False,
            'encrypted': False
        }

        try:
            with open(dmg_path, 'rb') as f:
                # Check header for format detection
                header = f.read(512)
                
                if header.startswith(b'encrcdsa') or header.startswith(b'cdsaencr'):
                    metadata['encrypted'] = True
                    metadata['format'] = 'encrypted'
                elif header.startswith(b'<?xml'):
                    metadata['format'] = 'sparse_bundle'
                elif header[0:2] == b'BZ':
                    metadata['compressed'] = True
                    metadata['format'] = 'bzip2_compressed'
                elif header[0:3] == b'\x1f\x8b\x08':
                    metadata['compressed'] = True
                    metadata['format'] = 'gzip_compressed'
                
                # Check for UDIF format by looking for koly trailer
                f.seek(-512, 2)
                trailer = f.read(512)
                if b'koly' in trailer:
                    metadata['format'] = 'UDIF'
                    
                    # Parse some UDIF metadata if possible
                    koly_offset = trailer.find(b'koly')
                    if koly_offset >= 0 and len(trailer) - koly_offset >= 512:
                        koly = trailer[koly_offset:]
                        
                        # Get image variant (at offset 0x7C)
                        if len(koly) > 0x80:
                            variant = struct.unpack('>I', koly[0x7C:0x80])[0]
                            variant_names = {
                                1: 'read/write',
                                2: 'compressed',
                                3: 'sparse'
                            }
                            metadata['variant'] = variant_names.get(variant, f'unknown ({variant})')
                        
                        # Check if compressed (flags at offset 0x38)
                        if len(koly) > 0x3C:
                            flags = struct.unpack('>I', koly[0x38:0x3C])[0]
                            if flags & 0x1:
                                metadata['compressed'] = True

        except Exception as e:
            self.logger.debug(f"Failed to extract DMG metadata: {e}")

        return metadata

    def get_files_by_category(self, extracted_files: List[Dict[str, any]], category: str) -> List[Dict[str, any]]:
        """Get all files of a specific category from extraction results."""
        return [f for f in extracted_files if f.get('category') == category]

    def find_main_executable(self, extracted_files: List[Dict[str, any]], app_bundles: List[Dict[str, any]]) -> Optional[Dict[str, any]]:
        """Attempt to identify the main executable from extracted files."""
        # First check app bundles for main executable
        for app in app_bundles:
            if app.get('executable'):
                # Find the corresponding file info
                for file_info in extracted_files:
                    if file_info['full_path'] == app['executable']:
                        return file_info
        
        # Otherwise look for Mach-O executables
        executables = self.get_files_by_category(extracted_files, 'macho_executable')
        
        if not executables:
            executables = self.get_files_by_category(extracted_files, 'executable')
        
        if not executables:
            return None
        
        # Heuristics to find main executable
        # Prefer executables in MacOS directories
        for exe in executables:
            if '/MacOS/' in exe['path'] or '\\MacOS\\' in exe['path']:
                return exe
        
        # Return the largest executable
        return max(executables, key=lambda x: x['size']) if executables else None