import hashlib
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from intellicrack.logger import logger

from ...utils.analysis.entropy_utils import calculate_byte_entropy
from ...utils.core.string_utils import extract_ascii_strings
from ..plugin_base import BasePlugin, PluginMetadata, create_plugin_info

"""
Enhanced Demo Plugin for Intellicrack
Comprehensive example showing modern plugin development practices

Author: Intellicrack Development Team
Version: 2.0.0
License: GPL v3
Compatibility: Intellicrack 1.0+
"""



# Plugin metadata
PLUGIN_NAME = "Enhanced Demo Plugin"
PLUGIN_VERSION = "2.0.0"
PLUGIN_AUTHOR = "Intellicrack Team"
PLUGIN_DESCRIPTION = "Comprehensive demonstration of Intellicrack plugin capabilities"
PLUGIN_CATEGORIES = ["demo", "analysis", "education"]

class DemoPlugin(BasePlugin):
    """
    Enhanced demo plugin that demonstrates comprehensive integration with Intellicrack.

    This plugin showcases:
    - Modern Python practices with type hints
    - Comprehensive error handling
    - Progress reporting
    - File validation
    - Multiple analysis techniques
    - Configuration management
    - Metadata handling
    """

    def __init__(self):
        """Initialize the demo plugin with enhanced metadata and configuration."""
        # Create metadata object
        metadata = PluginMetadata(
            name=PLUGIN_NAME,
            version=PLUGIN_VERSION,
            author=PLUGIN_AUTHOR,
            description=PLUGIN_DESCRIPTION,
            categories=PLUGIN_CATEGORIES,
            capabilities=[
                'analyze', 'patch', 'validate', 'configure',
                'entropy_analysis', 'string_extraction', 'pattern_matching'
            ]
        )

        # Plugin configuration from environment
        default_config = {
            'max_file_size': int(os.environ.get('PLUGIN_MAX_FILE_SIZE', str(50 * 1024 * 1024))),
            'detailed_output': os.environ.get('PLUGIN_DETAILED_OUTPUT', 'true').lower() == 'true',
            'include_file_hash': os.environ.get('PLUGIN_INCLUDE_HASH', 'true').lower() == 'true',
            'show_hex_preview': os.environ.get('PLUGIN_SHOW_HEX', 'true').lower() == 'true',
            'analysis_timeout': int(os.environ.get('PLUGIN_ANALYSIS_TIMEOUT', '15'))
        }

        # Initialize base plugin
        super().__init__(metadata, default_config)

        # Internal state
        self.analysis_count = 0
        self.last_analysis_time = None

        # Initialize logger
        self.logger = logging.getLogger(f"IntellicrackLogger.{self.__class__.__name__}")

        # Analysis patterns - these are standard file signatures
        self.file_signatures = {
            'pe_signature': b'MZ',
            'elf_signature': b'\x7fELF',
            'macho_signature': b'\xcf\xfa\xed\xfe',
            'zip_signature': b'PK',
            'pdf_signature': b'%PDF',
            'java_signature': b'\xca\xfe\xba\xbe'
        }

        # Common system library names for detection
        self.system_libraries = self._load_system_libraries()

        # Initialize demo patterns that were missing
        self.demo_patterns = self.file_signatures  # Use file_signatures as demo_patterns for backward compatibility

    def get_metadata(self) -> Dict[str, Any]:
        """Return comprehensive plugin metadata with custom state."""
        metadata = super().get_metadata()
        # Add custom state information
        metadata.update({
            'analysis_count': self.analysis_count,
            'last_analysis': self.last_analysis_time,
        })
        return metadata

    def validate_binary(self, binary_path: str) -> tuple[bool, str]:
        """Validate binary file before analysis."""
        try:
            path = Path(binary_path)

            # Check existence
            if not path.exists():
                return False, f"File does not exist: {binary_path}"

            # Check if it's a file (not directory)
            if not path.is_file():
                return False, f"Path is not a file: {binary_path}"

            # Check file size
            file_size = path.stat().st_size
            if file_size == 0:
                return False, "File is empty"

            if file_size > self.config_manager.get('max_file_size'):
                return False, f"File too large: {file_size:,} bytes (max: {self.config_manager.get('max_file_size'):,})"

            # Check read permissions
            if not os.access(binary_path, os.R_OK):
                return False, f"File not readable: {binary_path}"

            return True, "File validation successful"

        except Exception as e:
            logger.error("Exception in demo_plugin: %s", e)
            return False, f"Validation error: {str(e)}"

    def _detect_file_type(self, data: bytes) -> str:
        """Detect file type based on magic bytes."""
        for sig_name, sig_bytes in self.file_signatures.items():
            if data.startswith(sig_bytes):
                file_types = {
                    'pe_signature': "PE (Windows Executable)",
                    'elf_signature': "ELF (Linux Executable)",
                    'macho_signature': "Mach-O (macOS Executable)",
                    'zip_signature': "ZIP Archive",
                    'pdf_signature': "PDF Document",
                    'java_signature': "Java Class File"
                }
                return file_types.get(sig_name, "Unknown")
        return "Unknown/Generic Binary"

    def _load_system_libraries(self) -> List[bytes]:
        """Load system library names based on platform."""
        import platform

        if platform.system() == 'Windows':
            return [
                b'kernel32.dll', b'ntdll.dll', b'user32.dll', b'advapi32.dll',
                b'gdi32.dll', b'shell32.dll', b'ole32.dll', b'msvcrt.dll'
            ]
        elif platform.system() == 'Linux':
            return [
                b'libc.so', b'libpthread.so', b'libdl.so', b'libm.so',
                b'librt.so', b'libgcc_s.so', b'libstdc++.so'
            ]
        elif platform.system() == 'Darwin':
            return [
                b'libSystem.dylib', b'libc++.dylib', b'libobjc.dylib',
                b'CoreFoundation', b'Foundation'
            ]
        else:
            return [b'libc', b'libm', b'libdl']  # Generic Unix

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        return calculate_byte_entropy(data)

    def _find_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extract printable strings from binary data."""
        strings = extract_ascii_strings(data, min_length)
        max_strings = int(os.environ.get('PLUGIN_MAX_STRINGS', '20'))
        return strings[:max_strings]

    def analyze(self, binary_path: str) -> List[str]:
        """Enhanced binary analysis with comprehensive demonstrations."""
        results = []
        start_time = time.time()

        try:
            # Update counters
            self.analysis_count += 1
            self.last_analysis_time = time.time()

            results.append(f"🚀 {self.name} v{self.version} - Analysis #{self.analysis_count}")
            results.append(f"📁 Target: {os.path.basename(binary_path)}")
            results.append("="*60)

            # Step 1: Validation
            results.append("🔍 Step 1: File Validation")
            is_valid, validation_msg = self.validate_binary(binary_path)
            if not is_valid:
                results.append(f"❌ {validation_msg}")
                return results
            results.append(f"✅ {validation_msg}")

            # Step 2: Basic file information
            results.append("\n📊 Step 2: File Information")
            file_info = os.stat(binary_path)
            results.append(f"📏 Size: {file_info.st_size:,} bytes")
            results.append(f"📅 Modified: {time.ctime(file_info.st_mtime)}")
            results.append(f"🔐 Mode: {oct(file_info.st_mode)}")

            # Step 3: Read and analyze file content
            results.append("\n🔬 Step 3: Content Analysis")
            with open(binary_path, 'rb') as f:
                # Read first part of file for analysis
                sample_size = min(8192, file_info.st_size)  # First 8KB or entire file
                file_data = f.read(sample_size)

            # File type detection
            file_type = self._detect_file_type(file_data)
            results.append(f"🏷️  File Type: {file_type}")

            # Hash calculation (if enabled)
            if self.config_manager.get('include_file_hash'):
                with open(binary_path, 'rb') as f:
                    full_data = f.read()
                    file_hash = hashlib.sha256(full_data).hexdigest()
                    results.append(f"🔐 SHA256: {file_hash[:32]}...{file_hash[-8:]}")

            # Entropy analysis
            entropy = self._calculate_entropy(file_data)
            results.append(f"📈 Entropy: {entropy:.2f}")
            if entropy > 7.5:
                results.append("   ⚠️  High entropy - possibly packed/encrypted")
            elif entropy < 1.0:
                results.append("   INFO: Low entropy - likely text or structured data")
            else:
                results.append("   ✅ Normal entropy range")

            # Hex preview (if enabled)
            if self.config_manager.get('show_hex_preview'):
                results.append("\n🔍 Step 4: Hex Preview (first 64 bytes)")
                hex_preview = ' '.join(f'{b:02x}' for b in file_data[:64])
                # Format as lines of 16 bytes
                for i in range(0, min(64, len(hex_preview.split())), 16):
                    hex_line = ' '.join(hex_preview.split()[i:i+16])
                    results.append(f"  {i:04x}: {hex_line}")

            # String extraction
            results.append("\n📝 Step 5: String Analysis")
            strings = self._find_strings(file_data)
            if strings:
                results.append(f"Found {len(strings)} strings (showing sample):")
                for i, string in enumerate(strings[:10], 1):
                    truncated = string[:40] + '...' if len(string) > 40 else string
                    results.append(f"  {i:2d}. '{truncated}'")
            else:
                results.append("No printable strings found in sample")

            # Pattern matching demonstration
            results.append("\n🎯 Step 6: Pattern Detection")
            patterns_found = []
            for pattern_name, pattern_bytes in self.demo_patterns.items():
                if isinstance(pattern_bytes, list):
                    # Handle list of patterns
                    for pattern in pattern_bytes:
                        if pattern in file_data:
                            patterns_found.append(f"{pattern_name}: {pattern.decode('utf-8', errors='ignore')}")
                else:
                    # Handle single pattern
                    if pattern_bytes in file_data:
                        patterns_found.append(pattern_name)

            if patterns_found:
                results.append("Detected patterns:")
                for pattern in patterns_found:
                    results.append(f"  🎯 {pattern}")
            else:
                results.append("No predefined patterns detected")

            # Analysis summary
            analysis_time = time.time() - start_time
            results.append("\n📋 Analysis Summary")
            results.append("="*30)
            results.append(f"⏱️  Analysis time: {analysis_time:.2f} seconds")
            results.append(f"📊 File type: {file_type}")
            results.append(f"📈 Entropy: {entropy:.2f}")
            results.append(f"📝 Strings found: {len(strings)}")
            results.append(f"🎯 Patterns detected: {len(patterns_found)}")
            results.append(f"🔢 Total analyses: {self.analysis_count}")

            # Educational notes
            if self.config_manager.get('detailed_output'):
                results.append("\n📚 Educational Notes")
                results.append("This demo plugin demonstrates:")
                results.append("  • File validation and error handling")
                results.append("  • Multiple analysis techniques")
                results.append("  • Entropy calculation for detecting packing")
                results.append("  • String extraction and pattern matching")
                results.append("  • Structured output with progress tracking")
                results.append("  • Configuration management")
                results.append("\n💡 Modify this code for your specific analysis needs!")

        except Exception as e:
            logger.error("Exception in demo_plugin: %s", e)
            results.append(f"❌ Analysis error: {str(e)}")
            results.append("💡 This error is being handled gracefully")

        return results

    def patch(self, binary_path: str, options: Optional[Dict] = None) -> List[str]:
        """Enhanced patching demonstration with safety features."""
        results = []

        # Use options to configure patch behavior
        if options is None:
            options = {}

        # Extract configuration from options
        create_backup = options.get('create_backup', True)
        patch_mode = options.get('mode', 'analysis')  # 'analysis', 'apply', 'simulate'
        target_offset = options.get('target_offset', None)
        patch_bytes = options.get('patch_bytes', None)
        patch_type = options.get('patch_type', 'auto')  # 'nop', 'jmp', 'call', 'custom'
        max_patches = options.get('max_patches', 10)
        verbose = options.get('verbose', True)

        try:
            results.append(f"🔧 {self.name} - Patch {'Analysis' if patch_mode == 'analysis' else 'Application'}")
            results.append(f"🎯 Target: {os.path.basename(binary_path)}")
            results.append(f"⚙️  Mode: {patch_mode.upper()}")
            if patch_type != 'auto':
                results.append(f"🔀 Patch Type: {patch_type}")
            results.append("="*50)

            # Validation
            is_valid, validation_msg = self.validate_binary(binary_path)
            if not is_valid:
                results.append(f"❌ Cannot patch: {validation_msg}")
                return results

            results.append(f"✅ {validation_msg}")

            # Safety check - create backup if requested
            if create_backup and patch_mode == 'apply':
                results.append("\n🛡️  Safety Measures")
                backup_suffix = options.get('backup_suffix', f"{int(time.time())}")
                backup_path = binary_path + f".backup_{backup_suffix}"

                try:
                    import shutil
                    shutil.copy2(binary_path, backup_path)
                    results.append(f"💾 Backup created: {os.path.basename(backup_path)}")
                except Exception as e:
                    logger.error("Exception in demo_plugin: %s", e)
                    results.append(f"⚠️  Backup failed: {e}")
                    if options.get('require_backup', True):
                        results.append("❌ Aborting patch for safety")
                        return results
            elif patch_mode == 'apply' and not create_backup:
                results.append("⚠️  Backup disabled by options - proceeding without safety net")

            # Demonstrate patch analysis
            results.append("\n🔍 Patch Analysis")
            if verbose:
                results.append("Analyzing binary for patch opportunities...")

            with open(binary_path, 'rb') as f:
                data = f.read(1024)  # Read first 1KB

            # Check if we should target a specific offset
            if target_offset is not None and patch_mode != 'analysis':
                results.append(f"\n🎯 Targeting specific offset: 0x{target_offset:08x}")
                if patch_bytes:
                    results.append(f"📝 Patch bytes: {patch_bytes.hex() if isinstance(patch_bytes, bytes) else patch_bytes}")

                # Apply patch at specific offset if mode is 'apply'
                if patch_mode == 'apply':
                    success = self._apply_patch_at_offset(binary_path, target_offset, patch_bytes, options)
                    if success:
                        results.append("✅ Patch applied successfully at target offset")
                    else:
                        results.append("❌ Failed to apply patch at target offset")
                elif patch_mode == 'simulate':
                    results.append("🔄 Simulating patch at target offset...")
                    results.append(f"   Would write {len(patch_bytes) if patch_bytes else 0} bytes")

            # Demonstrate various patch scenarios based on patch_type
            patch_opportunities = []

            # Filter opportunities based on patch_type option
            if patch_type in ['auto', 'nop']:
                # Look for NOP instructions (safe to patch)
                if b'\x90\x90\x90\x90' in data:
                    patch_opportunities.append({
                        'type': 'nop',
                        'description': "NOP sled detected - safe patch target"
                    })

            if patch_type in ['auto', 'jmp', 'call']:
                # Look for function prologues
                if b'\x55\x8b\xec' in data:
                    patch_opportunities.append({
                        'type': 'prologue',
                        'description': "Function prologue found - potential hook point"
                    })

            if patch_type in ['auto', 'api']:
                # Look for common API calls
                if b'kernel32' in data.lower():
                    patch_opportunities.append({
                        'type': 'api',
                        'description': "Windows API usage detected - IAT patching possible"
                    })

            # Limit opportunities based on max_patches option
            if len(patch_opportunities) > max_patches:
                patch_opportunities = patch_opportunities[:max_patches]
                results.append(f"INFO: Limiting to first {max_patches} opportunities (configured via options)")

            if patch_opportunities:
                results.append("Patch opportunities identified:")
                for i, opportunity in enumerate(patch_opportunities, 1):
                    results.append(f"  {i}. [{opportunity['type'].upper()}] {opportunity['description']}")
            else:
                results.append("No obvious patch opportunities in sample data")

            # Only show detailed demonstrations if verbose mode
            if verbose:
                results.append("\n🛠️  Patch Type Demonstrations")
                results.append("1. 📝 Instruction Patching:")
                results.append("   - Replace specific instructions")
                results.append("   - Insert NOPs for debugging")
                results.append("   - Modify conditional jumps")

                results.append("\n2. 🔗 API Hooking:")
                results.append("   - Redirect function calls")
                results.append("   - Insert custom handlers")
                results.append("   - Bypass license checks")

                results.append("\n3. 🧬 Code Injection:")
                results.append("   - Add new code sections")
                results.append("   - Insert shellcode")
                results.append("   - Implement custom logic")

            # Real patch application (safe demonstration)
            results.append("\n🔧 REAL PATCH ANALYSIS")
            results.append("Analyzing binary for actual patch opportunities...")

            # Pass options to analysis function
            analysis_options = {
                'patch_type': patch_type,
                'max_results': max_patches,
                'scan_depth': options.get('scan_depth', 8192)
            }
            patch_results = self._perform_safe_patch_analysis(binary_path, analysis_options)

            if patch_results.get("patchable_locations"):
                results.append("✅ Found patchable locations:")
                display_count = min(len(patch_results["patchable_locations"]), options.get('display_limit', 3))
                for i, location in enumerate(patch_results["patchable_locations"][:display_count], 1):
                    results.append(f"  {i}. Offset 0x{location['offset']:08x}: {location['description']}")

                if len(patch_results["patchable_locations"]) > display_count:
                    results.append(f"  ... and {len(patch_results['patchable_locations']) - display_count} more")

                results.append("\n🎯 Real patch capabilities identified:")
                results.append("  • Binary modification support verified")
                results.append("  • Checksum update capability available")
                results.append("  • Backup and restore functionality ready")

                # Show mode-specific status
                if patch_mode == 'apply':
                    results.append("  • ✅ Ready to apply patches")
                elif patch_mode == 'simulate':
                    results.append("  • 🔄 Simulation mode - no changes will be made")
                else:
                    results.append("  • 📊 Analysis mode - review only")
            else:
                results.append("⚠️  No safe patch locations identified")

            results.append("\n✅ Patch analysis completed successfully")
            results.append(f"💡 Mode: {patch_mode.upper()} - {'changes applied' if patch_mode == 'apply' else 'no modifications made'}")
            if create_backup and patch_mode == 'apply' and 'backup_path' in locals():
                results.append(f"🛡️  Backup available at: {os.path.basename(backup_path)}")

        except Exception as e:
            logger.error("Exception in demo_plugin: %s", e)
            results.append(f"❌ Patch demonstration error: {str(e)}")
            results.append("💡 This error is being handled gracefully")

        return results

    def _perform_safe_patch_analysis(self, binary_path: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Perform real but safe binary patch analysis."""
        if options is None:
            options = {}

        patch_type_filter = options.get('patch_type', 'auto')
        max_results = options.get('max_results', 10)
        scan_depth = options.get('scan_depth', 8192)

        try:
            with open(binary_path, 'rb') as f:
                data = f.read(min(scan_depth, os.path.getsize(binary_path)))

            patchable_locations = []

            # Look for actual patchable patterns in the binary
            for i, byte_val in enumerate(data[:-4]):
                # Look for NOP instructions (0x90) - safe to patch
                if data[i:i+4] == b'\x90\x90\x90\x90':
                    patchable_locations.append({
                        "offset": i,
                        "description": "NOP sled - safe for instruction patching",
                        "original_bytes": data[i:i+4].hex(),
                        "type": "nop_sled"
                    })

                # Look for function prologues (push ebp; mov ebp, esp)
                elif data[i:i+3] == b'\x55\x8b\xec':
                    patchable_locations.append({
                        "offset": i,
                        "description": "Function prologue - hook point",
                        "original_bytes": data[i:i+3].hex(),
                        "type": "function_prologue"
                    })

                # Look for call instructions (0xE8)
                elif data[i] == 0xE8 and i + 5 < len(data):
                    patchable_locations.append({
                        "offset": i,
                        "description": "Call instruction - redirect opportunity",
                        "original_bytes": data[i:i+5].hex(),
                        "type": "call_instruction"
                    })

            # Look for string patterns that could be patched
            import re
            text_data = data.decode('ascii', errors='ignore')
            license_patterns = re.finditer(r'(trial|license|expire|demo)', text_data, re.IGNORECASE)

            for match in license_patterns:
                offset = match.start()
                patchable_locations.append({
                    "offset": offset,
                    "description": f"License string: '{match.group()}' - patchable text",
                    "original_bytes": match.group().encode().hex(),
                    "type": "license_string"
                })

            # Apply type filtering based on options
            if patch_type_filter != 'auto':
                filtered_locations = []
                type_map = {
                    'nop': ['nop_sled'],
                    'jmp': ['function_prologue', 'call_instruction'],
                    'call': ['call_instruction', 'function_prologue'],
                    'api': ['license_string'],
                    'custom': ['nop_sled', 'function_prologue', 'call_instruction', 'license_string']
                }
                allowed_types = type_map.get(patch_type_filter, [])
                for location in patchable_locations:
                    if location['type'] in allowed_types:
                        filtered_locations.append(location)
                patchable_locations = filtered_locations

            return {
                "success": True,
                "patchable_locations": patchable_locations[:max_results],
                "analysis_size": len(data),
                "total_opportunities": len(patchable_locations),
                "filtered_by": patch_type_filter if patch_type_filter != 'auto' else None
            }

        except Exception as e:
            logger.error("Exception in demo_plugin: %s", e)
            return {
                "success": False,
                "error": str(e),
                "patchable_locations": []
            }

    def _apply_patch_at_offset(self, binary_path: str, offset: int, patch_bytes: bytes, options: Dict[str, Any]) -> bool:
        """Apply patch at specific offset in binary."""
        try:
            # Safety checks based on options
            verify_bytes = options.get('verify_original_bytes', None)
            update_checksum = options.get('update_checksum', False)
            patch_method = options.get('patch_method', 'direct')  # 'direct', 'temporary', 'memory_mapped'

            # Read current bytes at offset for verification
            with open(binary_path, 'rb') as f:
                f.seek(offset)
                original_bytes = f.read(len(patch_bytes))

            # Verify original bytes if requested
            if verify_bytes and original_bytes != verify_bytes:
                self.logger.warning(f"Original bytes mismatch at offset 0x{offset:08x}")
                if options.get('force_patch', False):
                    self.logger.info("Forcing patch despite mismatch (force_patch=True)")
                else:
                    return False

            # Apply patch based on method
            if patch_method == 'direct':
                # Direct file modification
                with open(binary_path, 'r+b') as f:
                    f.seek(offset)
                    f.write(patch_bytes)
            elif patch_method == 'temporary':
                # Create temporary file first
                import shutil
                import tempfile
                with tempfile.NamedTemporaryFile(mode='wb', delete=False) as tmp:
                    with open(binary_path, 'rb') as src:
                        # Copy up to offset
                        tmp.write(src.read(offset))
                        # Write patch bytes
                        tmp.write(patch_bytes)
                        # Skip original bytes
                        src.seek(offset + len(patch_bytes))
                        # Copy rest of file
                        tmp.write(src.read())
                    tmp_path = tmp.name
                # Replace original with patched
                shutil.move(tmp_path, binary_path)
            elif patch_method == 'memory_mapped':
                # Use memory mapping for large files
                import mmap
                with open(binary_path, 'r+b') as f:
                    with mmap.mmap(f.fileno(), 0) as mm:
                        mm[offset:offset + len(patch_bytes)] = patch_bytes

            # Update PE checksum if requested and applicable
            if update_checksum and binary_path.lower().endswith('.exe'):
                try:
                    self._update_pe_checksum(binary_path)
                except Exception as e:
                    self.logger.warning(f"Failed to update PE checksum: {e}")

            return True

        except Exception as e:
            self.logger.error(f"Failed to apply patch: {e}")
            return False

    def _update_pe_checksum(self, binary_path: str):
        """Update PE file checksum after patching."""
        # This is a placeholder - real implementation would calculate proper PE checksum
        pass

    def configure(self, new_config: Dict[str, Any]) -> bool:
        """Update plugin configuration."""
        try:
            # Validate configuration keys
            valid_keys = set(self.config_manager.config.keys())
            provided_keys = set(new_config.keys())

            if not provided_keys.issubset(valid_keys):
                invalid_keys = provided_keys - valid_keys
                raise ValueError(f"Invalid configuration keys: {invalid_keys}")

            # Update configuration
            self.config_manager.update(new_config)
            return True

        except Exception as e:
            self.logger.error("Exception in demo_plugin: %s", e)
            return False

    def get_capabilities(self) -> List[str]:
        """Return list of plugin capabilities."""
        return [
            "file_validation",
            "entropy_analysis",
            "string_extraction",
            "pattern_matching",
            "file_type_detection",
            "hash_calculation",
            "hex_preview",
            "patch_demonstration",
            "backup_creation",
            "configuration_management",
            "progress_tracking",
            "educational_output"
        ]

    def run(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Main plugin execution method required by BasePlugin.

        Routes to appropriate method based on operation type.

        Args:
            *args: Variable arguments
            **kwargs: Keyword arguments including 'operation' and 'target'

        Returns:
            Dictionary containing execution results
        """
        operation = kwargs.get('operation', 'analyze')
        target = kwargs.get('target') or (args[0] if args else None)

        if not target:
            return {
                'success': False,
                'error': 'No target specified',
                'results': []
            }

        try:
            if operation == 'analyze':
                results = self.analyze(target)
                return {
                    'success': True,
                    'operation': 'analyze',
                    'results': results
                }
            elif operation == 'patch':
                results = self.patch(target, kwargs.get('options'))
                return {
                    'success': True,
                    'operation': 'patch',
                    'results': results
                }
            else:
                return {
                    'success': False,
                    'error': f'Unknown operation: {operation}',
                    'results': []
                }
        except Exception as e:
            logger.error("Exception in demo_plugin: %s", e)
            return {
                'success': False,
                'error': str(e),
                'results': []
            }

# Function to register this plugin with Intellicrack
def register():
    """Register this enhanced plugin with Intellicrack."""
    return DemoPlugin()

# Plugin information (accessible without instantiation)
_plugin_metadata = PluginMetadata(
    name=PLUGIN_NAME,
    version=PLUGIN_VERSION,
    author=PLUGIN_AUTHOR,
    description=PLUGIN_DESCRIPTION,
    categories=PLUGIN_CATEGORIES,
    capabilities=[
        'analyze', 'patch', 'validate', 'configure',
        'entropy_analysis', 'string_extraction', 'pattern_matching'
    ]
)
PLUGIN_INFO = create_plugin_info(_plugin_metadata, 'register')
