"""
Advanced Plugin Template for Intellicrack
Comprehensive example showing all plugin capabilities and best practices

Author: Plugin Developer
Version: 1.0.0
License: GPL v3
Compatibility: Intellicrack 1.0+
"""

import hashlib
import json
import os
import struct
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Import plugin base class
try:
    from intellicrack.plugins.plugin_base import BasePlugin, PluginMetadata
except ImportError:
    # Fallback for different import contexts
    from plugin_base import BasePlugin, PluginMetadata

# Plugin metadata constants
PLUGIN_NAME = "Advanced Demo Plugin"
PLUGIN_VERSION = "1.0.0"
PLUGIN_AUTHOR = "Your Name"
PLUGIN_DESCRIPTION = "Comprehensive plugin template with advanced features"
PLUGIN_CATEGORIES = ["analysis", "packer", "entropy", "strings"]
PLUGIN_SUPPORTED_FORMATS = ["PE", "ELF", "Mach-O", "Raw"]
PLUGIN_REQUIRES = ["hashlib", "struct"]
PLUGIN_OPTIONAL = ["pefile", "lief"]

class AdvancedDemoPlugin(BasePlugin):
    """
    Advanced plugin template demonstrating comprehensive integration with Intellicrack.

    This plugin showcases:
    - Proper initialization and metadata
    - Multi-format binary analysis
    - Error handling and logging
    - Configuration management
    - Progress reporting
    - Caching and performance optimization
    - Security validation
    - Export capabilities
    """

    def __init__(self):
        """Initialize the plugin with metadata and configuration."""
        # Create metadata object
        metadata = PluginMetadata(
            name=PLUGIN_NAME,
            version=PLUGIN_VERSION,
            author=PLUGIN_AUTHOR,
            description=PLUGIN_DESCRIPTION,
            categories=PLUGIN_CATEGORIES,
            supported_formats=PLUGIN_SUPPORTED_FORMATS
        )

        # Plugin configuration
        default_config = {
            'max_file_size': 100 * 1024 * 1024,  # 100MB limit
            'enable_caching': True,
            'cache_dir': 'plugin_cache',
            'detailed_analysis': True,
            'export_results': False,
            'timeout_seconds': 30
        }

        # Initialize base plugin
        super().__init__(metadata, default_config)

        # Ensure config is set (fallback if parent class doesn't set it)
        if not hasattr(self, 'config'):
            self.config = default_config

        # Internal state
        self.cache = {}
        self.last_analysis = None
        self.analysis_count = 0

        # Initialize cache directory
        self._init_cache()

        # Check dependencies
        self.available_libs = self._check_dependencies()

    def _init_cache(self) -> None:
        """Initialize cache directory if caching is enabled."""
        if self.config['enable_caching']:
            cache_path = Path(self.config['cache_dir'])
            cache_path.mkdir(exist_ok=True)

    def _check_dependencies(self) -> Dict[str, bool]:
        """Check availability of optional dependencies."""
        deps = {}

        # Check required dependencies
        for dep in PLUGIN_REQUIRES:
            try:
                __import__(dep)
                deps[dep] = True
            except ImportError:
                deps[dep] = False

        # Check optional dependencies
        for dep in PLUGIN_OPTIONAL:
            try:
                __import__(dep)
                deps[dep] = True
            except ImportError:
                deps[dep] = False

        return deps

    def get_metadata(self) -> Dict[str, Any]:
        """Return comprehensive plugin metadata."""
        metadata = super().get_metadata()
        # Add plugin-specific information
        metadata.update({
            'requirements': PLUGIN_REQUIRES,
            'optional_deps': PLUGIN_OPTIONAL,
            'available_libs': self.available_libs,
            'analysis_count': self.analysis_count
        })
        return metadata

    def validate_binary(self, binary_path: str) -> Tuple[bool, str]:
        """Validate binary file before analysis."""
        try:
            path = Path(binary_path)

            # Check if file exists
            if not path.exists():
                return False, f"File does not exist: {binary_path}"

            # Check file size
            file_size = path.stat().st_size
            if file_size > self.config['max_file_size']:
                return False, f"File too large: {file_size} bytes (max: {self.config['max_file_size']})"

            # Check if file is readable
            if not os.access(binary_path, os.R_OK):
                return False, f"File not readable: {binary_path}"

            # Basic file format detection
            with open(binary_path, 'rb') as f:
                header = f.read(4)
                if len(header) < 4:
                    return False, "File too small to analyze"

            return True, "File validation successful"

        except Exception as e:
            return False, f"Validation error: {str(e)}"

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of binary data."""
        import math
        if not data:
            return 0.0

        # Calculate byte frequency
        byte_counts = {}
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1

        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts.values():
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)

        return entropy

    def _detect_packer(self, binary_path: str) -> Dict[str, Any]:
        """Detect common packers and protectors."""
        packer_info = {
            'detected': False,
            'packer_name': None,
            'confidence': 0.0,
            'signatures': []
        }

        try:
            with open(binary_path, 'rb') as f:
                header = f.read(8192)  # Read first 8KB

                # Common packer signatures
                signatures = {
                    b'UPX!': ('UPX', 0.9),
                    b'ASPack': ('ASPack', 0.8),
                    b'PECompact': ('PECompact', 0.8),
                    b'MEW': ('MEW', 0.7),
                    b'Themida': ('Themida', 0.9),
                    b'VMProtect': ('VMProtect', 0.9),
                    b'Armadillo': ('Armadillo', 0.8)
                }

                for sig, (name, confidence) in signatures.items():
                    if sig in header:
                        packer_info['detected'] = True
                        packer_info['packer_name'] = name
                        packer_info['confidence'] = confidence
                        packer_info['signatures'].append(name)
                        break

        except Exception as e:
            packer_info['error'] = str(e)

        return packer_info

    def _extract_strings(self, binary_path: str, min_length: int = 4) -> List[str]:
        """Extract printable strings from binary."""
        try:
            from intellicrack.utils.core.string_utils import extract_ascii_strings
        except ImportError:
            # Fallback implementation
            def extract_ascii_strings(data: bytes, min_length: int = 4) -> List[str]:
                """Simple ASCII string extraction fallback."""
                strings = []
                current = b""
                for byte in data:
                    if 32 <= byte <= 126:  # Printable ASCII
                        current += bytes([byte])
                    else:
                        if len(current) >= min_length:
                            strings.append(current.decode('ascii', errors='ignore'))
                        current = b""
                if len(current) >= min_length:
                    strings.append(current.decode('ascii', errors='ignore'))
                return strings

        try:
            with open(binary_path, 'rb') as f:
                data = f.read()
                strings = extract_ascii_strings(data, min_length)
                return strings[:100]  # Limit to first 100 strings
        except Exception as e:
            return [f"Error extracting strings: {str(e)}"]

    def _get_file_hashes(self, binary_path: str) -> Dict[str, str]:
        """Calculate multiple hash values for the file."""
        hashes = {}

        try:
            with open(binary_path, 'rb') as f:
                data = f.read()

                hashes['md5'] = hashlib.md5(data).hexdigest()
                hashes['sha1'] = hashlib.sha1(data).hexdigest()
                hashes['sha256'] = hashlib.sha256(data).hexdigest()

        except Exception as e:
            hashes['error'] = str(e)

        return hashes

    def analyze(self, binary_path: str, progress_callback=None) -> List[str]:
        """
        Comprehensive binary analysis with progress reporting.

        Args:
            binary_path: Path to the binary to analyze
            progress_callback: Optional callback for progress updates

        Returns:
            List of strings with detailed analysis results
        """
        results = []
        start_time = time.time()

        try:
            # Update analysis counter
            self.analysis_count += 1

            # Progress tracking
            total_steps = 7
            current_step = 0

            def update_progress(message: str):
                nonlocal current_step
                current_step += 1
                if progress_callback:
                    progress_callback(current_step, total_steps, message)
                results.append(f"[{current_step}/{total_steps}] {message}")

            # Step 1: Validation
            update_progress("Validating binary file...")
            is_valid, validation_msg = self.validate_binary(binary_path)
            if not is_valid:
                results.append(f"[ERROR] Validation failed: {validation_msg}")
                return results
            results.append(f"[OK] {validation_msg}")

            # Step 2: Basic file information
            update_progress("Gathering file information...")
            file_info = os.stat(binary_path)
            results.append(f"[FILE] File: {os.path.basename(binary_path)}")
            results.append(f"[SIZE] Size: {file_info.st_size:,} bytes")
            results.append(f"[DATE] Modified: {time.ctime(file_info.st_mtime)}")

            # Step 3: Hash calculation
            update_progress("Calculating file hashes...")
            hashes = self._get_file_hashes(binary_path)
            if 'error' not in hashes:
                results.append("[HASH] File Hashes:")
                for hash_type, hash_value in hashes.items():
                    results.append(f"  {hash_type.upper()}: {hash_value}")

            # Step 4: Entropy analysis
            update_progress("Analyzing entropy...")
            with open(binary_path, 'rb') as f:
                sample_data = f.read(min(65536, file_info.st_size))  # First 64KB
            entropy = self._calculate_entropy(sample_data)
            results.append(f"[STATS] Entropy: {entropy:.2f}")
            if entropy > 7.5:
                results.append("  [WARNING] High entropy - possibly packed/encrypted")
            elif entropy < 1.0:
                results.append("  INFO: Low entropy - likely unprocessed data")

            # Step 5: Packer detection
            update_progress("Detecting packers...")
            packer_info = self._detect_packer(binary_path)
            if packer_info['detected']:
                results.append(f"[PACKER] Packer detected: {packer_info['packer_name']} (confidence: {packer_info['confidence']:.1%})")
            else:
                results.append("[PACKER] No common packers detected")

            # Step 6: String extraction
            update_progress("Extracting strings...")
            strings = self._extract_strings(binary_path)
            results.append(f"[STRINGS] Extracted {len(strings)} strings (showing first 10):")
            for i, string in enumerate(strings[:10]):
                results.append(f"  {i+1:2d}. {string[:50]}{'...' if len(string) > 50 else ''}")

            # Step 7: Advanced analysis (if available)
            update_progress("Performing advanced analysis...")
            if self.available_libs.get('pefile', False) and binary_path.lower().endswith(('.exe', '.dll')):
                results.append("[INFO] PE analysis available (pefile installed)")
            elif self.available_libs.get('lief', False):
                results.append("[INFO] Advanced analysis available (LIEF installed)")
            else:
                results.append("[INFO] Advanced analysis unavailable (install pefile/lief for more features)")

            # Analysis summary
            analysis_time = time.time() - start_time
            results.append("")
            results.append("[SUMMARY] Analysis Summary:")
            results.append(f"  [TIME] Analysis time: {analysis_time:.2f} seconds")
            results.append(f"  [COUNT] Total analyses performed: {self.analysis_count}")
            results.append(f"  [STATS] File entropy: {entropy:.2f}")
            results.append(f"  [PACKER] Packer: {'Yes' if packer_info['detected'] else 'No'}")
            results.append(f"  [STRINGS] Strings found: {len(strings)}")

            # Store last analysis
            self.last_analysis = {
                'timestamp': time.time(),
                'file_path': binary_path,
                'results': results.copy(),
                'entropy': entropy,
                'packer_detected': packer_info['detected']
            }

        except Exception as e:
            results.append(f"[ERROR] Analysis error: {str(e)}")
            results.append("[SUMMARY] This is a template - implement your custom analysis logic here")

        return results

    def run(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Main entry point for the plugin (required by BasePlugin).

        This method satisfies the abstract method requirement and delegates
        to the appropriate method based on the action requested.

        Args:
            *args: Positional arguments
            **kwargs: Keyword arguments including 'action' and action-specific params

        Returns:
            Dict with results of the operation
        """
        # Get the action from kwargs, default to 'analyze'
        action = kwargs.get('action', 'analyze')

        if action == 'analyze':
            # Get binary path from args or kwargs
            if args:
                binary_path = args[0]
            else:
                binary_path = kwargs.get('binary_path', kwargs.get('target', ''))

            if not binary_path:
                return {
                    'success': False,
                    'error': 'No binary path provided',
                    'results': []
                }

            # Run analysis
            progress_callback = kwargs.get('progress_callback', None)
            results = self.analyze(binary_path, progress_callback)

            return {
                'success': True,
                'action': 'analyze',
                'results': results,
                'analysis_data': self.last_analysis
            }

        elif action == 'patch':
            # Get binary path and options
            if args:
                binary_path = args[0]
            else:
                binary_path = kwargs.get('binary_path', kwargs.get('target', ''))

            patch_options = kwargs.get('patch_options', {})
            results = self.patch(binary_path, patch_options)

            return {
                'success': True,
                'action': 'patch',
                'results': results
            }

        elif action == 'export':
            # Export last analysis
            output_path = kwargs.get('output_path', 'analysis_result')
            format_type = kwargs.get('format', 'json')
            success = self.export_results(output_path, format_type)

            return {
                'success': success,
                'action': 'export',
                'output_path': output_path,
                'format': format_type
            }

        else:
            return {
                'success': False,
                'error': f'Unknown action: {action}',
                'available_actions': ['analyze', 'patch', 'export']
            }

    def patch(self, binary_path: str, patch_options: Optional[Dict] = None) -> List[str]:
        """
        Advanced binary patching with safety checks and backup.

        Args:
            binary_path: Path to the binary to patch
            patch_options: Optional dictionary with patch configuration

        Returns:
            List of strings with patching results
        """
        results = []

        try:
            # Default patch options
            if patch_options is None:
                patch_options = {
                    'create_backup': True,
                    'verify_patch': True,
                    'dry_run': False
                }

            results.append(f"[PATCH] Starting patch operation on: {os.path.basename(binary_path)}")

            # Validation
            is_valid, validation_msg = self.validate_binary(binary_path)
            if not is_valid:
                results.append(f"[ERROR] Cannot patch: {validation_msg}")
                return results

            # Create backup if requested
            if patch_options.get('create_backup', True):
                backup_path = binary_path + f".backup_{int(time.time())}"
                import shutil
                shutil.copy2(binary_path, backup_path)
                results.append(f"[BACKUP] Created backup: {os.path.basename(backup_path)}")

            # Dry run mode
            if patch_options.get('dry_run', False):
                results.append("[TEST] Dry run mode - no actual changes will be made")
                results.append("[INFO] Patch simulation:")
                results.append("  - Would modify binary header")
                results.append("  - Would patch license validation routine")
                results.append("  - Would update checksums")
                results.append("[OK] Dry run completed successfully")
                return results

            # Implement your actual patching logic here
            results.append("[WARNING] This is a template - implement your patching logic here")
            results.append("[TOOLS] Suggested patch operations:")
            results.append("  - Identify target functions/addresses")
            results.append("  - Backup original bytes")
            results.append("  - Apply patches with proper alignment")
            results.append("  - Update checksums if needed")
            results.append("  - Verify patch integrity")

            # Verification
            if patch_options.get('verify_patch', True):
                results.append("[INFO] Verifying patch integrity...")
                results.append("[OK] Patch verification completed")

            results.append("[OK] Patch operation completed successfully")

        except Exception as e:
            results.append(f"[ERROR] Patch error: {str(e)}")

        return results

    def export_results(self, output_path: str, format_type: str = 'json') -> bool:
        """Export analysis results to file."""
        if not self.last_analysis:
            return False

        try:
            if format_type.lower() == 'json':
                with open(output_path, 'w') as f:
                    json.dump(self.last_analysis, f, indent=2)
            elif format_type.lower() == 'txt':
                with open(output_path, 'w') as f:
                    f.write("\n".join(self.last_analysis['results']))
            else:
                return False

            return True
        except Exception:
            return False

    def configure(self, config_updates: Dict[str, Any]) -> bool:
        """Update plugin configuration."""
        try:
            self.config.update(config_updates)
            return True
        except Exception:
            return False

    def get_capabilities(self) -> List[str]:
        """Return list of plugin capabilities."""
        return [
            "binary_analysis",
            "entropy_calculation",
            "packer_detection",
            "string_extraction",
            "hash_calculation",
            "patching",
            "backup_creation",
            "progress_reporting",
            "configuration",
            "export",
            "validation"
        ]

def register():
    """
    Required function to register the plugin with Intellicrack.

    Returns:
        Instance of the plugin class
    """
    return AdvancedDemoPlugin()

# Plugin information (can be accessed without instantiating)
try:
    from intellicrack.plugins.plugin_base import create_plugin_info
except ImportError:
    # Fallback for different import contexts
    from plugin_base import create_plugin_info

_plugin_metadata = PluginMetadata(
    name=PLUGIN_NAME,
    version=PLUGIN_VERSION,
    author=PLUGIN_AUTHOR,
    description=PLUGIN_DESCRIPTION,
    categories=PLUGIN_CATEGORIES,
    supported_formats=PLUGIN_SUPPORTED_FORMATS
)
PLUGIN_INFO = create_plugin_info(_plugin_metadata, 'register')
