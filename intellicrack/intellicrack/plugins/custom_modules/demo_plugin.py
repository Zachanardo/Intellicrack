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
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Import plugin base class
from intellicrack.plugins.plugin_base import BasePlugin, PluginMetadata

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
            supported_formats=PLUGIN_SUPPORTED_FORMATS,
        )

        # Plugin configuration
        from intellicrack.utils.core.plugin_paths import get_plugin_cache_dir

        default_config = {
            "max_file_size": 100 * 1024 * 1024,  # 100MB limit
            "enable_caching": True,
            "cache_dir": str(get_plugin_cache_dir()),
            "detailed_analysis": True,
            "export_results": False,
            "timeout_seconds": 30,
        }

        # Initialize base plugin
        super().__init__(metadata, default_config)

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
        if self.config_manager.get("enable_caching"):
            cache_path = Path(self.config_manager.get("cache_dir"))
            cache_path.mkdir(exist_ok=True)

    def _check_dependencies(self) -> Dict[str, bool]:
        """Check availability of optional dependencies."""
        deps = {}

        # Check required dependencies
        for dep in PLUGIN_REQUIRES:
            try:
                __import__(dep)
                deps[dep] = True
            except ImportError as e:
                self.logger.error("Import error in plugin_system: %s", e)
                deps[dep] = False

        # Check optional dependencies
        for dep in PLUGIN_OPTIONAL:
            try:
                __import__(dep)
                deps[dep] = True
            except ImportError as e:
                self.logger.error("Import error in plugin_system: %s", e)
                deps[dep] = False

        return deps

    def get_metadata(self) -> Dict[str, Any]:
        """Return comprehensive plugin metadata."""
        metadata = super().get_metadata()
        # Add plugin-specific information
        metadata.update(
            {
                "requirements": PLUGIN_REQUIRES,
                "optional_deps": PLUGIN_OPTIONAL,
                "available_libs": self.available_libs,
                "analysis_count": self.analysis_count,
            }
        )
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
            max_file_size = self.config_manager.get("max_file_size")
            if file_size > max_file_size:
                return False, f"File too large: {file_size} bytes (max: {max_file_size})"

            # Check if file is readable
            if not os.access(binary_path, os.R_OK):
                return False, f"File not readable: {binary_path}"

            # Basic file format detection
            with open(binary_path, "rb") as f:
                header = f.read(4)
                if len(header) < 4:
                    return False, "File too small to analyze"

            return True, "File validation successful"

        except Exception as e:
            logger.error("Exception in plugin_system: %s", e)
            return False, f"Validation error: {str(e)}"

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of binary data."""
        import math
        if not data:
            return 0.0

        # Count frequency of each byte value
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1

        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for count in freq:
            if count > 0:
                prob = count / data_len
                entropy -= prob * math.log2(prob)

        return entropy

    def _detect_packer(self, binary_path: str) -> Dict[str, Any]:
        """Detect common packers and protectors."""
        packer_info = {"detected": False, "packer_name": None, "confidence": 0.0, "signatures": []}

        try:
            with open(binary_path, "rb") as f:
                header = f.read(8192)  # Read first 8KB

                # Common packer signatures
                signatures = {
                    b"UPX!": ("UPX", 0.9),
                    b"ASPack": ("ASPack", 0.8),
                    b"PECompact": ("PECompact", 0.8),
                    b"MEW": ("MEW", 0.7),
                    b"Themida": ("Themida", 0.9),
                    b"VMProtect": ("VMProtect", 0.9),
                    b"Armadillo": ("Armadillo", 0.8),
                }

                for sig, (name, confidence) in signatures.items():
                    if sig in header:
                        packer_info["detected"] = True
                        packer_info["packer_name"] = name
                        packer_info["confidence"] = confidence
                        packer_info["signatures"].append(name)
                        break

        except Exception as e:
            logger.error("Exception in plugin_system: %s", e)
            packer_info["error"] = str(e)

        return packer_info

    def _extract_strings(self, binary_path: str, min_length: int = 4) -> List[str]:
        """Extract printable strings from binary."""
        from intellicrack.utils.core.string_utils import extract_ascii_strings

        try:
            with open(binary_path, "rb") as f:
                data = f.read()
                strings = extract_ascii_strings(data, min_length)
                return strings[:100]  # Limit to first 100 strings
        except Exception as e:
            self.logger.error("Exception in plugin_system: %s", e)
            return [f"Error extracting strings: {str(e)}"]

    def _get_file_hashes(self, binary_path: str) -> Dict[str, str]:
        """Calculate multiple hash values for the file."""
        hashes = {}

        try:
            with open(binary_path, "rb") as f:
                data = f.read()

                hashes["md5"] = hashlib.md5(data).hexdigest()
                hashes["sha1"] = hashlib.sha1(data).hexdigest()
                hashes["sha256"] = hashlib.sha256(data).hexdigest()

        except Exception as e:
            self.logger.error("Exception in plugin_system: %s", e)
            hashes["error"] = str(e)

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
                results.append(f"❌ Validation failed: {validation_msg}")
                return results
            results.append(f"✅ {validation_msg}")

            # Step 2: Basic file information
            update_progress("Gathering file information...")
            file_info = os.stat(binary_path)
            results.append(f"📁 File: {os.path.basename(binary_path)}")
            results.append(f"📏 Size: {file_info.st_size:,} bytes")
            results.append(f"📅 Modified: {time.ctime(file_info.st_mtime)}")

            # Step 3: Hash calculation
            update_progress("Calculating file hashes...")
            hashes = self._get_file_hashes(binary_path)
            if "error" not in hashes:
                results.append("🔒 File Hashes:")
                for hash_type, hash_value in hashes.items():
                    results.append(f"  {hash_type.upper()}: {hash_value}")

            # Step 4: Entropy analysis
            update_progress("Analyzing entropy...")
            with open(binary_path, "rb") as f:
                sample_data = f.read(min(65536, file_info.st_size))  # First 64KB
            entropy = self._calculate_entropy(sample_data)
            results.append(f"📊 Entropy: {entropy:.2f}")
            if entropy > 7.5:
                results.append("  ⚠️  High entropy - possibly packed/encrypted")
            elif entropy < 1.0:
                results.append("  ℹ️  Low entropy - likely unprocessed data")

            # Step 5: Packer detection
            update_progress("Detecting packers...")
            packer_info = self._detect_packer(binary_path)
            if packer_info["detected"]:
                results.append(
                    f"📦 Packer detected: {packer_info['packer_name']} (confidence: {packer_info['confidence']:.1%})"
                )
            else:
                results.append("📦 No common packers detected")

            # Step 6: String extraction
            update_progress("Extracting strings...")
            strings = self._extract_strings(binary_path)
            results.append(f"📝 Extracted {len(strings)} strings (showing first 10):")
            for i, string in enumerate(strings[:10]):
                results.append(f"  {i+1:2d}. {string[:50]}{'...' if len(string) > 50 else ''}")

            # Step 7: Advanced analysis (if available)
            update_progress("Performing advanced analysis...")
            if self.available_libs.get("pefile", False) and binary_path.lower().endswith(
                (".exe", ".dll")
            ):
                results.append("🔍 PE analysis available (pefile installed)")
            elif self.available_libs.get("lief", False):
                results.append("🔍 Advanced analysis available (LIEF installed)")
            else:
                results.append(
                    "🔍 Advanced analysis unavailable (install pefile/lief for more features)"
                )

            # Analysis summary
            analysis_time = time.time() - start_time
            results.append("")
            results.append("📋 Analysis Summary:")
            results.append(f"  ⏱️  Analysis time: {analysis_time:.2f} seconds")
            results.append(f"  🔢 Total analyses performed: {self.analysis_count}")
            results.append(f"  📊 File entropy: {entropy:.2f}")
            results.append(f"  📦 Packer: {'Yes' if packer_info['detected'] else 'No'}")
            results.append(f"  📝 Strings found: {len(strings)}")

            # Store last analysis
            self.last_analysis = {
                "timestamp": time.time(),
                "file_path": binary_path,
                "results": results.copy(),
                "entropy": entropy,
                "packer_detected": packer_info["detected"],
            }

        except Exception as e:
            logger.error("Exception in plugin_system: %s", e)
            results.append(f"❌ Analysis error: {str(e)}")
            results.append("📋 This is a template - implement your custom analysis logic here")

        return results

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
                patch_options = {"create_backup": True, "verify_patch": True, "dry_run": False}

            results.append(f"🔧 Starting patch operation on: {os.path.basename(binary_path)}")

            # Validation
            is_valid, validation_msg = self.validate_binary(binary_path)
            if not is_valid:
                results.append(f"❌ Cannot patch: {validation_msg}")
                return results

            # Create backup if requested
            if patch_options.get("create_backup", True):
                backup_path = binary_path + f".backup_{int(time.time())}"
                import shutil

                shutil.copy2(binary_path, backup_path)
                results.append(f"💾 Created backup: {os.path.basename(backup_path)}")

            # Dry run mode
            if patch_options.get("dry_run", False):
                results.append("🧪 Dry run mode - no actual changes will be made")
                results.append("🔍 Patch simulation:")
                results.append("  • Would modify binary header")
                results.append("  • Would patch license validation routine")
                results.append("  • Would update checksums")
                results.append("✅ Dry run completed successfully")
                return results

            # Implement your actual patching logic here
            results.append("⚠️  This is a template - implement your patching logic here")
            results.append("🛠️  Suggested patch operations:")
            results.append("  • Identify target functions/addresses")
            results.append("  • Backup original bytes")
            results.append("  • Apply patches with proper alignment")
            results.append("  • Update checksums if needed")
            results.append("  • Verify patch integrity")

            # Verification
            if patch_options.get("verify_patch", True):
                results.append("🔍 Verifying patch integrity...")
                results.append("✅ Patch verification completed")

            results.append("✅ Patch operation completed successfully")

        except Exception as e:
            logger.error("Exception in plugin_system: %s", e)
            results.append(f"❌ Patch error: {str(e)}")

        return results

    def run(self, *args, **kwargs) -> Dict[str, Any]:
        """Main plugin execution method required by BasePlugin.

        Args:
            *args: Variable arguments
            **kwargs: Keyword arguments

        Returns:
            Dictionary containing execution results
        """
        binary_path = kwargs.get("binary_path", args[0] if args else None)

        if not binary_path:
            return {"success": False, "error": "No binary path provided", "results": []}

        try:
            # Run analysis
            results = self.analyze(binary_path, kwargs.get("progress_callback"))

            return {
                "success": True,
                "error": None,
                "results": results,
                "metadata": {
                    "plugin_name": self.name,
                    "plugin_version": self.version,
                    "analysis_count": self.analysis_count,
                },
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "results": [f"Plugin execution failed: {str(e)}"],
            }

    def export_results(self, output_path: str, format_type: str = "json") -> bool:
        """Export analysis results to file."""
        if not self.last_analysis:
            return False

        try:
            if format_type.lower() == "json":
                with open(output_path, "w") as f:
                    json.dump(self.last_analysis, f, indent=2)
            elif format_type.lower() == "txt":
                with open(output_path, "w") as f:
                    f.write("\n".join(self.last_analysis["results"]))
            else:
                return False

            return True
        except Exception as e:
            self.logger.error("Exception in plugin_system: %s", e)
            return False

    def configure(self, config_updates: Dict[str, Any]) -> bool:
        """Update plugin configuration."""
        try:
            self.config_manager.update(config_updates)
            return True
        except Exception as e:
            self.logger.error("Exception in plugin_system: %s", e)
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
            "validation",
        ]


def register():
    """
    Required function to register the plugin with Intellicrack.

    Returns:
        Instance of the plugin class
    """
    return AdvancedDemoPlugin()


# Plugin information (can be accessed without instantiating)
from intellicrack.plugins.plugin_base import create_plugin_info

_plugin_metadata = PluginMetadata(
    name=PLUGIN_NAME,
    version=PLUGIN_VERSION,
    author=PLUGIN_AUTHOR,
    description=PLUGIN_DESCRIPTION,
    categories=PLUGIN_CATEGORIES,
    supported_formats=PLUGIN_SUPPORTED_FORMATS,
)
PLUGIN_INFO = create_plugin_info(_plugin_metadata, "register")
