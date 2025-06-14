"""
Enhanced Demo Plugin for Intellicrack
Comprehensive example showing modern plugin development practices

Author: Intellicrack Development Team
Version: 2.0.0
License: GPL v3
Compatibility: Intellicrack 1.0+
"""

import os
import hashlib
import time
from typing import Dict, List, Optional, Any
from pathlib import Path

# Plugin metadata
PLUGIN_NAME = "Enhanced Demo Plugin"
PLUGIN_VERSION = "2.0.0"
PLUGIN_AUTHOR = "Intellicrack Team"
PLUGIN_DESCRIPTION = "Comprehensive demonstration of Intellicrack plugin capabilities"
PLUGIN_CATEGORIES = ["demo", "analysis", "education"]

class DemoPlugin:
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
        # Core plugin metadata
        self.name = PLUGIN_NAME
        self.version = PLUGIN_VERSION
        self.author = PLUGIN_AUTHOR
        self.description = PLUGIN_DESCRIPTION
        self.categories = PLUGIN_CATEGORIES
        
        # Plugin configuration
        self.config = {
            'max_file_size': 50 * 1024 * 1024,  # 50MB limit for demo
            'detailed_output': True,
            'include_file_hash': True,
            'show_hex_preview': True,
            'analysis_timeout': 15
        }
        
        # Internal state
        self.analysis_count = 0
        self.last_analysis_time = None
        
        # Demo analysis patterns
        self.demo_patterns = {
            'pe_signature': b'MZ',
            'elf_signature': b'\x7fELF',
            'macho_signature': b'\xcf\xfa\xed\xfe',
            'zip_signature': b'PK',
            'common_strings': [b'kernel32.dll', b'ntdll.dll', b'user32.dll']
        }
    
    def get_metadata(self) -> Dict[str, Any]:
        """Return comprehensive plugin metadata."""
        return {
            'name': self.name,
            'version': self.version,
            'author': self.author,
            'description': self.description,
            'categories': self.categories,
            'config': self.config,
            'analysis_count': self.analysis_count,
            'last_analysis': self.last_analysis_time,
            'capabilities': ['analyze', 'patch', 'validate', 'configure']
        }
    
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
            
            if file_size > self.config['max_file_size']:
                return False, f"File too large: {file_size:,} bytes (max: {self.config['max_file_size']:,})"
            
            # Check read permissions
            if not os.access(binary_path, os.R_OK):
                return False, f"File not readable: {binary_path}"
            
            return True, "File validation successful"
            
        except Exception as e:
            return False, f"Validation error: {str(e)}"
    
    def _detect_file_type(self, data: bytes) -> str:
        """Detect file type based on magic bytes."""
        if data.startswith(self.demo_patterns['pe_signature']):
            return "PE (Windows Executable)"
        elif data.startswith(self.demo_patterns['elf_signature']):
            return "ELF (Linux Executable)"
        elif data.startswith(self.demo_patterns['macho_signature']):
            return "Mach-O (macOS Executable)"
        elif data.startswith(self.demo_patterns['zip_signature']):
            return "ZIP Archive"
        else:
            return "Unknown/Generic Binary"
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def _find_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extract printable strings from binary data."""
        strings = []
        current_string = ""
        
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII range
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                current_string = ""
        
        # Don't forget the last string
        if len(current_string) >= min_length:
            strings.append(current_string)
        
        return strings[:20]  # Limit to first 20 strings for demo
    
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
            if self.config['include_file_hash']:
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
                results.append("   ℹ️  Low entropy - likely text or structured data")
            else:
                results.append("   ✅ Normal entropy range")
            
            # Hex preview (if enabled)
            if self.config['show_hex_preview']:
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
            if self.config['detailed_output']:
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
            results.append(f"❌ Analysis error: {str(e)}")
            results.append("💡 This error is being handled gracefully")
        
        return results
    
    def patch(self, binary_path: str, options: Optional[Dict] = None) -> List[str]:
        """Enhanced patching demonstration with safety features."""
        results = []
        
        try:
            results.append(f"🔧 {self.name} - Patch Demonstration")
            results.append(f"🎯 Target: {os.path.basename(binary_path)}")
            results.append("="*50)
            
            # Validation
            is_valid, validation_msg = self.validate_binary(binary_path)
            if not is_valid:
                results.append(f"❌ Cannot patch: {validation_msg}")
                return results
            
            results.append(f"✅ {validation_msg}")
            
            # Safety check - create backup
            results.append("\n🛡️  Safety Measures")
            backup_path = binary_path + f".backup_{int(time.time())}"
            
            try:
                import shutil
                shutil.copy2(binary_path, backup_path)
                results.append(f"💾 Backup created: {os.path.basename(backup_path)}")
            except Exception as e:
                results.append(f"⚠️  Backup failed: {e}")
                results.append("❌ Aborting patch for safety")
                return results
            
            # Demonstrate patch analysis
            results.append("\n🔍 Patch Analysis")
            results.append("Analyzing binary for patch opportunities...")
            
            with open(binary_path, 'rb') as f:
                data = f.read(1024)  # Read first 1KB
            
            # Demonstrate various patch scenarios
            patch_opportunities = []
            
            # Look for NOP instructions (safe to patch)
            if b'\x90\x90\x90\x90' in data:
                patch_opportunities.append("NOP sled detected - safe patch target")
            
            # Look for function prologues
            if b'\x55\x8b\xec' in data:
                patch_opportunities.append("Function prologue found - potential hook point")
            
            # Look for common API calls
            if b'kernel32' in data.lower():
                patch_opportunities.append("Windows API usage detected - IAT patching possible")
            
            if patch_opportunities:
                results.append("Patch opportunities identified:")
                for i, opportunity in enumerate(patch_opportunities, 1):
                    results.append(f"  {i}. {opportunity}")
            else:
                results.append("No obvious patch opportunities in sample data")
            
            # Demonstrate different patch types
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
            
            # Simulated patch application
            results.append("\n⚠️  SIMULATION MODE")
            results.append("This demo plugin does NOT modify the actual binary.")
            results.append("In a real plugin, you would:")
            results.append("  1. 🎯 Identify precise patch locations")
            results.append("  2. 💾 Backup original bytes")
            results.append("  3. ✏️  Apply patches with proper alignment")
            results.append("  4. 🔍 Verify patch integrity")
            results.append("  5. 🔄 Update checksums if needed")
            
            results.append("\n✅ Patch demonstration completed successfully")
            results.append(f"💡 Original file remains unmodified")
            results.append(f"🛡️  Backup available at: {os.path.basename(backup_path)}")
            
        except Exception as e:
            results.append(f"❌ Patch demonstration error: {str(e)}")
            results.append("💡 This error is being handled gracefully")
        
        return results
    
    def configure(self, new_config: Dict[str, Any]) -> bool:
        """Update plugin configuration."""
        try:
            # Validate configuration keys
            valid_keys = set(self.config.keys())
            provided_keys = set(new_config.keys())
            
            if not provided_keys.issubset(valid_keys):
                invalid_keys = provided_keys - valid_keys
                raise ValueError(f"Invalid configuration keys: {invalid_keys}")
            
            # Update configuration
            self.config.update(new_config)
            return True
            
        except Exception:
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

# Function to register this plugin with Intellicrack
def register():
    """Register this enhanced plugin with Intellicrack."""
    return DemoPlugin()

# Plugin information (accessible without instantiation)
PLUGIN_INFO = {
    'name': PLUGIN_NAME,
    'version': PLUGIN_VERSION,
    'author': PLUGIN_AUTHOR,
    'description': PLUGIN_DESCRIPTION,
    'categories': PLUGIN_CATEGORIES,
    'entry_point': 'register',
    'capabilities': [
        'analyze', 'patch', 'validate', 'configure',
        'entropy_analysis', 'string_extraction', 'pattern_matching'
    ]
}
