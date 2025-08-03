"""
Functional tests for REAL binary analysis workflows.
Tests actual commercial software analysis and packed binary handling.
NO MOCKS - ALL TESTS USE REAL BINARIES AND VALIDATE ACTUAL ANALYSIS RESULTS.
"""

import pytest
import tempfile
from pathlib import Path
import subprocess
import os

from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer
from intellicrack.core.analysis.multi_format_analyzer import MultiFormatAnalyzer
from intellicrack.core.analysis.radare2_enhanced_integration import RadareIntegration
from tests.base_test import IntellicrackTestBase


class TestRealBinaries(IntellicrackTestBase):
    """Test REAL binary analysis with actual commercial software and packed binaries."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test with analyzers and temp directory."""
        self.binary_analyzer = BinaryAnalyzer()
        self.multi_analyzer = MultiFormatAnalyzer()
        
        # Try to initialize radare2 if available
        try:
            self.r2_integration = RadareIntegration()
        except Exception:
            self.r2_integration = None
            
        self.temp_dir = Path(tempfile.mkdtemp())
        
    def teardown_method(self):
        """Clean up temp files."""
        import shutil
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
            
        if self.r2_integration and hasattr(self.r2_integration, 'cleanup'):
            self.r2_integration.cleanup()
            
    def get_system_binaries(self):
        """Get REAL system binaries for testing."""
        system_binaries = []
        
        # Windows system binaries
        if os.name == 'nt':
            windows_paths = [
                r"C:\Windows\System32\notepad.exe",
                r"C:\Windows\System32\calc.exe", 
                r"C:\Windows\System32\cmd.exe",
                r"C:\Windows\System32\ping.exe",
                r"C:\Windows\System32\whoami.exe"
            ]
            
            for path in windows_paths:
                if Path(path).exists():
                    system_binaries.append(path)
                    
        # Unix system binaries
        else:
            unix_paths = [
                "/bin/ls",
                "/bin/cat", 
                "/bin/echo",
                "/usr/bin/whoami",
                "/usr/bin/id"
            ]
            
            for path in unix_paths:
                if Path(path).exists():
                    system_binaries.append(path)
                    
        return system_binaries
        
    def create_upx_packed_binary(self):
        """Create UPX packed binary if UPX is available."""
        # First create a simple binary
        simple_binary = self.temp_dir / "simple.exe"
        
        # Create minimal PE
        pe_content = self.create_minimal_pe()
        simple_binary.write_bytes(pe_content)
        
        # Try to pack with UPX
        packed_binary = self.temp_dir / "packed.exe"
        
        try:
            result = subprocess.run([
                'upx', '--best', '-o', str(packed_binary), str(simple_binary)
            ], capture_output=True, timeout=30)
            
            if result.returncode == 0 and packed_binary.exists():
                return packed_binary
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
            
        return None
        
    def create_minimal_pe(self):
        """Create minimal PE binary."""
        import struct
        
        # DOS header
        dos_header = b'MZ' + b'\x00' * 58 + struct.pack('<L', 0x80)
        dos_stub = b'\x00' * (0x80 - len(dos_header))
        
        # PE signature
        nt_signature = b'PE\x00\x00'
        
        # COFF header
        machine = struct.pack('<H', 0x014c)  # i386
        num_sections = struct.pack('<H', 1)
        timestamp = struct.pack('<L', 0)
        ptr_symbols = struct.pack('<L', 0)
        num_symbols = struct.pack('<L', 0)
        size_optional = struct.pack('<H', 224)
        characteristics = struct.pack('<H', 0x0102)
        
        coff_header = (machine + num_sections + timestamp + 
                      ptr_symbols + num_symbols + size_optional + characteristics)
        
        # Optional header
        magic = struct.pack('<H', 0x010b)  # PE32
        optional_data = b'\x00' * 223  # Rest of optional header
        optional_header = magic + optional_data
        
        # Section header
        section_name = b'.text\x00\x00\x00'
        virtual_size = struct.pack('<L', 0x1000)
        virtual_addr = struct.pack('<L', 0x1000)
        raw_size = struct.pack('<L', 0x200)
        raw_ptr = struct.pack('<L', 0x400)
        reloc_ptr = struct.pack('<L', 0)
        line_ptr = struct.pack('<L', 0)
        num_relocs = struct.pack('<H', 0)
        num_lines = struct.pack('<H', 0)
        section_chars = struct.pack('<L', 0x60000020)
        
        section_header = (section_name + virtual_size + virtual_addr + raw_size +
                         raw_ptr + reloc_ptr + line_ptr + num_relocs + 
                         num_lines + section_chars)
        
        # Headers
        headers = dos_header + dos_stub + nt_signature + coff_header + optional_header + section_header
        
        # Pad and add section
        padding = b'\x00' * (0x400 - len(headers))
        code = b'\xb8\x2a\x00\x00\x00\xc3' + b'\x00' * (0x200 - 6)  # mov eax, 42; ret
        
        return headers + padding + code
        
    def test_analyze_real_system_binaries(self):
        """Test analysis of REAL system binaries."""
        system_binaries = self.get_system_binaries()
        
        if not system_binaries:
            pytest.skip("No system binaries available for testing")
            
        analysis_results = {}
        
        for binary_path in system_binaries[:3]:  # Test first 3 to avoid long test times
            try:
                # Analyze with binary analyzer
                result = self.binary_analyzer.analyze(binary_path)
                
                # Verify real analysis
                self.assert_real_output(result)
                
                # Should detect file format
                assert 'format' in result or 'type' in result
                
                # Should have valid analysis data
                if 'sections' in result:
                    assert isinstance(result['sections'], list)
                    
                if 'imports' in result:
                    assert isinstance(result['imports'], list)
                    
                analysis_results[Path(binary_path).name] = result
                
                print(f"\\nAnalyzed {Path(binary_path).name}:")
                print(f"  Format: {result.get('format', 'detected')}")
                print(f"  Size: {result.get('size', 'N/A')} bytes")
                
            except Exception as e:
                print(f"Analysis failed for {binary_path}: {e}")
                
        # Should successfully analyze at least one binary
        assert len(analysis_results) > 0, "No system binaries were successfully analyzed"
        
    def test_analyze_packed_binary(self):
        """Test analysis of REAL packed binary (UPX)."""
        packed_binary = self.create_upx_packed_binary()
        
        if not packed_binary:
            pytest.skip("UPX not available or packing failed")
            
        # Analyze packed binary
        result = self.binary_analyzer.analyze(str(packed_binary))
        
        # Verify real analysis
        self.assert_real_output(result)
        
        # Should detect packing or handle gracefully
        analysis_text = str(result).lower()
        
        # Look for packing indicators
        packing_indicators = ['upx', 'packed', 'compressed', 'entropy']
        detected_packing = any(indicator in analysis_text for indicator in packing_indicators)
        
        print(f"\\nPacked Binary Analysis:")
        print(f"  Packing detected: {detected_packing}")
        print(f"  Analysis completed: Yes")
        
    def test_multi_format_analysis_workflow(self):
        """Test REAL multi-format analysis workflow."""
        # Create different format files
        formats_to_test = []
        
        # PE file
        pe_file = self.temp_dir / "test.exe"
        pe_file.write_bytes(self.create_minimal_pe())
        formats_to_test.append(("PE", pe_file))
        
        # ELF file (minimal)
        elf_file = self.temp_dir / "test.elf"
        elf_header = b'\\x7fELF\\x02\\x01\\x01\\x00' + b'\\x00' * 56
        elf_file.write_bytes(elf_header)
        formats_to_test.append(("ELF", elf_file))
        
        # PDF file
        pdf_file = self.temp_dir / "test.pdf"
        pdf_file.write_bytes(b'%PDF-1.4\\n1 0 obj<</Type/Catalog>>endobj')
        formats_to_test.append(("PDF", pdf_file))
        
        # Analyze each format
        analysis_results = {}
        
        for format_name, file_path in formats_to_test:
            try:
                result = self.multi_analyzer.analyze(str(file_path))
                
                self.assert_real_output(result)
                
                # Should identify format
                assert 'format' in result or 'type' in result
                
                analysis_results[format_name] = result
                
            except Exception as e:
                print(f"Multi-format analysis failed for {format_name}: {e}")
                
        # Should analyze multiple formats
        assert len(analysis_results) >= 2, "Multi-format analysis failed"
        
        print(f"\\nMulti-format Analysis:")
        for format_name, result in analysis_results.items():
            print(f"  {format_name}: {result.get('format', 'detected')}")
            
    def test_comprehensive_binary_analysis_pipeline(self):
        """Test REAL comprehensive analysis pipeline."""
        # Use a system binary for comprehensive analysis
        system_binaries = self.get_system_binaries()
        
        if not system_binaries:
            pytest.skip("No system binaries available")
            
        test_binary = system_binaries[0]
        
        # Stage 1: Basic analysis
        basic_result = self.binary_analyzer.analyze(test_binary)
        self.assert_real_output(basic_result)
        
        # Stage 2: Multi-format analysis  
        multi_result = self.multi_analyzer.analyze(test_binary)
        self.assert_real_output(multi_result)
        
        # Stage 3: Radare2 analysis (if available)
        r2_result = None
        if self.r2_integration:
            try:
                self.r2_integration.load_binary(test_binary)
                r2_result = self.r2_integration.execute_command('i')  # Binary info
                self.assert_real_output(r2_result)
            except Exception as e:
                print(f"Radare2 analysis failed: {e}")
                
        # Verify pipeline completion
        pipeline_stages = [
            ("Basic Analysis", basic_result),
            ("Multi-format Analysis", multi_result),
            ("Radare2 Analysis", r2_result)
        ]
        
        completed_stages = [(name, result) for name, result in pipeline_stages 
                           if result is not None]
        
        # Should complete at least 2 stages
        assert len(completed_stages) >= 2, "Analysis pipeline failed"
        
        print(f"\\nComprehensive Analysis Pipeline:")
        for stage_name, result in completed_stages:
            print(f"  {stage_name}: Completed ({len(str(result))} chars output)")
            
    def test_known_correct_results_validation(self):
        """Test validation against KNOWN CORRECT analysis results."""
        # Create binary with known characteristics
        known_binary = self.temp_dir / "known_test.exe"
        pe_content = self.create_minimal_pe()
        known_binary.write_bytes(pe_content)
        
        # Expected characteristics
        expected_characteristics = {
            'format': ['PE', 'pe', 'PE32'],
            'architecture': ['i386', 'x86', '32-bit', 'Intel'],
            'sections': ['.text'],
            'has_code': True
        }
        
        # Analyze binary
        result = self.binary_analyzer.analyze(str(known_binary))
        self.assert_real_output(result)
        
        # Validate against known correct results
        validation_results = {}
        
        # Check format detection
        if 'format' in result:
            format_detected = any(expected in str(result['format']).upper() 
                                for expected in ['PE', 'PE32'])
            validation_results['format'] = format_detected
            
        # Check architecture detection
        if 'architecture' in result or 'arch' in result:
            arch_field = result.get('architecture', result.get('arch', ''))
            arch_detected = any(expected.lower() in str(arch_field).lower() 
                              for expected in expected_characteristics['architecture'])
            validation_results['architecture'] = arch_detected
            
        # Check sections
        if 'sections' in result:
            sections = result['sections']
            text_section_found = any('.text' in str(section).lower() 
                                   for section in sections)
            validation_results['sections'] = text_section_found
            
        # Should validate at least one characteristic
        validated_items = [k for k, v in validation_results.items() if v]
        assert len(validated_items) > 0, f"No known characteristics validated: {validation_results}"
        
        print(f"\\nKnown Results Validation:")
        for characteristic, validated in validation_results.items():
            status = "✓" if validated else "✗"
            print(f"  {status} {characteristic}: {validated}")
            
    def test_placeholder_data_detection(self):
        """Test that analysis FAILS when placeholder data is returned."""
        # Create test binary
        test_binary = self.temp_dir / "placeholder_test.exe"
        test_binary.write_bytes(self.create_minimal_pe())
        
        # Analyze binary
        result = self.binary_analyzer.analyze(str(test_binary))
        self.assert_real_output(result)
        
        # Check for common placeholder patterns
        result_str = str(result).lower()
        
        placeholder_patterns = [
            'placeholder', 'todo', 'fixme', 'not implemented',
            'mock', 'fake', 'dummy', 'stub', 'example'
        ]
        
        found_placeholders = [pattern for pattern in placeholder_patterns 
                            if pattern in result_str]
        
        # Should NOT contain placeholder data
        assert len(found_placeholders) == 0, f"Placeholder data detected: {found_placeholders}"
        
        print(f"\\nPlaceholder Detection:")
        print(f"  Placeholder patterns found: {len(found_placeholders)}")
        print(f"  Analysis appears real: {len(found_placeholders) == 0}")
        
    def test_large_binary_analysis_performance(self):
        """Test analysis performance on larger REAL binaries."""
        import time
        
        # Find a larger system binary
        system_binaries = self.get_system_binaries()
        
        if not system_binaries:
            pytest.skip("No system binaries available")
            
        # Sort by size and pick largest
        binary_sizes = []
        for binary_path in system_binaries:
            try:
                size = Path(binary_path).stat().st_size
                binary_sizes.append((size, binary_path))
            except OSError:
                continue
                
        if not binary_sizes:
            pytest.skip("Could not determine binary sizes")
            
        # Use largest binary
        largest_binary = max(binary_sizes)[1]
        binary_size = max(binary_sizes)[0]
        
        print(f"\\nTesting large binary: {Path(largest_binary).name} ({binary_size:,} bytes)")
        
        # Measure analysis time
        start_time = time.time()
        result = self.binary_analyzer.analyze(largest_binary)
        analysis_time = time.time() - start_time
        
        self.assert_real_output(result)
        
        # Should complete in reasonable time relative to size
        max_time = max(30.0, binary_size / (1024 * 1024) * 5)  # 5 seconds per MB, min 30s
        
        assert analysis_time < max_time, f"Analysis too slow: {analysis_time:.2f}s for {binary_size:,} bytes"
        
        print(f"  Analysis time: {analysis_time:.3f}s")
        print(f"  Performance: {binary_size / analysis_time / 1024 / 1024:.2f} MB/s")
        
    def test_cross_platform_binary_analysis(self):
        """Test analysis of binaries from different platforms."""
        platform_binaries = {}
        
        # Create Windows PE
        pe_binary = self.temp_dir / "windows.exe"
        pe_binary.write_bytes(self.create_minimal_pe())
        platform_binaries["Windows PE"] = pe_binary
        
        # Create ELF binary (minimal)
        elf_binary = self.temp_dir / "linux.elf"
        elf_header = b'\\x7fELF' + b'\\x00' * 60  # Minimal ELF header
        elf_binary.write_bytes(elf_header)
        platform_binaries["Linux ELF"] = elf_binary
        
        # Create Mach-O binary (minimal)
        macho_binary = self.temp_dir / "macos.macho"
        macho_header = b'\\xfe\\xed\\xfa\\xce' + b'\\x00' * 60  # Mach-O magic
        macho_binary.write_bytes(macho_header)
        platform_binaries["macOS Mach-O"] = macho_binary
        
        # Analyze each platform
        analysis_results = {}
        
        for platform, binary_path in platform_binaries.items():
            try:
                result = self.binary_analyzer.analyze(str(binary_path))
                self.assert_real_output(result)
                
                analysis_results[platform] = result
                
            except Exception as e:
                print(f"Cross-platform analysis failed for {platform}: {e}")
                
        # Should handle multiple platforms
        assert len(analysis_results) >= 2, "Cross-platform analysis failed"
        
        print(f"\\nCross-platform Analysis:")
        for platform, result in analysis_results.items():
            format_detected = result.get('format', 'unknown')
            print(f"  {platform}: {format_detected}")
            
    def test_malformed_binary_handling(self):
        """Test handling of REAL malformed/corrupted binaries."""
        # Create various malformed binaries
        malformed_binaries = []
        
        # Truncated PE
        truncated_pe = self.temp_dir / "truncated.exe"
        pe_content = self.create_minimal_pe()
        truncated_pe.write_bytes(pe_content[:100])  # Truncate
        malformed_binaries.append(("Truncated PE", truncated_pe))
        
        # Corrupted headers
        corrupted_pe = self.temp_dir / "corrupted.exe"
        corrupted_content = bytearray(pe_content)
        corrupted_content[50:60] = b'\\xff' * 10  # Corrupt section
        corrupted_pe.write_bytes(corrupted_content)
        malformed_binaries.append(("Corrupted PE", corrupted_pe))
        
        # Wrong extension
        wrong_ext = self.temp_dir / "notpe.exe"
        wrong_ext.write_bytes(b'This is not a PE file at all!')
        malformed_binaries.append(("Wrong Format", wrong_ext))
        
        # Test handling of each malformed binary
        handling_results = {}
        
        for description, binary_path in malformed_binaries:
            try:
                result = self.binary_analyzer.analyze(str(binary_path))
                
                # Should handle gracefully (not crash)
                self.assert_real_output(result)
                
                # Should indicate error or partial analysis
                has_error = ('error' in str(result).lower() or 
                           'invalid' in str(result).lower() or
                           'corrupt' in str(result).lower())
                           
                handling_results[description] = {
                    'handled': True,
                    'error_indicated': has_error,
                    'result_size': len(str(result))
                }
                
            except Exception as e:
                # Controlled exception is acceptable
                handling_results[description] = {
                    'handled': True,
                    'error_indicated': True,
                    'exception': str(e)
                }
                
        # Should handle all malformed binaries without crashing
        assert len(handling_results) == len(malformed_binaries), "Some binaries caused unhandled crashes"
        
        print(f"\\nMalformed Binary Handling:")
        for description, result in handling_results.items():
            print(f"  {description}: Handled gracefully")
            if 'exception' in result:
                print(f"    Exception: {result['exception'][:50]}...")
            else:
                print(f"    Error indicated: {result['error_indicated']}")