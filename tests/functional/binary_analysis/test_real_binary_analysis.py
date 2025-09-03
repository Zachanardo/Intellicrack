import pytest
import tempfile
import os
import shutil
from pathlib import Path

from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer
from intellicrack.core.analysis.radare2_enhanced_integration import Radare2EnhancedIntegration
from intellicrack.core.analysis.multi_format_analyzer import MultiFormatAnalyzer
from intellicrack.core.analysis.entropy_analyzer import EntropyAnalyzer
from intellicrack.protection.protection_detector import ProtectionDetector
from intellicrack.core.app_context import AppContext


class TestRealBinaryAnalysis:
    """Functional tests for REAL binary analysis with actual file formats."""

    @pytest.fixture
    def real_pe_executable(self):
        """Create REAL PE executable for functional testing."""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as temp_file:
            dos_header = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
            dos_header += b'\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00'
            dos_header += b'\x00' * 40
            dos_header += b'\x80\x00\x00\x00'
            dos_header += b'\x00' * 60

            pe_signature = b'PE\x00\x00'

            coff_header = b'\x4c\x01'
            coff_header += b'\x02\x00'
            coff_header += b'\x00\x00\x00\x00'
            coff_header += b'\x00\x00\x00\x00'
            coff_header += b'\xe0\x00'
            coff_header += b'\x02\x01'

            optional_header = b'\x0b\x01'
            optional_header += b'\x0e\x00'
            optional_header += b'\x00\x10\x00\x00'
            optional_header += b'\x00\x10\x00\x00'
            optional_header += b'\x00\x00\x00\x00'
            optional_header += b'\x00\x30\x00\x00'
            optional_header += b'\x00\x10\x00\x00'
            optional_header += b'\x00\x02\x00\x00'
            optional_header += b'\x05\x00\x01\x00'
            optional_header += b'\x05\x00\x01\x00'
            optional_header += b'\x04\x00\x00\x00'
            optional_header += b'\x00\x00\x00\x00'
            optional_header += b'\x00\x50\x00\x00'
            optional_header += b'\x00\x04\x00\x00'
            optional_header += b'\x00\x00\x00\x00'
            optional_header += b'\x03\x00'
            optional_header += b'\x60\x01'
            optional_header += b'\x00\x10\x00\x00'
            optional_header += b'\x00\x10\x00\x00'
            optional_header += b'\x00\x10\x00\x00'
            optional_header += b'\x00\x00\x00\x00'
            optional_header += b'\x00' * (224 - len(optional_header))

            section_text = b'\x2e\x74\x65\x78\x74\x00\x00\x00'
            section_text += b'\x00\x10\x00\x00'
            section_text += b'\x00\x10\x00\x00'
            section_text += b'\x00\x10\x00\x00'
            section_text += b'\x00\x04\x00\x00'
            section_text += b'\x00\x00\x00\x00'
            section_text += b'\x00\x00\x00\x00'
            section_text += b'\x00\x00\x00\x00'
            section_text += b'\x20\x00\x00\x60'

            section_data = b'\x2e\x64\x61\x74\x61\x00\x00\x00'
            section_data += b'\x00\x10\x00\x00'
            section_data += b'\x00\x20\x00\x00'
            section_data += b'\x00\x10\x00\x00'
            section_data += b'\x00\x14\x00\x00'
            section_data += b'\x00\x00\x00\x00'
            section_data += b'\x00\x00\x00\x00'
            section_data += b'\x00\x00\x00\x00'
            section_data += b'\x40\x00\x00\xc0'

            text_section_code = b'\x55'
            text_section_code += b'\x8b\xec'
            text_section_code += b'\x83\xec\x08'
            text_section_code += b'\x53\x56\x57'
            text_section_code += b'\x68\x00\x20\x40\x00'
            text_section_code += b'\x68\x00\x30\x40\x00'
            text_section_code += b'\x6a\x00'
            text_section_code += b'\xff\x15\x10\x20\x40\x00'
            text_section_code += b'\x33\xc0'
            text_section_code += b'\x5f\x5e\x5b'
            text_section_code += b'\x8b\xe5\x5d'
            text_section_code += b'\xc3'
            text_section_code += b'\x90' * (4096 - len(text_section_code))

            data_section_content = b'Hello World!\x00\x00\x00\x00'
            data_section_content += b'This is a test binary\x00\x00'
            data_section_content += b'\x00' * (4096 - len(data_section_content))

            temp_file.write(dos_header + pe_signature + coff_header + optional_header +
                          section_text + section_data + text_section_code + data_section_content)
            temp_file.flush()
            yield temp_file.name

        try:
            os.unlink(temp_file.name)
        except:
            pass

    @pytest.fixture
    def real_elf_binary(self):
        """Create REAL ELF binary for functional testing."""
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            elf_header = b'\x7f\x45\x4c\x46'
            elf_header += b'\x02\x01\x01\x00'
            elf_header += b'\x00' * 8
            elf_header += b'\x02\x00'
            elf_header += b'\x3e\x00'
            elf_header += b'\x01\x00\x00\x00'
            elf_header += b'\x80\x10\x40\x00\x00\x00\x00\x00'
            elf_header += b'\x40\x00\x00\x00\x00\x00\x00\x00'
            elf_header += b'\x00\x00\x00\x00\x00\x00\x00\x00'
            elf_header += b'\x00\x00\x00\x00'
            elf_header += b'\x40\x00\x38\x00'
            elf_header += b'\x01\x00\x40\x00'
            elf_header += b'\x00\x00\x00\x00'

            program_header = b'\x01\x00\x00\x00'
            program_header += b'\x05\x00\x00\x00'
            program_header += b'\x00\x00\x00\x00\x00\x00\x00\x00'
            program_header += b'\x00\x10\x40\x00\x00\x00\x00\x00'
            program_header += b'\x00\x10\x40\x00\x00\x00\x00\x00'
            program_header += b'\x00\x10\x00\x00\x00\x00\x00\x00'
            program_header += b'\x00\x10\x00\x00\x00\x00\x00\x00'
            program_header += b'\x00\x10\x00\x00\x00\x00\x00\x00'

            code_section = b'\x48\x31\xc0'
            code_section += b'\x48\xff\xc0'
            code_section += b'\x48\x31\xff'
            code_section += b'\x48\x31\xf6'
            code_section += b'\x48\x31\xd2'
            code_section += b'\x0f\x05'
            code_section += b'\x90' * (4096 - len(code_section))

            temp_file.write(elf_header + program_header + code_section)
            temp_file.flush()
            yield temp_file.name

        try:
            os.unlink(temp_file.name)
        except:
            pass

    @pytest.fixture
    def packed_binary(self):
        """Create REAL packed binary for functional testing."""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as temp_file:
            dos_header = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
            dos_header += b'\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00'
            dos_header += b'\x00' * 40
            dos_header += b'\x80\x00\x00\x00'
            dos_header += b'\x00' * 60

            pe_signature = b'PE\x00\x00'
            coff_header = b'\x4c\x01\x03\x00' + b'\x00' * 16
            optional_header = b'\x0b\x01\x0e\x00' + b'\x00' * 220

            upx_section_1 = b'UPX0\x00\x00\x00\x00'
            upx_section_1 += b'\x00\x10\x00\x00'
            upx_section_1 += b'\x00\x10\x00\x00'
            upx_section_1 += b'\x00\x00\x00\x00'
            upx_section_1 += b'\x00\x04\x00\x00'
            upx_section_1 += b'\x00\x00\x00\x00'
            upx_section_1 += b'\x00\x00\x00\x00'
            upx_section_1 += b'\x00\x00\x00\x00'
            upx_section_1 += b'\x80\x00\x00\x60'

            upx_section_2 = b'UPX1\x00\x00\x00\x00'
            upx_section_2 += b'\x00\x10\x00\x00'
            upx_section_2 += b'\x00\x20\x00\x00'
            upx_section_2 += b'\x00\x10\x00\x00'
            upx_section_2 += b'\x00\x14\x00\x00'
            upx_section_2 += b'\x00\x00\x00\x00'
            upx_section_2 += b'\x00\x00\x00\x00'
            upx_section_2 += b'\x00\x00\x00\x00'
            upx_section_2 += b'\x80\x00\x00\x60'

            compressed_data = b'\x55\x8b\xec\x83\xec\x08'
            compressed_data += b'\x68\x00\x40\x00\x00'
            compressed_data += b'\xff\x15\x00\x20\x00\x00'
            compressed_data += b'\x90' * (4096 - len(compressed_data))

            upx_stub = b'\x60\x8b\x74\x24\x24\x8b\x7c\x24\x28'
            upx_stub += b'\xfc\xb2\x80\x33\xdb\xa4\xb3\x02'
            upx_stub += b'\xe8\x6d\x00\x00\x00\x73\xf6\x31\xc9'
            upx_stub += b'\x90' * (4096 - len(upx_stub))

            temp_file.write(dos_header + pe_signature + coff_header + optional_header +
                          upx_section_1 + upx_section_2 + upx_stub + compressed_data)
            temp_file.flush()
            yield temp_file.name

        try:
            os.unlink(temp_file.name)
        except:
            pass

    @pytest.fixture
    def app_context(self):
        """Create REAL application context."""
        context = AppContext()
        context.initialize()
        return context

    def test_complete_pe_analysis_functionality(self, real_pe_executable, app_context):
        """Test REAL complete PE file analysis functionality."""
        analyzer = BinaryAnalyzer()

        analysis_result = analyzer.analyze_file(real_pe_executable)

        assert analysis_result is not None, "PE analysis must return results"
        assert analysis_result['file_type'] == 'PE', "Must correctly identify PE file type"
        assert 'file_size' in analysis_result, "Must report actual file size"
        assert analysis_result['file_size'] > 0, "File size must be greater than 0"

        assert 'sections' in analysis_result, "Must identify PE sections"
        sections = analysis_result['sections']
        assert len(sections) >= 2, "Must identify at least .text and .data sections"

        text_section_found = False
        data_section_found = False

        for section in sections:
            assert 'name' in section, "Each section must have a name"
            assert 'virtual_address' in section, "Each section must have virtual address"
            assert 'raw_size' in section, "Each section must have raw size"
            assert 'characteristics' in section, "Each section must have characteristics"

            if section['name'] == '.text':
                text_section_found = True
                assert section['characteristics'] & 0x20000000, ".text section must be executable"
            elif section['name'] == '.data':
                data_section_found = True
                assert section['characteristics'] & 0x80000000, ".data section must be writable"

        assert text_section_found, "Must find .text section"
        assert data_section_found, "Must find .data section"

        assert 'imports' in analysis_result, "Must analyze imports"
        assert 'strings' in analysis_result, "Must extract strings"

        strings = analysis_result['strings']
        assert len(strings) > 0, "Must extract at least some strings"

        hello_world_found = any('Hello World' in s for s in strings)
        assert hello_world_found, "Must find 'Hello World' string in binary"

    def test_elf_binary_analysis_functionality(self, real_elf_binary, app_context):
        """Test REAL ELF binary analysis functionality."""
        analyzer = MultiFormatAnalyzer()

        analysis_result = analyzer.analyze_file(real_elf_binary)

        assert analysis_result is not None, "ELF analysis must return results"
        assert analysis_result['file_type'] == 'ELF', "Must correctly identify ELF file type"
        assert 'architecture' in analysis_result, "Must identify architecture"
        assert analysis_result['architecture'] in ['x86_64', 'amd64'], "Must identify x86_64 architecture"

        assert 'program_headers' in analysis_result, "Must identify program headers"
        program_headers = analysis_result['program_headers']
        assert len(program_headers) > 0, "Must find at least one program header"

        for header in program_headers:
            assert 'type' in header, "Each program header must have type"
            assert 'offset' in header, "Each program header must have offset"
            assert 'virtual_address' in header, "Each program header must have virtual address"
            assert 'size' in header, "Each program header must have size"

        assert 'entry_point' in analysis_result, "Must identify entry point"
        entry_point = analysis_result['entry_point']
        assert entry_point > 0, "Entry point must be valid address"

    def test_packed_binary_detection_functionality(self, packed_binary, app_context):
        """Test REAL packed binary detection functionality."""
        detector = ProtectionDetector()
        analyzer = BinaryAnalyzer()

        protection_result = detector.analyze_file(packed_binary)
        assert protection_result is not None, "Protection detection must return results"

        protections = protection_result['protections']
        upx_detected = any('UPX' in p.get('name', '') for p in protections)
        assert upx_detected, "Must detect UPX packer"

        binary_result = analyzer.analyze_file(packed_binary)
        assert binary_result is not None, "Binary analysis must work on packed files"

        sections = binary_result['sections']
        upx_sections = [s for s in sections if 'UPX' in s.get('name', '')]
        assert len(upx_sections) >= 2, "Must identify UPX sections (UPX0, UPX1)"

        entropy_analyzer = EntropyAnalyzer()
        with open(packed_binary, 'rb') as f:
            file_data = f.read()

        entropy = entropy_analyzer.calculate_entropy(file_data)
        assert entropy > 6.0, "Packed binary should have high entropy (> 6.0)"

    def test_radare2_integration_functionality(self, real_pe_executable, app_context):
        """Test REAL radare2 integration functionality."""
        r2_integration = Radare2EnhancedIntegration()

        session = r2_integration.create_session(real_pe_executable)
        assert session is not None, "Must create radare2 session"

        try:
            binary_info = r2_integration.get_binary_info(session)
            assert binary_info is not None, "Must retrieve binary information"
            assert binary_info['format'] == 'pe', "Must identify PE format"
            assert 'entry_point' in binary_info, "Must identify entry point"

            functions = r2_integration.analyze_functions(session)
            assert functions is not None, "Must analyze functions"
            assert isinstance(functions, list), "Functions must be a list"

            if len(functions) > 0:
                main_function = None
                for func in functions:
                    if 'main' in func.get('name', '') or func.get('address') == binary_info.get('entry_point'):
                        main_function = func
                        break

                if main_function:
                    disasm = r2_integration.disassemble_function(session, main_function['name'])
                    assert disasm is not None, "Must disassemble main function"
                    assert len(disasm) > 0, "Disassembly must contain instructions"

                    for instruction in disasm:
                        assert 'address' in instruction, "Each instruction must have address"
                        assert 'opcode' in instruction, "Each instruction must have opcode"

            strings = r2_integration.extract_strings(session)
            assert strings is not None, "Must extract strings"
            assert len(strings) > 0, "Must find strings in binary"

            hello_string = any('Hello World' in s.get('value', '') for s in strings)
            assert hello_string, "Must find 'Hello World' string"

        finally:
            r2_integration.close_session(session)

    def test_entropy_analysis_functionality(self, real_pe_executable, packed_binary):
        """Test REAL entropy analysis functionality."""
        entropy_analyzer = EntropyAnalyzer()

        with open(real_pe_executable, 'rb') as f:
            pe_data = f.read()

        pe_entropy = entropy_analyzer.calculate_entropy(pe_data)
        assert pe_entropy is not None, "Must calculate PE entropy"
        assert 0 <= pe_entropy <= 8, "Entropy must be between 0 and 8"
        assert pe_entropy < 7.0, "Normal PE should have entropy < 7.0"

        section_entropies = entropy_analyzer.calculate_section_entropies(pe_data, 'PE')
        assert section_entropies is not None, "Must calculate section entropies"
        assert len(section_entropies) > 0, "Must analyze at least one section"

        for section_name, entropy_value in section_entropies.items():
            assert 0 <= entropy_value <= 8, f"Section {section_name} entropy must be valid"

        with open(packed_binary, 'rb') as f:
            packed_data = f.read()

        packed_entropy = entropy_analyzer.calculate_entropy(packed_data)
        assert packed_entropy > pe_entropy, "Packed binary should have higher entropy than normal PE"
        assert packed_entropy > 6.0, "Packed binary entropy should be > 6.0"

        entropy_blocks = entropy_analyzer.calculate_block_entropies(packed_data, block_size=1024)
        assert entropy_blocks is not None, "Must calculate block entropies"
        assert len(entropy_blocks) > 0, "Must analyze entropy blocks"

        high_entropy_blocks = [e for e in entropy_blocks if e > 7.0]
        assert len(high_entropy_blocks) > 0, "Packed binary should have high-entropy blocks"

    def test_multi_format_analysis_functionality(self, real_pe_executable, real_elf_binary, app_context):
        """Test REAL multi-format analysis functionality."""
        multi_analyzer = MultiFormatAnalyzer()

        pe_result = multi_analyzer.analyze_file(real_pe_executable)
        assert pe_result is not None, "PE multi-format analysis must succeed"
        assert pe_result['file_type'] == 'PE', "Must identify PE format"
        assert 'pe_specific' in pe_result, "Must include PE-specific analysis"

        pe_specific = pe_result['pe_specific']
        assert 'subsystem' in pe_specific, "Must identify PE subsystem"
        assert 'machine_type' in pe_specific, "Must identify machine type"
        assert 'timestamp' in pe_specific, "Must extract compilation timestamp"

        elf_result = multi_analyzer.analyze_file(real_elf_binary)
        assert elf_result is not None, "ELF multi-format analysis must succeed"
        assert elf_result['file_type'] == 'ELF', "Must identify ELF format"
        assert 'elf_specific' in elf_result, "Must include ELF-specific analysis"

        elf_specific = elf_result['elf_specific']
        assert 'class' in elf_specific, "Must identify ELF class (32/64-bit)"
        assert 'endianness' in elf_specific, "Must identify endianness"
        assert 'abi' in elf_specific, "Must identify ABI"

        format_comparison = multi_analyzer.compare_formats([pe_result, elf_result])
        assert format_comparison is not None, "Must compare different formats"
        assert 'similarities' in format_comparison, "Must identify similarities"
        assert 'differences' in format_comparison, "Must identify differences"

    def test_comprehensive_binary_workflow(self, real_pe_executable, app_context):
        """Test REAL comprehensive binary analysis workflow."""
        analyzer = BinaryAnalyzer()
        protection_detector = ProtectionDetector()
        entropy_analyzer = EntropyAnalyzer()
        r2_integration = Radare2EnhancedIntegration()

        binary_result = analyzer.analyze_file(real_pe_executable)
        assert binary_result is not None, "Binary analysis must succeed"

        protection_result = protection_detector.analyze_file(real_pe_executable)
        assert protection_result is not None, "Protection detection must succeed"

        with open(real_pe_executable, 'rb') as f:
            file_data = f.read()
        entropy_result = entropy_analyzer.calculate_entropy(file_data)
        assert entropy_result is not None, "Entropy analysis must succeed"

        r2_session = r2_integration.create_session(real_pe_executable)
        assert r2_session is not None, "Radare2 session must be created"

        try:
            r2_functions = r2_integration.analyze_functions(r2_session)
            r2_strings = r2_integration.extract_strings(r2_session)

            comprehensive_result = {
                'binary_analysis': binary_result,
                'protection_analysis': protection_result,
                'entropy_analysis': entropy_result,
                'radare2_functions': r2_functions,
                'radare2_strings': r2_strings
            }

            assert len(comprehensive_result['binary_analysis']['sections']) > 0, "Must have sections"
            assert len(comprehensive_result['binary_analysis']['strings']) > 0, "Must have strings"
            assert comprehensive_result['entropy_analysis'] > 0, "Must have valid entropy"

            if comprehensive_result['radare2_functions']:
                assert len(comprehensive_result['radare2_functions']) > 0, "Must find functions"

            if comprehensive_result['radare2_strings']:
                assert len(comprehensive_result['radare2_strings']) > 0, "Must find strings"

            consistency_check = analyzer.validate_analysis_consistency(comprehensive_result)
            assert consistency_check['valid'], "Comprehensive analysis must be consistent"

        finally:
            r2_integration.close_session(r2_session)

    def test_error_handling_with_corrupted_files(self, app_context):
        """Test REAL error handling with corrupted files."""
        analyzer = BinaryAnalyzer()

        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as temp_file:
            corrupted_data = b'MZ' + b'\x00' * 100 + b'corrupted_data' * 50
            temp_file.write(corrupted_data)
            temp_file.flush()

            try:
                result = analyzer.analyze_file(temp_file.name)

                if result is not None:
                    assert 'error' in result or 'warnings' in result, "Corrupted file should produce errors/warnings"

                    if 'error' in result:
                        assert 'corrupted' in result['error'].lower() or 'invalid' in result['error'].lower(), \
                            "Error should indicate file corruption"

            except Exception as e:
                assert 'corrupted' in str(e).lower() or 'invalid' in str(e).lower() or 'malformed' in str(e).lower(), \
                    "Exception should indicate file corruption issues"

            finally:
                os.unlink(temp_file.name)

    def test_performance_with_large_binary(self, app_context):
        """Test REAL performance with larger binary files."""
        analyzer = BinaryAnalyzer()

        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as temp_file:
            dos_header = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
            dos_header += b'\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00'
            dos_header += b'\x00' * 40
            dos_header += b'\x80\x00\x00\x00'
            dos_header += b'\x00' * 60

            pe_signature = b'PE\x00\x00'
            coff_header = b'\x4c\x01\x02\x00' + b'\x00' * 16
            optional_header = b'\x0b\x01\x0e\x00' + b'\x00' * 220

            section_header = b'\x2e\x74\x65\x78\x74\x00\x00\x00'
            section_header += b'\x00\x00\x10\x00'
            section_header += b'\x00\x10\x00\x00'
            section_header += b'\x00\x00\x10\x00'
            section_header += b'\x00\x04\x00\x00'
            section_header += b'\x00' * 12
            section_header += b'\x20\x00\x00\x60'

            large_code_section = b'\x90' * (1024 * 1024)

            temp_file.write(dos_header + pe_signature + coff_header + optional_header +
                          section_header + large_code_section)
            temp_file.flush()

            import time
            start_time = time.time()

            try:
                result = analyzer.analyze_file(temp_file.name)

                end_time = time.time()
                analysis_time = end_time - start_time

                assert result is not None, "Large binary analysis must succeed"
                assert analysis_time < 30.0, "Large binary analysis should complete under 30 seconds"
                assert result['file_size'] > 1024 * 1024, "Must correctly report large file size"

            finally:
                os.unlink(temp_file.name)
