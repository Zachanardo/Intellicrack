"""
Unit tests for ELF analyzer with REAL ELF binary analysis.
Tests REAL ELF header parsing, section analysis, and symbol extraction.
NO MOCKS - ALL TESTS USE REAL BINARIES AND PRODUCE REAL RESULTS.
"""

import pytest
import struct
from pathlib import Path

from intellicrack.core.analysis.elf_analyzer import ELFAnalyzer
from tests.base_test import IntellicrackTestBase


class TestELFAnalyzer(IntellicrackTestBase):
    """Test ELF analyzer with REAL ELF binaries."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test with real ELF binaries."""
        self.analyzer = ELFAnalyzer()
        self.test_dir = Path(__file__).parent.parent.parent / 'fixtures' / 'binaries'
        
        # Use real binaries we generated
        self.simple_elf = self.test_dir / 'elf' / 'simple_x64'
        self.protected_dir = self.test_dir / 'protected'
        self.elf_x86 = self.protected_dir / 'elf_x86_0'
        self.elf_x64 = self.protected_dir / 'elf_x64_0'
        
    def test_elf_header_parsing(self):
        """Test ELF header parsing on real binary."""
        if not self.simple_elf.exists() and self.elf_x64.exists():
            test_file = self.elf_x64
        else:
            test_file = self.simple_elf
            
        result = self.analyzer.analyze_elf(test_file)
        
        # Validate real ELF analysis
        self.assert_real_output(result)
        
        # Check ELF header
        assert 'elf_header' in result
        header = result['elf_header']
        
        # Magic number
        assert header['e_ident'][0:4] == b'\x7fELF'
        
        # Class (32/64 bit)
        assert header['e_ident'][4] in [1, 2]  # ELFCLASS32 or ELFCLASS64
        
        # Data encoding
        assert header['e_ident'][5] in [1, 2]  # Little or big endian
        
        # Version
        assert header['e_ident'][6] == 1  # EV_CURRENT
        
        # Type
        assert header['e_type'] in [1, 2, 3, 4]  # REL, EXEC, DYN, CORE
        
        # Machine
        assert header['e_machine'] in [0x03, 0x3E, 0x28, 0xB7]  # x86, x86-64, ARM, ARM64
        
        # Entry point
        if header['e_type'] == 2:  # ET_EXEC
            assert header['e_entry'] > 0
            
    def test_program_header_parsing(self):
        """Test program header parsing."""
        test_file = self.elf_x64 if self.elf_x64.exists() else self.simple_elf
        
        result = self.analyzer.parse_program_headers(test_file)
        
        self.assert_real_output(result)
        assert isinstance(result, list)
        assert len(result) > 0  # Executable must have program headers
        
        for phdr in result:
            assert 'p_type' in phdr
            assert 'p_offset' in phdr
            assert 'p_vaddr' in phdr
            assert 'p_paddr' in phdr
            assert 'p_filesz' in phdr
            assert 'p_memsz' in phdr
            assert 'p_flags' in phdr
            assert 'p_align' in phdr
            
            # Check valid segment types
            valid_types = [
                0,  # PT_NULL
                1,  # PT_LOAD
                2,  # PT_DYNAMIC
                3,  # PT_INTERP
                4,  # PT_NOTE
                6,  # PT_PHDR
                0x6474e550,  # PT_GNU_EH_FRAME
                0x6474e551,  # PT_GNU_STACK
                0x6474e552,  # PT_GNU_RELRO
            ]
            assert phdr['p_type'] in valid_types
            
            # LOAD segments must have valid addresses
            if phdr['p_type'] == 1:  # PT_LOAD
                assert phdr['p_vaddr'] >= 0
                assert phdr['p_filesz'] >= 0
                assert phdr['p_memsz'] >= phdr['p_filesz']
                
    def test_section_header_parsing(self):
        """Test section header parsing."""
        test_file = self.elf_x64 if self.elf_x64.exists() else self.simple_elf
        
        result = self.analyzer.parse_section_headers(test_file)
        
        self.assert_real_output(result)
        assert isinstance(result, list)
        assert len(result) > 0
        
        section_names = []
        for shdr in result:
            assert 'sh_name' in shdr
            assert 'sh_type' in shdr
            assert 'sh_flags' in shdr
            assert 'sh_addr' in shdr
            assert 'sh_offset' in shdr
            assert 'sh_size' in shdr
            assert 'sh_link' in shdr
            assert 'sh_info' in shdr
            assert 'sh_addralign' in shdr
            assert 'sh_entsize' in shdr
            assert 'name' in shdr  # Resolved section name
            
            section_names.append(shdr['name'])
            
        # Common ELF sections
        common_sections = ['.text', '.data', '.bss', '.rodata']
        assert any(name in section_names for name in common_sections)
        
    def test_symbol_table_parsing(self):
        """Test symbol table extraction."""
        test_file = self.elf_x64 if self.elf_x64.exists() else self.simple_elf
        
        symbols = self.analyzer.parse_symbol_table(test_file)
        
        assert isinstance(symbols, list)
        # Stripped binaries might have no symbols
        if symbols:
            self.assert_real_output(symbols)
            for sym in symbols:
                assert 'name' in sym
                assert 'value' in sym
                assert 'size' in sym
                assert 'type' in sym
                assert 'bind' in sym
                assert 'visibility' in sym
                assert 'section_index' in sym
                
    def test_dynamic_section_parsing(self):
        """Test dynamic section parsing."""
        test_file = self.elf_x64 if self.elf_x64.exists() else self.simple_elf
        
        dynamic = self.analyzer.parse_dynamic_section(test_file)
        
        assert isinstance(dynamic, list)
        # Static binaries won't have dynamic section
        if dynamic:
            self.assert_real_output(dynamic)
            for entry in dynamic:
                assert 'd_tag' in entry
                assert 'd_val' in entry
                assert 'tag_name' in entry  # Human readable tag name
                
                # Common dynamic tags
                valid_tags = [
                    1,   # DT_NEEDED
                    2,   # DT_PLTRELSZ
                    3,   # DT_PLTGOT
                    4,   # DT_HASH
                    5,   # DT_STRTAB
                    6,   # DT_SYMTAB
                    12,  # DT_INIT
                    13,  # DT_FINI
                ]
                
    def test_relocation_parsing(self):
        """Test relocation entries parsing."""
        test_file = self.elf_x64 if self.elf_x64.exists() else self.simple_elf
        
        relocations = self.analyzer.parse_relocations(test_file)
        
        assert isinstance(relocations, dict)
        # Static binaries might not have relocations
        if relocations:
            self.assert_real_output(relocations)
            for section, relocs in relocations.items():
                assert isinstance(relocs, list)
                for reloc in relocs:
                    assert 'offset' in reloc
                    assert 'type' in reloc
                    assert 'symbol' in reloc
                    
    def test_architecture_detection(self):
        """Test architecture detection for different ELF files."""
        # Test x86
        if self.elf_x86.exists():
            arch_x86 = self.analyzer.get_architecture(self.elf_x86)
            self.assert_real_output(arch_x86)
            assert arch_x86 == 'x86'
            
        # Test x64
        if self.elf_x64.exists():
            arch_x64 = self.analyzer.get_architecture(self.elf_x64)
            self.assert_real_output(arch_x64)
            assert arch_x64 == 'x64'
            
    def test_interpreter_extraction(self):
        """Test interpreter (dynamic linker) extraction."""
        test_file = self.elf_x64 if self.elf_x64.exists() else self.simple_elf
        
        interpreter = self.analyzer.get_interpreter(test_file)
        
        # Static binaries won't have interpreter
        assert interpreter is None or isinstance(interpreter, str)
        
        if interpreter:
            self.assert_real_output(interpreter)
            # Common interpreters
            common_interpreters = [
                '/lib/ld-linux.so.2',      # 32-bit
                '/lib64/ld-linux-x86-64.so.2',  # 64-bit
                '/lib/ld-musl-x86_64.so.1',     # musl
            ]
            assert any(interp in interpreter for interp in common_interpreters)
            
    def test_string_extraction(self):
        """Test string extraction from ELF binary."""
        test_file = self.elf_x64 if self.elf_x64.exists() else self.simple_elf
        
        strings = self.analyzer.extract_strings(test_file, min_length=4)
        
        self.assert_real_output(strings)
        assert isinstance(strings, list)
        assert len(strings) > 0  # Every binary has some strings
        
        for string_info in strings:
            assert 'offset' in string_info
            assert 'string' in string_info
            assert 'section' in string_info
            
            # Validate string properties
            assert len(string_info['string']) >= 4
            assert not string_info['string'].startswith('MOCK_')
            
    def test_security_features_detection(self):
        """Test security features detection (NX, PIE, RELRO, etc)."""
        test_file = self.elf_x64 if self.elf_x64.exists() else self.simple_elf
        
        security = self.analyzer.check_security_features(test_file)
        
        self.assert_real_output(security)
        assert isinstance(security, dict)
        
        # Expected security checks
        expected_features = [
            'nx_enabled',      # Non-executable stack
            'pie_enabled',     # Position Independent Executable
            'relro',          # RELRO protection level
            'stack_canary',   # Stack protector
            'fortify_source', # FORTIFY_SOURCE
        ]
        
        for feature in expected_features:
            assert feature in security
            
    def test_entropy_calculation(self):
        """Test entropy calculation for ELF sections."""
        test_file = self.elf_x64 if self.elf_x64.exists() else self.simple_elf
        
        entropy_map = self.analyzer.calculate_section_entropy(test_file)
        
        self.assert_real_output(entropy_map)
        assert isinstance(entropy_map, dict)
        assert len(entropy_map) > 0
        
        for section, entropy in entropy_map.items():
            assert isinstance(entropy, float)
            assert 0.0 <= entropy <= 8.0
            
            # Code sections typically have higher entropy
            if section == '.text':
                assert entropy > 4.0
                
    def test_packer_detection(self):
        """Test packer/protector detection in ELF."""
        test_file = self.elf_x64 if self.elf_x64.exists() else self.simple_elf
        
        packers = self.analyzer.detect_packers(test_file)
        
        assert isinstance(packers, list)
        # Our test binaries shouldn't be packed
        
    def test_library_dependencies(self):
        """Test shared library dependency extraction."""
        test_file = self.elf_x64 if self.elf_x64.exists() else self.simple_elf
        
        deps = self.analyzer.get_library_dependencies(test_file)
        
        assert isinstance(deps, list)
        # Static binaries have no dependencies
        if deps:
            self.assert_real_output(deps)
            for dep in deps:
                assert isinstance(dep, str)
                assert dep.endswith('.so') or '.so.' in dep
                
    def test_build_id_extraction(self):
        """Test build ID extraction."""
        test_file = self.elf_x64 if self.elf_x64.exists() else self.simple_elf
        
        build_id = self.analyzer.get_build_id(test_file)
        
        # Not all binaries have build ID
        assert build_id is None or isinstance(build_id, str)
        
        if build_id:
            self.assert_real_output(build_id)
            # Build ID is typically hex string
            assert all(c in '0123456789abcdef' for c in build_id.lower())
            
    def test_function_symbols(self):
        """Test function symbol extraction."""
        test_file = self.elf_x64 if self.elf_x64.exists() else self.simple_elf
        
        functions = self.analyzer.get_function_symbols(test_file)
        
        assert isinstance(functions, list)
        # Stripped binaries might have no function symbols
        if functions:
            self.assert_real_output(functions)
            for func in functions:
                assert 'name' in func
                assert 'address' in func
                assert 'size' in func
                assert func['address'] > 0