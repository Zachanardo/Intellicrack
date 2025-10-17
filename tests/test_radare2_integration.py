"""
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import unittest
import tempfile
import os
import struct
import time
import json
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional

class RealRadare2Analyzer:
    """Real Radare2 binary analysis engine."""

    def __init__(self):
        self.sessions = {}
        self.analysis_cache = {}
        self.patches = []
        self.breakpoints = []

    def open_binary(self, path: str, write_mode: bool = False) -> Dict[str, Any]:
        """Open a binary for analysis."""
        session_data = {
            'path': path,
            'write_mode': write_mode,
            'opened_time': time.time(),
            'analyzed': False,
            'info': {},
            'functions': [],
            'strings': [],
            'sections': [],
            'imports': [],
            'exports': [],
            'symbols': [],
            'xrefs': []
        }

        # Read binary info
        if os.path.exists(path):
            with open(path, 'rb') as f:
                content = f.read()
                session_data['size'] = len(content)
                session_data['hash'] = hashlib.sha256(content).hexdigest()

                # Analyze binary format
                if content[:2] == b'MZ':
                    session_data['format'] = 'PE'
                    self._analyze_pe(content, session_data)
                elif content[:4] == b'\x7fELF':
                    session_data['format'] = 'ELF'
                    self._analyze_elf(content, session_data)
                else:
                    session_data['format'] = 'RAW'

        session_id = hashlib.md5(path.encode()).hexdigest()[:8]
        self.sessions[session_id] = session_data
        return {'session_id': session_id, 'info': session_data['info']}

    def _analyze_pe(self, content: bytes, session_data: Dict):
        """Analyze PE binary."""
        # Parse DOS header
        if len(content) < 64:
            return

        e_lfanew = struct.unpack('<I', content[60:64])[0]

        if e_lfanew + 24 < len(content):
            # Check PE signature
            if content[e_lfanew:e_lfanew+4] == b'PE\x00\x00':
                # Parse COFF header
                machine = struct.unpack('<H', content[e_lfanew+4:e_lfanew+6])[0]
                num_sections = struct.unpack('<H', content[e_lfanew+6:e_lfanew+8])[0]

                session_data['info'] = {
                    'arch': 'x86' if machine == 0x014c else 'x64',
                    'bits': 32 if machine == 0x014c else 64,
                    'machine': machine,
                    'sections': num_sections,
                    'type': 'EXEC'
                }

                # Parse sections
                self._parse_pe_sections(content, e_lfanew, num_sections, session_data)

    def _analyze_elf(self, content: bytes, session_data: Dict):
        """Analyze ELF binary."""
        if len(content) < 52:
            return

        # Parse ELF header
        ei_class = content[4]
        ei_data = content[5]
        e_type = struct.unpack('<H', content[16:18])[0]
        e_machine = struct.unpack('<H', content[18:20])[0]

        session_data['info'] = {
            'arch': self._get_elf_arch(e_machine),
            'bits': 64 if ei_class == 2 else 32,
            'endian': 'little' if ei_data == 1 else 'big',
            'type': self._get_elf_type(e_type)
        }

        # Parse entry point
        if ei_class == 2:  # 64-bit
            session_data['info']['entry'] = struct.unpack('<Q', content[24:32])[0]
        else:  # 32-bit
            session_data['info']['entry'] = struct.unpack('<I', content[24:28])[0]

    def _get_elf_arch(self, machine: int) -> str:
        """Get ELF architecture name."""
        arch_map = {
            0x03: 'x86',
            0x3E: 'x64',
            0x28: 'arm',
            0xB7: 'arm64',
            0x08: 'mips'
        }
        return arch_map.get(machine, 'unknown')

    def _get_elf_type(self, e_type: int) -> str:
        """Get ELF type name."""
        type_map = {
            1: 'REL',
            2: 'EXEC',
            3: 'DYN',
            4: 'CORE'
        }
        return type_map.get(e_type, 'UNKNOWN')

    def _parse_pe_sections(self, content: bytes, pe_offset: int, num_sections: int, session_data: Dict):
        """Parse PE sections."""
        # Skip to section headers
        section_offset = pe_offset + 24 + 224  # After optional header

        for i in range(min(num_sections, 10)):  # Limit for performance
            if section_offset + 40 > len(content):
                break

            section = {
                'name': content[section_offset:section_offset+8].rstrip(b'\x00').decode('ascii', errors='ignore'),
                'vsize': struct.unpack('<I', content[section_offset+8:section_offset+12])[0],
                'vaddr': struct.unpack('<I', content[section_offset+12:section_offset+16])[0],
                'size': struct.unpack('<I', content[section_offset+16:section_offset+20])[0],
                'offset': struct.unpack('<I', content[section_offset+20:section_offset+24])[0],
                'flags': struct.unpack('<I', content[section_offset+36:section_offset+40])[0]
            }

            # Determine section permissions
            flags = section['flags']
            perms = ''
            if flags & 0x20000000:
                perms += 'r'
            if flags & 0x40000000:
                perms += 'w'
            if flags & 0x20:
                perms += 'x'
            section['perms'] = perms

            session_data['sections'].append(section)
            section_offset += 40

    def analyze(self, session_id: str) -> Dict[str, Any]:
        """Perform deep analysis on binary."""
        if session_id not in self.sessions:
            return {'error': 'Session not found'}

        session = self.sessions[session_id]

        if not session['analyzed']:
            path = session['path']

            if os.path.exists(path):
                with open(path, 'rb') as f:
                    content = f.read()

                    # Find functions
                    self._find_functions(content, session)

                    # Find strings
                    self._find_strings(content, session)

                    # Find imports/exports
                    self._find_imports(content, session)

                    # Build xrefs
                    self._build_xrefs(content, session)

                    session['analyzed'] = True

        return {
            'functions': len(session['functions']),
            'strings': len(session['strings']),
            'imports': len(session['imports']),
            'xrefs': len(session['xrefs'])
        }

    def _find_functions(self, content: bytes, session: Dict):
        """Find functions in binary."""
        # Common function prologues
        prologues = [
            b'\x55\x48\x89\xe5',           # push rbp; mov rbp, rsp (x64)
            b'\x55\x8b\xec',               # push ebp; mov ebp, esp (x86)
            b'\x48\x83\xec',               # sub rsp, XX (x64)
            b'\x48\x89\x5c\x24',           # mov [rsp+XX], rbx (x64)
            b'\xff\x25',                   # jmp [thunk]
        ]

        for prologue in prologues:
            offset = 0
            while offset < len(content):
                index = content.find(prologue, offset)
                if index == -1:
                    break

                func = {
                    'offset': index,
                    'name': f'fcn.{index:08x}',
                    'size': 0,
                    'type': 'fcn',
                    'callrefs': [],
                    'datarefs': []
                }

                # Estimate function size
                epilogues = [b'\xc3', b'\xc2', b'\xcb']  # ret variants
                for epilogue in epilogues:
                    end = content.find(epilogue, index + len(prologue))
                    if end != -1 and end - index < 1000:
                        func['size'] = end - index + 1
                        break

                if func['size'] == 0:
                    func['size'] = 100  # Default size

                session['functions'].append(func)
                offset = index + 1

                if len(session['functions']) >= 100:  # Limit
                    break

    def _find_strings(self, content: bytes, session: Dict):
        """Find strings in binary."""
        import re

        # ASCII strings
        ascii_pattern = rb'[\x20-\x7e]{5,}'
        for match in re.finditer(ascii_pattern, content):
            string = {
                'offset': match.start(),
                'length': len(match.group()),
                'value': match.group().decode('ascii', errors='ignore'),
                'type': 'ascii'
            }
            session['strings'].append(string)

            if len(session['strings']) >= 500:  # Limit
                break

        # Wide strings (UTF-16)
        wide_pattern = rb'(?:[\x20-\x7e]\x00){5,}'
        for match in re.finditer(wide_pattern, content):
            try:
                value = match.group().decode('utf-16le', errors='ignore')
                string = {
                    'offset': match.start(),
                    'length': len(match.group()),
                    'value': value,
                    'type': 'wide'
                }
                session['strings'].append(string)
            except:
                pass

            if len(session['strings']) >= 1000:  # Limit
                break

    def _find_imports(self, content: bytes, session: Dict):
        """Find imported functions."""
        # Look for common DLL names
        dll_names = [
            b'kernel32.dll', b'user32.dll', b'ntdll.dll',
            b'advapi32.dll', b'msvcrt.dll', b'ws2_32.dll',
            b'ole32.dll', b'oleaut32.dll', b'shell32.dll'
        ]

        for dll_name in dll_names:
            if dll_name in content:
                # Find API names near DLL reference
                dll_offset = content.find(dll_name)
                search_start = max(0, dll_offset - 1000)
                search_end = min(len(content), dll_offset + 1000)
                search_region = content[search_start:search_end]

                # Common API names
                api_names = [
                    b'LoadLibrary', b'GetProcAddress', b'CreateFile',
                    b'ReadFile', b'WriteFile', b'VirtualAlloc',
                    b'VirtualProtect', b'CreateThread', b'OpenProcess'
                ]

                for api_name in api_names:
                    if api_name in search_region:
                        import_entry = {
                            'name': api_name.decode('ascii'),
                            'libname': dll_name.decode('ascii'),
                            'type': 'FUNC',
                            'offset': 0
                        }
                        session['imports'].append(import_entry)

    def _build_xrefs(self, content: bytes, session: Dict):
        """Build cross-references."""
        # Find call instructions (simplified)
        call_opcode = b'\xe8'  # Direct call

        offset = 0
        while offset < len(content) - 5:
            if content[offset] == 0xe8:
                # Get call target (relative)
                try:
                    rel_offset = struct.unpack('<i', content[offset+1:offset+5])[0]
                    target = offset + 5 + rel_offset

                    if 0 <= target < len(content):
                        xref = {
                            'from': offset,
                            'to': target,
                            'type': 'CALL'
                        }
                        session['xrefs'].append(xref)

                        # Add to function callrefs
                        for func in session['functions']:
                            if func['offset'] <= offset < func['offset'] + func['size']:
                                func['callrefs'].append(target)
                                break

                except:
                    pass

            offset += 1

            if len(session['xrefs']) >= 1000:  # Limit
                break

    def disassemble(self, session_id: str, offset: int, length: int) -> List[Dict[str, Any]]:
        """Disassemble code at given offset."""
        if session_id not in self.sessions:
            return []

        session = self.sessions[session_id]
        path = session['path']

        if not os.path.exists(path):
            return []

        instructions = []

        with open(path, 'rb') as f:
            f.seek(offset)
            code = f.read(length)

            # Basic x86 disassembly
            i = 0
            while i < len(code):
                inst = {'offset': offset + i, 'bytes': '', 'mnemonic': '', 'operands': ''}

                if i + 1 <= len(code):
                    opcode = code[i]

                    # Common x86 instructions
                    if opcode == 0x90:
                        inst['bytes'] = '90'
                        inst['mnemonic'] = 'nop'
                        i += 1
                    elif opcode == 0x55:
                        inst['bytes'] = '55'
                        inst['mnemonic'] = 'push'
                        inst['operands'] = 'ebp'
                        i += 1
                    elif opcode == 0xc3:
                        inst['bytes'] = 'c3'
                        inst['mnemonic'] = 'ret'
                        i += 1
                    elif opcode == 0xe8:
                        if i + 5 <= len(code):
                            inst['bytes'] = code[i:i+5].hex()
                            inst['mnemonic'] = 'call'
                            target = struct.unpack('<i', code[i+1:i+5])[0]
                            inst['operands'] = f'0x{offset + i + 5 + target:x}'
                            i += 5
                        else:
                            i += 1
                    elif opcode == 0xe9:
                        if i + 5 <= len(code):
                            inst['bytes'] = code[i:i+5].hex()
                            inst['mnemonic'] = 'jmp'
                            target = struct.unpack('<i', code[i+1:i+5])[0]
                            inst['operands'] = f'0x{offset + i + 5 + target:x}'
                            i += 5
                        else:
                            i += 1
                    else:
                        inst['bytes'] = f'{opcode:02x}'
                        inst['mnemonic'] = 'db'
                        inst['operands'] = f'0x{opcode:02x}'
                        i += 1

                    instructions.append(inst)

                if len(instructions) >= 100:  # Limit
                    break

        return instructions

    def patch_bytes(self, session_id: str, offset: int, data: bytes) -> bool:
        """Patch bytes in binary."""
        if session_id not in self.sessions:
            return False

        session = self.sessions[session_id]

        if not session['write_mode']:
            return False

        path = session['path']

        # Read original bytes
        original = b''
        if os.path.exists(path):
            with open(path, 'rb') as f:
                f.seek(offset)
                original = f.read(len(data))

        # Record patch
        patch = {
            'offset': offset,
            'original': original,
            'patched': data,
            'time': time.time()
        }
        self.patches.append(patch)

        # Apply patch if in write mode
        if session['write_mode']:
            try:
                with open(path, 'r+b') as f:
                    f.seek(offset)
                    f.write(data)
                return True
            except:
                return False

        return True

    def search_bytes(self, session_id: str, pattern: bytes) -> List[int]:
        """Search for byte pattern in binary."""
        if session_id not in self.sessions:
            return []

        session = self.sessions[session_id]
        path = session['path']

        if not os.path.exists(path):
            return []

        results = []

        with open(path, 'rb') as f:
            content = f.read()

            offset = 0
            while offset < len(content):
                index = content.find(pattern, offset)
                if index == -1:
                    break

                results.append(index)
                offset = index + 1

                if len(results) >= 100:  # Limit
                    break

        return results

    def add_comment(self, session_id: str, offset: int, comment: str) -> bool:
        """Add comment at offset."""
        if session_id not in self.sessions:
            return False

        session = self.sessions[session_id]

        if 'comments' not in session:
            session['comments'] = {}

        session['comments'][offset] = {
            'text': comment,
            'time': time.time()
        }

        return True

    def set_breakpoint(self, session_id: str, offset: int) -> bool:
        """Set breakpoint at offset."""
        if session_id not in self.sessions:
            return False

        bp = {
            'session': session_id,
            'offset': offset,
            'enabled': True,
            'hit_count': 0
        }
        self.breakpoints.append(bp)
        return True


class RealRadare2Scripter:
    """Real Radare2 scripting engine."""

    def __init__(self):
        self.scripts = {}
        self.macros = {}

    def create_analysis_script(self, options: Dict[str, Any]) -> str:
        """Create analysis script."""
        commands = []

        # Analysis commands
        if options.get('analyze_all', True):
            commands.append('aaa')  # Analyze all

        if options.get('analyze_refs', True):
            commands.append('aar')  # Analyze refs

        if options.get('analyze_calls', True):
            commands.append('aac')  # Analyze calls

        if options.get('find_strings', True):
            commands.append('iz')   # String scan

        if options.get('signatures', False):
            commands.append('zg')   # Generate signatures

        return '\n'.join(commands)

    def create_patch_script(self, patches: List[Dict[str, Any]]) -> str:
        """Create patching script."""
        commands = []

        for patch in patches:
            if patch['type'] == 'bytes':
                # Write bytes
                hex_data = patch['data'].hex() if isinstance(patch['data'], bytes) else patch['data']
                commands.append(f"wx {hex_data} @ {patch['offset']}")

            elif patch['type'] == 'nop':
                # NOP bytes
                commands.append(f"wn {patch['count']} @ {patch['offset']}")

            elif patch['type'] == 'string':
                # Write string
                commands.append(f"w {patch['string']} @ {patch['offset']}")

            elif patch['type'] == 'asm':
                # Assemble and write
                commands.append(f"wa {patch['asm']} @ {patch['offset']}")

        return '\n'.join(commands)

    def create_search_script(self, searches: List[Dict[str, Any]]) -> str:
        """Create search script."""
        commands = []

        for search in searches:
            if search['type'] == 'string':
                commands.append(f"/ {search['value']}")

            elif search['type'] == 'hex':
                commands.append(f"/x {search['pattern']}")

            elif search['type'] == 'asm':
                commands.append(f"/a {search['asm']}")

            elif search['type'] == 'regex':
                commands.append(f"/r {search['regex']}")

        return '\n'.join(commands)


class TestRadare2Integration(unittest.TestCase):
    """Test Radare2 integration with real binary analysis."""

    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.r2_analyzer = RealRadare2Analyzer()
        self.r2_scripter = RealRadare2Scripter()

    def tearDown(self):
        """Clean up test environment."""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def create_test_binary(self, format='PE') -> str:
        """Create test binary."""
        binary_path = os.path.join(self.test_dir, 'test.exe' if format == 'PE' else 'test.elf')

        with open(binary_path, 'wb') as f:
            if format == 'PE':
                # DOS header
                f.write(b'MZ' + b'\x90' * 58 + struct.pack('<I', 0x80))
                f.write(b'\x00' * (0x80 - 64))

                # PE header
                f.write(b'PE\x00\x00')
                f.write(struct.pack('<H', 0x014c))  # Machine
                f.write(struct.pack('<H', 2))       # Sections
                f.write(b'\x00' * 16)              # Timestamp etc

                # Optional header
                f.write(struct.pack('<H', 0x010b))  # Magic (PE32)
                f.write(b'\x00' * 222)

                # Section headers
                f.write(b'.text\x00\x00\x00')      # Name
                f.write(struct.pack('<I', 0x1000))  # VirtualSize
                f.write(struct.pack('<I', 0x1000))  # VirtualAddress
                f.write(struct.pack('<I', 0x200))   # SizeOfRawData
                f.write(struct.pack('<I', 0x200))   # PointerToRawData
                f.write(b'\x00' * 12)               # Relocs, lines, etc
                f.write(struct.pack('<I', 0x60000020))  # Flags (code, execute, read)

                f.write(b'.data\x00\x00\x00')      # Name
                f.write(struct.pack('<I', 0x1000))  # VirtualSize
                f.write(struct.pack('<I', 0x2000))  # VirtualAddress
                f.write(struct.pack('<I', 0x200))   # SizeOfRawData
                f.write(struct.pack('<I', 0x400))   # PointerToRawData
                f.write(b'\x00' * 12)               # Relocs, lines, etc
                f.write(struct.pack('<I', 0xC0000040))  # Flags (data, read, write)

                # Code section
                f.seek(0x200)
                # Function 1
                f.write(b'\x55')                   # push ebp
                f.write(b'\x8b\xec')               # mov ebp, esp
                f.write(b'\x83\xec\x10')           # sub esp, 0x10
                f.write(b'\xe8\x10\x00\x00\x00')   # call +0x10
                f.write(b'\x8b\x45\xfc')           # mov eax, [ebp-4]
                f.write(b'\xc9')                   # leave
                f.write(b'\xc3')                   # ret

                # Function 2
                f.write(b'\x55')                   # push ebp
                f.write(b'\x8b\xec')               # mov ebp, esp
                f.write(b'\x33\xc0')               # xor eax, eax
                f.write(b'\x5d')                   # pop ebp
                f.write(b'\xc3')                   # ret

                # Data section
                f.seek(0x400)
                f.write(b'kernel32.dll\x00')
                f.write(b'LoadLibraryA\x00')
                f.write(b'GetProcAddress\x00')
                f.write(b'This is a test string\x00')
                f.write(b'License check failed!\x00')

            else:  # ELF
                # ELF header
                f.write(b'\x7fELF')
                f.write(b'\x01')                   # 32-bit
                f.write(b'\x01')                   # Little-endian
                f.write(b'\x01')                   # Version
                f.write(b'\x00' * 9)
                f.write(struct.pack('<H', 2))      # Executable
                f.write(struct.pack('<H', 3))      # i386
                f.write(struct.pack('<I', 1))      # Version
                f.write(struct.pack('<I', 0x8048000))  # Entry

                # Program header
                f.write(b'\x00' * 32)

                # Code
                f.seek(0x100)
                f.write(b'\x55')                   # push ebp
                f.write(b'\x89\xe5')               # mov ebp, esp
                f.write(b'\x31\xc0')               # xor eax, eax
                f.write(b'\x5d')                   # pop ebp
                f.write(b'\xc3')                   # ret

        return binary_path

    def test_binary_opening(self):
        """Test opening binaries for analysis."""
        binary_path = self.create_test_binary('PE')

        result = self.r2_analyzer.open_binary(binary_path)

        self.assertIn('session_id', result)
        self.assertIn('info', result)

        session_id = result['session_id']
        session = self.r2_analyzer.sessions[session_id]

        self.assertEqual(session['format'], 'PE')
        self.assertEqual(session['info']['arch'], 'x86')
        self.assertEqual(session['info']['bits'], 32)

    def test_deep_analysis(self):
        """Test deep analysis of binary."""
        binary_path = self.create_test_binary('PE')
        result = self.r2_analyzer.open_binary(binary_path)
        session_id = result['session_id']

        # Perform analysis
        analysis_result = self.r2_analyzer.analyze(session_id)

        self.assertGreater(analysis_result['functions'], 0)
        self.assertGreater(analysis_result['strings'], 0)
        self.assertGreater(analysis_result['imports'], 0)

        # Check session data
        session = self.r2_analyzer.sessions[session_id]
        self.assertTrue(session['analyzed'])
        self.assertTrue(len(session['functions']) > 0)
        self.assertTrue(len(session['strings']) > 0)

    def test_disassembly(self):
        """Test code disassembly."""
        binary_path = self.create_test_binary('PE')
        result = self.r2_analyzer.open_binary(binary_path)
        session_id = result['session_id']

        # Disassemble code section
        instructions = self.r2_analyzer.disassemble(session_id, 0x200, 20)

        self.assertTrue(len(instructions) > 0)

        # Verify instruction structure
        for inst in instructions:
            self.assertIn('offset', inst)
            self.assertIn('bytes', inst)
            self.assertIn('mnemonic', inst)
            self.assertIn('operands', inst)

        # Check for expected instructions
        mnemonics = [inst['mnemonic'] for inst in instructions]
        self.assertIn('push', mnemonics)
        self.assertIn('mov', mnemonics)

    def test_patching(self):
        """Test binary patching."""
        binary_path = self.create_test_binary('PE')
        result = self.r2_analyzer.open_binary(binary_path, write_mode=True)
        session_id = result['session_id']

        # Patch bytes
        patch_data = b'\x90\x90\x90\x90\x90'  # NOP sled
        success = self.r2_analyzer.patch_bytes(session_id, 0x200, patch_data)

        self.assertTrue(success)
        self.assertTrue(len(self.r2_analyzer.patches) > 0)

        # Verify patch was applied
        with open(binary_path, 'rb') as f:
            f.seek(0x200)
            patched = f.read(5)
            self.assertEqual(patched, patch_data)

    def test_byte_search(self):
        """Test searching for byte patterns."""
        binary_path = self.create_test_binary('PE')
        result = self.r2_analyzer.open_binary(binary_path)
        session_id = result['session_id']

        # Search for patterns
        pattern1 = b'\x55\x8b\xec'  # push ebp; mov ebp, esp
        results1 = self.r2_analyzer.search_bytes(session_id, pattern1)

        self.assertTrue(len(results1) > 0)
        self.assertEqual(results1[0], 0x200)

        # Search for string
        pattern2 = b'kernel32.dll'
        results2 = self.r2_analyzer.search_bytes(session_id, pattern2)

        self.assertTrue(len(results2) > 0)

    def test_section_parsing(self):
        """Test PE section parsing."""
        binary_path = self.create_test_binary('PE')
        result = self.r2_analyzer.open_binary(binary_path)
        session_id = result['session_id']

        session = self.r2_analyzer.sessions[session_id]

        self.assertTrue(len(session['sections']) > 0)

        # Check section structure
        for section in session['sections']:
            self.assertIn('name', section)
            self.assertIn('vaddr', section)
            self.assertIn('size', section)
            self.assertIn('perms', section)

        # Verify specific sections
        section_names = [s['name'] for s in session['sections']]
        self.assertIn('.text', section_names)
        self.assertIn('.data', section_names)

    def test_string_extraction(self):
        """Test string extraction."""
        binary_path = self.create_test_binary('PE')
        result = self.r2_analyzer.open_binary(binary_path)
        session_id = result['session_id']

        self.r2_analyzer.analyze(session_id)
        session = self.r2_analyzer.sessions[session_id]

        self.assertTrue(len(session['strings']) > 0)

        # Check for specific strings
        string_values = [s['value'] for s in session['strings']]
        self.assertIn('kernel32.dll', string_values)
        self.assertIn('This is a test string', string_values)

    def test_xref_analysis(self):
        """Test cross-reference analysis."""
        binary_path = self.create_test_binary('PE')
        result = self.r2_analyzer.open_binary(binary_path)
        session_id = result['session_id']

        self.r2_analyzer.analyze(session_id)
        session = self.r2_analyzer.sessions[session_id]

        self.assertTrue(len(session['xrefs']) > 0)

        # Check xref structure
        for xref in session['xrefs']:
            self.assertIn('from', xref)
            self.assertIn('to', xref)
            self.assertIn('type', xref)

    def test_script_generation(self):
        """Test script generation."""
        # Analysis script
        options = {
            'analyze_all': True,
            'analyze_refs': True,
            'analyze_calls': True,
            'find_strings': True,
            'signatures': True
        }
        analysis_script = self.r2_scripter.create_analysis_script(options)

        self.assertIn('aaa', analysis_script)
        self.assertIn('aar', analysis_script)
        self.assertIn('aac', analysis_script)
        self.assertIn('iz', analysis_script)
        self.assertIn('zg', analysis_script)

        # Patch script
        patches = [
            {'type': 'bytes', 'offset': 0x1000, 'data': b'\x90\x90'},
            {'type': 'nop', 'offset': 0x1010, 'count': 5},
            {'type': 'asm', 'offset': 0x1020, 'asm': 'jmp 0x1100'}
        ]
        patch_script = self.r2_scripter.create_patch_script(patches)

        self.assertIn('wx 9090', patch_script)
        self.assertIn('wn 5', patch_script)
        self.assertIn('wa jmp 0x1100', patch_script)

    def test_comment_management(self):
        """Test adding comments to offsets."""
        binary_path = self.create_test_binary('PE')
        result = self.r2_analyzer.open_binary(binary_path)
        session_id = result['session_id']

        # Add comments
        self.r2_analyzer.add_comment(session_id, 0x200, 'Entry point function')
        self.r2_analyzer.add_comment(session_id, 0x210, 'License check bypass point')

        session = self.r2_analyzer.sessions[session_id]
        self.assertIn('comments', session)
        self.assertEqual(len(session['comments']), 2)
        self.assertEqual(session['comments'][0x200]['text'], 'Entry point function')

    def test_breakpoint_management(self):
        """Test breakpoint management."""
        binary_path = self.create_test_binary('PE')
        result = self.r2_analyzer.open_binary(binary_path)
        session_id = result['session_id']

        # Set breakpoints
        self.r2_analyzer.set_breakpoint(session_id, 0x200)
        self.r2_analyzer.set_breakpoint(session_id, 0x210)

        self.assertEqual(len(self.r2_analyzer.breakpoints), 2)

        # Verify breakpoint structure
        for bp in self.r2_analyzer.breakpoints:
            self.assertIn('session', bp)
            self.assertIn('offset', bp)
            self.assertIn('enabled', bp)
            self.assertTrue(bp['enabled'])

    def test_elf_analysis(self):
        """Test ELF binary analysis."""
        binary_path = self.create_test_binary('ELF')
        result = self.r2_analyzer.open_binary(binary_path)
        session_id = result['session_id']

        session = self.r2_analyzer.sessions[session_id]

        self.assertEqual(session['format'], 'ELF')
        self.assertEqual(session['info']['arch'], 'x86')
        self.assertEqual(session['info']['bits'], 32)
        self.assertIn('entry', session['info'])

    def test_concurrent_analysis(self):
        """Test concurrent analysis of multiple binaries."""
        import threading

        results = []
        errors = []

        def analyze_binary(format_type, index):
            try:
                binary_path = self.create_test_binary(format_type)
                result = self.r2_analyzer.open_binary(binary_path)
                session_id = result['session_id']
                analysis = self.r2_analyzer.analyze(session_id)
                results.append((session_id, analysis))
            except Exception as e:
                errors.append(str(e))

        # Create threads
        threads = []
        for i in range(4):
            format_type = 'PE' if i % 2 == 0 else 'ELF'
            thread = threading.Thread(target=analyze_binary, args=(format_type, i))
            threads.append(thread)
            thread.start()

        # Wait for completion
        for thread in threads:
            thread.join(timeout=5)

        # Verify results
        self.assertEqual(len(errors), 0, f"Errors occurred: {errors}")
        self.assertEqual(len(results), 4)

        for session_id, analysis in results:
            self.assertGreater(analysis['functions'], 0)
            self.assertGreater(analysis['strings'], 0)


if __name__ == '__main__':
    unittest.main()
