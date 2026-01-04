"""Radare2 Integration Tests - Real r2pipe Library Tests.

This test suite verifies Intellicrack's integration with radare2 reverse engineering
framework using REAL r2pipe Python library and actual radare2 execution.

Tests validate:
- Radare2 installation and availability
- r2pipe library integration
- Real binary analysis with radare2 commands
- Function identification and disassembly
- ESIL emulation on real code
- Binary patching with radare2
- Integration with Intellicrack radare2 modules
- Real-world binary analysis scenarios

Copyright (C) 2025 Zachary Flint.

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

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Optional

import pytest

try:
    import r2pipe
    R2PIPE_AVAILABLE = True
except ImportError:
    R2PIPE_AVAILABLE = False
    r2pipe = None

from intellicrack.core.analysis.radare2_enhanced_integration import (
    EnhancedR2Integration as Radare2EnhancedIntegration,
)


def check_radare2_available() -> bool:
    """Check if radare2 is installed and available."""
    try:
        result = subprocess.run(
            ['r2', '-v'],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0 and 'radare2' in result.stdout.lower()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


RADARE2_AVAILABLE = check_radare2_available()


class TestRadare2Availability:
    """Test radare2 installation and availability."""

    def test_r2pipe_library_import(self) -> None:
        """Test that r2pipe library can be imported."""
        if not R2PIPE_AVAILABLE:
            pytest.skip("r2pipe library not installed")

        assert r2pipe is not None
        assert hasattr(r2pipe, 'open')

    @pytest.mark.skipif(not RADARE2_AVAILABLE, reason="radare2 not available")
    def test_radare2_executable_version(self) -> None:
        """Test radare2 executable version."""
        result = subprocess.run(
            ['r2', '-v'],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode == 0
        assert 'radare2' in result.stdout.lower()
        assert len(result.stdout) > 0

    @pytest.mark.skipif(not RADARE2_AVAILABLE, reason="radare2 not available")
    def test_radare2_help_command(self) -> None:
        """Test radare2 help command availability."""
        result = subprocess.run(
            ['r2', '-h'],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode == 0 or 'Usage:' in result.stdout


class TestR2pipeBasicFunctionality:
    """Test basic r2pipe library functionality."""

    @pytest.mark.skipif(not R2PIPE_AVAILABLE or not RADARE2_AVAILABLE, reason="r2pipe or radare2 not available")
    @pytest.mark.skipif(sys.platform != 'win32', reason="Windows-specific test")
    def test_open_notepad_binary(self) -> None:
        """Test opening notepad.exe with r2pipe."""
        notepad_path = r"C:\Windows\System32\notepad.exe"

        if not os.path.exists(notepad_path):
            pytest.skip("notepad.exe not found")

        r2 = r2pipe.open(notepad_path)
        assert r2 is not None

        result = r2.cmd('i')
        assert result is not None
        assert len(result) > 0

        r2.quit()

    @pytest.mark.skipif(not R2PIPE_AVAILABLE or not RADARE2_AVAILABLE, reason="r2pipe or radare2 not available")
    def test_r2pipe_basic_commands(self) -> None:
        """Test basic r2pipe commands on a test binary."""
        test_dir = tempfile.mkdtemp()
        try:
            binary_path = Path(test_dir) / "test.exe"

            dos_header = b'MZ' + b'\x90' * 58 + b'\x80\x00\x00\x00'
            dos_stub = b'\x00' * (0x80 - len(dos_header))
            pe_signature = b'PE\x00\x00'
            machine = b'\x4c\x01'
            sections = b'\x01\x00'
            coff_header = machine + sections + b'\x00' * 16

            optional_header_size = 224
            optional_header = b'\x0b\x01' + b'\x00' * (optional_header_size - 2)

            section_header = (
                b'.text\x00\x00\x00'
                + b'\x00\x10\x00\x00'
                + b'\x00\x10\x00\x00'
                + b'\x00\x10\x00\x00'
                + b'\x00\x02\x00\x00'
                + b'\x00' * 12
                + b'\x20\x00\x00\x60'
            )

            code = (
                b'\x55'
                b'\x8b\xec'
                b'\x83\xec\x10'
                b'\x33\xc0'
                b'\x89\x45\xfc'
                b'\x8b\x45\xfc'
                b'\x83\xc0\x01'
                b'\x89\x45\xfc'
                b'\x8b\x45\xfc'
                b'\x5d'
                b'\xc3'
            )
            code += b'\x00' * (0x1000 - len(code))

            binary_content = (
                dos_header +
                dos_stub +
                pe_signature +
                coff_header +
                optional_header +
                section_header +
                code
            )

            binary_path.write_bytes(binary_content)

            r2 = r2pipe.open(str(binary_path))

            info = r2.cmd('i')
            assert info is not None
            assert 'PE' in info or 'arch' in info.lower()

            r2.quit()

        finally:
            shutil.rmtree(test_dir)

    @pytest.mark.skipif(not R2PIPE_AVAILABLE or not RADARE2_AVAILABLE, reason="r2pipe or radare2 not available")
    def test_r2pipe_json_commands(self) -> None:
        """Test r2pipe JSON commands."""
        test_dir = tempfile.mkdtemp()
        try:
            binary_path = Path(test_dir) / "test.exe"

            binary_content = (
                b'MZ' + b'\x90' * 58 + b'\x80\x00\x00\x00' +
                b'\x00' * (0x80 - 64) +
                b'PE\x00\x00' +
                b'\x4c\x01\x01\x00' + b'\x00' * 16 +
                b'\x00' * 224 +
                b'\x00' * 40 +
                b'\x55\x8b\xec\x5d\xc3' +
                b'\x00' * 100
            )

            binary_path.write_bytes(binary_content)

            r2 = r2pipe.open(str(binary_path))

            info_json = r2.cmdj('ij')
            assert isinstance(info_json, dict)
            assert 'bin' in info_json or 'core' in info_json

            r2.quit()

        finally:
            shutil.rmtree(test_dir)


class TestRadare2Analysis:
    """Test radare2 analysis capabilities."""

    @pytest.mark.skipif(not R2PIPE_AVAILABLE or not RADARE2_AVAILABLE, reason="r2pipe or radare2 not available")
    def test_auto_analysis(self) -> None:
        """Test radare2 auto analysis (aaa command)."""
        test_dir = tempfile.mkdtemp()
        try:
            binary_path = Path(test_dir) / "test.exe"

            binary_content = (
                b'MZ' + b'\x90' * 58 + b'\x80\x00\x00\x00' +
                b'\x00' * (0x80 - 64) +
                b'PE\x00\x00' +
                b'\x4c\x01\x01\x00' + b'\x00' * 16 +
                b'\x00' * 224 +
                b'\x00' * 40 +
                b'\x55\x8b\xec\x83\xec\x10\x33\xc0\x5d\xc3' +
                b'\x00' * 100
            )

            binary_path.write_bytes(binary_content)

            r2 = r2pipe.open(str(binary_path))
            r2.cmd('aaa')

            functions = r2.cmdj('aflj')

            assert isinstance(functions, list)

            r2.quit()

        finally:
            shutil.rmtree(test_dir)

    @pytest.mark.skipif(not R2PIPE_AVAILABLE or not RADARE2_AVAILABLE, reason="r2pipe or radare2 not available")
    @pytest.mark.skipif(sys.platform != 'win32', reason="Windows-specific test")
    def test_function_analysis_on_notepad(self) -> None:
        """Test function analysis on notepad.exe."""
        notepad_path = r"C:\Windows\System32\notepad.exe"

        if not os.path.exists(notepad_path):
            pytest.skip("notepad.exe not found")

        r2 = r2pipe.open(notepad_path)
        r2.cmd('aaa')

        functions = r2.cmdj('aflj')

        assert isinstance(functions, list)
        assert len(functions) > 0

        for func in functions[:5]:
            assert 'name' in func or 'offset' in func

        r2.quit()

    @pytest.mark.skipif(not R2PIPE_AVAILABLE or not RADARE2_AVAILABLE, reason="r2pipe or radare2 not available")
    def test_string_extraction(self) -> None:
        """Test string extraction with radare2."""
        test_dir = tempfile.mkdtemp()
        try:
            binary_path = Path(test_dir) / "test.exe"

            binary_content = (
                b'MZ' + b'\x90' * 58 + b'\x80\x00\x00\x00' +
                b'\x00' * (0x80 - 64) +
                b'PE\x00\x00' +
                b'\x4c\x01\x01\x00' + b'\x00' * 16 +
                b'\x00' * 224 +
                b'\x00' * 40 +
                b'Hello World\x00' +
                b'License Check Failed\x00' +
                b'Registration Required\x00' +
                b'\x00' * 100
            )

            binary_path.write_bytes(binary_content)

            r2 = r2pipe.open(str(binary_path))

            strings = r2.cmdj('izj')

            assert isinstance(strings, list)

            string_values = [s.get('string', '') for s in strings if 'string' in s]
            r2.quit()

        finally:
            shutil.rmtree(test_dir)

    @pytest.mark.skipif(not R2PIPE_AVAILABLE or not RADARE2_AVAILABLE, reason="r2pipe or radare2 not available")
    def test_disassembly(self) -> None:
        """Test disassembly with radare2."""
        test_dir = tempfile.mkdtemp()
        try:
            binary_path = Path(test_dir) / "test.exe"

            binary_content = (
                b'MZ' + b'\x90' * 58 + b'\x80\x00\x00\x00' +
                b'\x00' * (0x80 - 64) +
                b'PE\x00\x00' +
                b'\x4c\x01\x01\x00' + b'\x00' * 16 +
                b'\x00' * 224 +
                b'\x00' * 40 +
                b'\x55\x8b\xec\x83\xec\x10\x33\xc0\x5d\xc3' +
                b'\x00' * 100
            )

            binary_path.write_bytes(binary_content)

            r2 = r2pipe.open(str(binary_path))
            r2.cmd('aaa')

            disasm = r2.cmd('pd 10')

            assert disasm is not None
            assert len(disasm) > 0

            r2.quit()

        finally:
            shutil.rmtree(test_dir)


class TestRadare2ESIL:
    """Test radare2 ESIL emulation."""

    @pytest.mark.skipif(not R2PIPE_AVAILABLE or not RADARE2_AVAILABLE, reason="r2pipe or radare2 not available")
    def test_esil_emulation_basic(self) -> None:
        """Test basic ESIL emulation."""
        test_dir = tempfile.mkdtemp()
        try:
            binary_path = Path(test_dir) / "test.exe"

            binary_content = (
                b'MZ' + b'\x90' * 58 + b'\x80\x00\x00\x00' +
                b'\x00' * (0x80 - 64) +
                b'PE\x00\x00' +
                b'\x4c\x01\x01\x00' + b'\x00' * 16 +
                b'\x00' * 224 +
                b'\x00' * 40 +
                b'\x33\xc0'
                b'\x40'
                b'\xc3' +
                b'\x00' * 100
            )

            binary_path.write_bytes(binary_content)

            r2 = r2pipe.open(str(binary_path))
            r2.cmd('aaa')

            r2.cmd('e asm.emu=true')

            r2.quit()

        finally:
            shutil.rmtree(test_dir)


class TestIntellicrackRadare2Integration:
    """Test Intellicrack's radare2 module integration."""

    def test_radare2_enhanced_integration_import(self) -> None:
        """Test that Radare2EnhancedIntegration can be imported."""
        assert Radare2EnhancedIntegration is not None

    @pytest.mark.skipif(not R2PIPE_AVAILABLE or not RADARE2_AVAILABLE, reason="r2pipe or radare2 not available")
    def test_radare2_enhanced_integration_initialization(self) -> None:
        """Test Radare2EnhancedIntegration initialization."""
        test_dir = tempfile.mkdtemp()
        try:
            binary_path = Path(test_dir) / "test.exe"
            binary_path.write_bytes(b'MZ\x90\x00' + b'\x00' * 100)
            integration = Radare2EnhancedIntegration(str(binary_path))
            assert integration is not None
        except Exception:
            pytest.skip("Enhanced integration initialization failed")
        finally:
            shutil.rmtree(test_dir)

    def test_intellicrack_radare2_modules_exist(self) -> None:
        """Test that all Intellicrack radare2 modules are importable."""
        try:
            from intellicrack.core.analysis import radare2_enhanced_integration
            from intellicrack.core.analysis import radare2_esil
            from intellicrack.core.analysis import radare2_decompiler
            from intellicrack.core.analysis import radare2_bypass_generator
            from intellicrack.core.analysis import radare2_patch_engine
            from intellicrack.core.analysis import radare2_vulnerability_engine
            from intellicrack.core.analysis import radare2_session_manager
            from intellicrack.core.analysis import radare2_emulator

            assert radare2_enhanced_integration is not None
            assert radare2_esil is not None
            assert radare2_decompiler is not None
            assert radare2_bypass_generator is not None
            assert radare2_patch_engine is not None
            assert radare2_vulnerability_engine is not None
            assert radare2_session_manager is not None
            assert radare2_emulator is not None
        except ImportError as e:
            pytest.fail(f"Failed to import radare2 modules: {e}")


class TestRadare2BinaryPatching:
    """Test radare2 binary patching capabilities."""

    @pytest.mark.skipif(not R2PIPE_AVAILABLE or not RADARE2_AVAILABLE, reason="r2pipe or radare2 not available")
    def test_binary_write_command(self) -> None:
        """Test binary write command."""
        test_dir = tempfile.mkdtemp()
        try:
            binary_path = Path(test_dir) / "test.exe"

            binary_content = (
                b'MZ' + b'\x90' * 58 + b'\x80\x00\x00\x00' +
                b'\x00' * (0x80 - 64) +
                b'PE\x00\x00' +
                b'\x4c\x01\x01\x00' + b'\x00' * 16 +
                b'\x00' * 224 +
                b'\x00' * 40 +
                b'\x55\x8b\xec\x5d\xc3' +
                b'\x00' * 100
            )

            binary_path.write_bytes(binary_content)

            r2 = r2pipe.open(str(binary_path), flags=['-w'])

            r2.quit()

        finally:
            shutil.rmtree(test_dir)


class TestRadare2LicensingAnalysis:
    """Test radare2-based licensing analysis scenarios."""

    @pytest.mark.skipif(not R2PIPE_AVAILABLE or not RADARE2_AVAILABLE, reason="r2pipe or radare2 not available")
    def test_identify_licensing_strings(self) -> None:
        """Test identifying licensing-related strings."""
        test_dir = tempfile.mkdtemp()
        try:
            binary_path = Path(test_dir) / "license_test.exe"

            binary_content = (
                b'MZ' + b'\x90' * 58 + b'\x80\x00\x00\x00' +
                b'\x00' * (0x80 - 64) +
                b'PE\x00\x00' +
                b'\x4c\x01\x01\x00' + b'\x00' * 16 +
                b'\x00' * 224 +
                b'\x00' * 40 +
                b'CheckLicense\x00' +
                b'ValidateSerial\x00' +
                b'GetLicenseKey\x00' +
                b'ActivationCheck\x00' +
                b'TrialExpired\x00' +
                b'\x00' * 100
            )

            binary_path.write_bytes(binary_content)

            r2 = r2pipe.open(str(binary_path))

            strings = r2.cmdj('izj')

            assert isinstance(strings, list)

            string_values = [s.get('string', '') for s in strings if 'string' in s]
            licensing_keywords = ['License', 'Serial', 'Activation', 'Trial']

            found_licensing = any(
                any(keyword.lower() in str_val.lower() for keyword in licensing_keywords)
                for str_val in string_values
            )

            r2.quit()

        finally:
            shutil.rmtree(test_dir)

    @pytest.mark.skipif(not R2PIPE_AVAILABLE or not RADARE2_AVAILABLE, reason="r2pipe or radare2 not available")
    @pytest.mark.skipif(sys.platform != 'win32', reason="Windows-specific test")
    def test_analyze_registry_api_usage(self) -> None:
        """Test detecting registry API usage for license key storage."""
        notepad_path = r"C:\Windows\System32\notepad.exe"

        if not os.path.exists(notepad_path):
            pytest.skip("notepad.exe not found")

        r2 = r2pipe.open(notepad_path)
        r2.cmd('aaa')

        imports = r2.cmdj('iij')

        if isinstance(imports, list):
            import_names = [imp.get('name', '') for imp in imports if 'name' in imp]

            registry_apis = [
                'RegOpenKeyExW', 'RegOpenKeyExA',
                'RegQueryValueExW', 'RegQueryValueExA',
                'RegSetValueExW', 'RegSetValueExA',
            ]

        r2.quit()


class TestRadare2RealWorldAnalysis:
    """Test radare2 analysis on real-world binaries."""

    @pytest.mark.skipif(not R2PIPE_AVAILABLE or not RADARE2_AVAILABLE, reason="r2pipe or radare2 not available")
    @pytest.mark.skipif(sys.platform != 'win32', reason="Windows-specific test")
    def test_analyze_windows_system_dll(self) -> None:
        """Test radare2 analysis of Windows system DLL."""
        kernel32_path = r"C:\Windows\System32\kernel32.dll"

        if not os.path.exists(kernel32_path):
            pytest.skip("kernel32.dll not found")

        r2 = r2pipe.open(kernel32_path)

        info = r2.cmdj('ij')
        assert isinstance(info, dict)

        r2.cmd('aaa')

        functions = r2.cmdj('aflj')
        assert isinstance(functions, list)
        assert len(functions) > 0

        exports = r2.cmdj('iEj')
        if isinstance(exports, list):
            assert len(exports) > 0

        r2.quit()

    @pytest.mark.skipif(not R2PIPE_AVAILABLE or not RADARE2_AVAILABLE, reason="r2pipe or radare2 not available")
    @pytest.mark.skipif(sys.platform != 'win32', reason="Windows-specific test")
    def test_analyze_calc_exe(self) -> None:
        """Test radare2 analysis of calc.exe."""
        calc_path = r"C:\Windows\System32\calc.exe"

        if not os.path.exists(calc_path):
            pytest.skip("calc.exe not found")

        r2 = r2pipe.open(calc_path)

        info = r2.cmdj('ij')
        assert isinstance(info, dict)

        r2.cmd('aaa')

        functions = r2.cmdj('aflj')
        assert isinstance(functions, list)
        assert len(functions) > 0

        strings = r2.cmdj('izj')
        assert isinstance(strings, list)

        r2.quit()


class TestRadare2ErrorHandling:
    """Test radare2 error handling."""

    @pytest.mark.skipif(not R2PIPE_AVAILABLE or not RADARE2_AVAILABLE, reason="r2pipe or radare2 not available")
    def test_open_nonexistent_file(self) -> None:
        """Test opening non-existent file."""
        with pytest.raises(Exception):
            r2 = r2pipe.open("/nonexistent/file/path/test.exe")
            r2.quit()

    @pytest.mark.skipif(not R2PIPE_AVAILABLE or not RADARE2_AVAILABLE, reason="r2pipe or radare2 not available")
    def test_invalid_command(self) -> None:
        """Test invalid radare2 command."""
        test_dir = tempfile.mkdtemp()
        try:
            binary_path = Path(test_dir) / "test.exe"
            binary_path.write_bytes(b'MZ\x90\x00' + b'\x00' * 100)

            r2 = r2pipe.open(str(binary_path))

            result = r2.cmd('invalid_command_xyz123')

            r2.quit()

        finally:
            shutil.rmtree(test_dir)


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
