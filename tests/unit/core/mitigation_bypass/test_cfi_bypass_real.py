"""Copyright (C) 2025 Zachary Flint.

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import pytest
import os
import subprocess
import tempfile
from pathlib import Path
import struct

try:
    from intellicrack.core.mitigation_bypass.cfi_bypass import CFIBypass
    MODULE_AVAILABLE = True
except ImportError:
    CFIBypass = None
    MODULE_AVAILABLE = False

pytestmark = pytest.mark.skipif(not MODULE_AVAILABLE, reason="Module not available")


class TestCFIBypassProduction:
    """Production tests for CFI Bypass using real binaries with CFI protection."""

    @pytest.fixture
    def windows_cfg_binary(self):
        """Get a real Windows binary with CFG enabled."""
        system32 = Path("C:/Windows/System32")

        # Windows binaries known to have CFG enabled
        cfg_binaries = [
            "msedge.exe",
            "WindowsTerminal.exe",
            "powershell.exe",
            "notepad.exe"
        ]

        for binary_name in cfg_binaries:
            binary_path = system32 / binary_name
            if binary_path.exists():
                return str(binary_path)

        # Fallback
        return str(system32 / "notepad.exe")

    def test_cfi_bypass_initialization(self):
        """Test CFI bypass initialization and technique loading."""
        bypass = CFIBypass()

        assert bypass is not None
        assert bypass.mitigation_name == "CFI"
        assert bypass.logger is not None
        assert hasattr(bypass, 'rop_gadgets')
        assert hasattr(bypass, 'jop_gadgets')
        assert isinstance(bypass.techniques, list)

    def test_cfi_techniques_available(self):
        """Test that CFI bypass techniques are available."""
        bypass = CFIBypass()

        # Check techniques list is populated
        assert len(bypass.techniques) > 0

        # Verify expected techniques exist
        expected_in_techniques = [
            "legitimate_targets",
            "jop_gadgets",
            "indirect_branches",
            "vtable_hijacking",
            "return_oriented"
        ]

        for technique in expected_in_techniques:
            assert technique in bypass.techniques

    def test_analyze_cfi_protection(self, windows_cfg_binary):
        """Test CFI protection analysis on real binary."""
        bypass = CFIBypass()

        # Read binary data
        with open(windows_cfg_binary, 'rb') as f:
            binary_data = f.read(1024 * 1024)  # Read first 1MB

        # Analyze CFI protection
        result = bypass.analyze_cfi_protection(binary_data)

        assert result is not None
        assert isinstance(result, dict)
        assert 'has_cfi' in result
        assert 'cfi_type' in result
        assert 'bypass_difficulty' in result

    def test_generate_bypass_payload(self, windows_cfg_binary):
        """Test bypass payload generation."""
        bypass = CFIBypass()

        # Read binary data
        with open(windows_cfg_binary, 'rb') as f:
            binary_data = f.read(1024 * 1024)

        # Generate bypass payload
        result = bypass.generate_bypass_payload(
            target_binary=binary_data,
            technique="jop_gadgets"
        )

        assert result is not None
        assert isinstance(result, dict)
        assert 'technique' in result
        assert 'payload' in result or 'gadgets' in result

    def test_find_rop_gadgets(self, windows_cfg_binary):
        """Test finding ROP gadgets in real binary."""
        bypass = CFIBypass()

        # Read binary data
        with open(windows_cfg_binary, 'rb') as f:
            binary_data = f.read(1024 * 1024)

        # Find ROP gadgets
        gadgets = bypass.find_rop_gadgets(binary_data, arch="x86_64")

        assert gadgets is not None
        assert isinstance(gadgets, list)

        # Should find some gadgets in any binary
        if len(gadgets) > 0:
            gadget = gadgets[0]
            assert 'address' in gadget
            assert 'instruction' in gadget

    def test_find_jop_gadgets(self, windows_cfg_binary):
        """Test finding JOP gadgets in real binary."""
        bypass = CFIBypass()

        # Read binary data
        with open(windows_cfg_binary, 'rb') as f:
            binary_data = f.read(1024 * 1024)

        # Find JOP gadgets
        gadgets = bypass.find_jop_gadgets(binary_data, arch="x86_64")

        assert gadgets is not None
        assert isinstance(gadgets, list)

        # JOP gadgets might not exist in all binaries
        if len(gadgets) > 0:
            gadget = gadgets[0]
            assert 'address' in gadget
            assert 'type' in gadget

    def test_get_recommended_technique(self):
        """Test recommended technique selection."""
        bypass = CFIBypass()

        binary_info = {
            "has_vtables": True,
            "has_cfi": True,
            "cfi_type": "CFG",
            "arch": "x64"
        }

        technique = bypass.get_recommended_technique(binary_info)

        assert technique is not None
        assert isinstance(technique, str)
        assert technique in bypass.techniques

    def test_cfi_bypass_vtable_hijacking(self):
        """Test vtable hijacking bypass generation."""
        bypass = CFIBypass()

        # Create test binary data with vtable-like structure
        binary_data = b'\x48\x8b\x01' * 100  # mov rax, [rcx] pattern
        binary_data += b'\xff\x50\x08' * 50  # call [rax+8] pattern

        # Generate vtable hijacking bypass
        result = bypass.generate_bypass_payload(
            target_binary=binary_data,
            technique="vtable_hijacking"
        )

        assert result is not None
        assert isinstance(result, dict)

    def test_cfi_bypass_return_oriented(self):
        """Test return-oriented bypass generation."""
        bypass = CFIBypass()

        # Create test binary data with ROP gadgets
        binary_data = b'\x58\xc3' * 10  # pop rax; ret
        binary_data += b'\x5d\xc3' * 10  # pop rbp; ret
        binary_data += b'\xc3' * 20  # ret

        # Generate return-oriented bypass
        result = bypass.generate_bypass_payload(
            target_binary=binary_data,
            technique="return_oriented"
        )

        assert result is not None
        assert isinstance(result, dict)

    def test_cfi_bypass_indirect_branches(self):
        """Test indirect branch bypass generation."""
        bypass = CFIBypass()

        # Create test binary data with indirect branches
        binary_data = b'\xff\xe0' * 10  # jmp rax
        binary_data += b'\xff\xd0' * 10  # call rax
        binary_data += b'\xff\x25\x00\x00\x00\x00' * 5  # jmp [rip]

        # Generate indirect branch bypass
        result = bypass.generate_bypass_payload(
            target_binary=binary_data,
            technique="indirect_branches"
        )

        assert result is not None
        assert isinstance(result, dict)

    def test_cfi_bypass_error_handling(self):
        """Test error handling for invalid inputs."""
        bypass = CFIBypass()

        # Test with empty binary data
        result = bypass.generate_bypass_payload(b"", technique="invalid")
        assert result is not None

        # Test with invalid technique
        result = bypass.generate_bypass_payload(b"test", technique="nonexistent")
        assert result is not None

        # Test analyze with minimal data
        result = bypass.analyze_cfi_protection(b"MZ")
        assert result is not None
        assert isinstance(result, dict)

    def test_cfi_bypass_with_multiple_techniques(self, windows_cfg_binary):
        """Test combining multiple bypass techniques."""
        bypass = CFIBypass()

        # Read binary data
        with open(windows_cfg_binary, 'rb') as f:
            binary_data = f.read(512 * 1024)  # Read 512KB

        # Try multiple techniques
        techniques_to_try = ["jop_gadgets", "return_oriented", "legitimate_targets"]

        results = []
        for technique in techniques_to_try:
            result = bypass.generate_bypass_payload(
                target_binary=binary_data,
                technique=technique
            )
            results.append(result)

        # At least one technique should produce results
        assert any(r is not None for r in results)
        assert all(isinstance(r, dict) for r in results if r is not None)

    def test_cfi_markers_detection(self, windows_cfg_binary):
        """Test detection of CFI markers in binary."""
        bypass = CFIBypass()

        # Read binary data
        with open(windows_cfg_binary, 'rb') as f:
            binary_data = f.read(256 * 1024)

        # Check for CFI markers using private method
        markers = bypass._check_cfi_markers(binary_data)

        assert markers is not None
        assert isinstance(markers, dict)
        assert 'has_endbr' in markers or 'has_cfg' in markers

    def test_bypass_difficulty_calculation(self):
        """Test bypass difficulty calculation."""
        bypass = CFIBypass()

        # Create analysis result
        analysis = {
            'has_cfi': True,
            'cfi_type': 'CFG',
            'has_shadow_stack': True,
            'has_ibt': True,
            'indirect_calls': 50,
            'indirect_jumps': 20
        }

        # Calculate difficulty using private method
        difficulty = bypass._calculate_bypass_difficulty(analysis)

        assert isinstance(difficulty, int)
        assert 0 <= difficulty <= 10  # Difficulty scale 0-10
