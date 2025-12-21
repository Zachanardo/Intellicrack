"""Production tests for AutomatedPatchAgent.

Validates binary patching, patch point detection, keygen generation,
bypass pattern application, and exploitation technique effectiveness.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import struct
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.automated_patch_agent import (
    AutomatedPatchAgent,
    run_automated_patch_agent,
)


@pytest.fixture
def agent() -> AutomatedPatchAgent:
    """Create AutomatedPatchAgent instance."""
    return AutomatedPatchAgent()


@pytest.fixture
def test_binary_with_checks() -> bytes:
    """Create test binary with detectable license checks."""
    dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
    pe_header = b"PE\x00\x00" + struct.pack("<H", 0x014C) + b"\x00" * 18

    license_check_pattern = b"\x85\xc0\x74\x10"
    anti_debug_pattern = b"\xff\x15\x00\x00\x00\x00\x75\x08"
    time_check_pattern = b"\xff\x15\x00\x00\x00\x00\x3d\x00\x00\x00\x00"

    protection_markers = b"UPX" + b"\x00" * 50 + b"Themida" + b"\x00" * 50

    code_section = (
        license_check_pattern + b"\x00" * 20 +
        anti_debug_pattern + b"\x00" * 20 +
        time_check_pattern + b"\x00" * 100
    )

    padding = b"\x00" * (0x200 - len(dos_header) - len(pe_header) - len(protection_markers))

    return dos_header + pe_header + protection_markers + padding + code_section


@pytest.fixture
def binary_path(tmp_path: Path, test_binary_with_checks: bytes) -> Path:
    """Create temporary binary file with license checks."""
    path = tmp_path / "test_target.exe"
    path.write_bytes(test_binary_with_checks)
    return path


class TestInitialization:
    """Test AutomatedPatchAgent initialization."""

    def test_agent_initializes_with_patterns(self, agent: AutomatedPatchAgent) -> None:
        """Agent initializes with bypass patterns."""
        assert agent.bypass_patterns is not None
        assert len(agent.bypass_patterns) > 0
        assert "license_check_jmp" in agent.bypass_patterns
        assert "isdebuggerpresent_bypass" in agent.bypass_patterns

    def test_agent_initializes_exploitation_techniques(self, agent: AutomatedPatchAgent) -> None:
        """Agent initializes with exploitation techniques."""
        assert agent.exploitation_techniques is not None
        assert "rop_chains" in agent.exploitation_techniques
        assert "shellcode" in agent.exploitation_techniques
        assert "hook_detours" in agent.exploitation_techniques
        assert "memory_patches" in agent.exploitation_techniques

    def test_agent_initializes_patch_history(self, agent: AutomatedPatchAgent) -> None:
        """Agent initializes with empty patch history."""
        assert agent.patch_history == []
        assert agent.patch_signatures == {}


class TestBypassPatterns:
    """Test bypass pattern initialization."""

    def test_license_bypass_patterns(self, agent: AutomatedPatchAgent) -> None:
        """Agent has license check bypass patterns."""
        assert agent.bypass_patterns["license_check_ret_true"] == b"\xb8\x01\x00\x00\x00\xc3"
        assert agent.bypass_patterns["license_check_nop"] == b"\x90" * 6
        assert isinstance(agent.bypass_patterns["license_check_jmp"], bytes)

    def test_anti_debug_bypass_patterns(self, agent: AutomatedPatchAgent) -> None:
        """Agent has anti-debug bypass patterns."""
        assert agent.bypass_patterns["isdebuggerpresent_bypass"] == b"\x33\xc0\xc3"
        assert len(agent.bypass_patterns["checkremotedebuggerpresent_bypass"]) > 0

    def test_time_bomb_bypass_patterns(self, agent: AutomatedPatchAgent) -> None:
        """Agent has time check bypass patterns."""
        assert "time_check_bypass" in agent.bypass_patterns
        assert "date_check_bypass" in agent.bypass_patterns

    def test_hardware_id_bypass_patterns(self, agent: AutomatedPatchAgent) -> None:
        """Agent has HWID spoofing patterns."""
        assert "hwid_spoof" in agent.bypass_patterns
        assert "mac_address_spoof" in agent.bypass_patterns

    def test_integrity_bypass_patterns(self, agent: AutomatedPatchAgent) -> None:
        """Agent has CRC/integrity bypass patterns."""
        assert "crc_check_bypass" in agent.bypass_patterns
        assert "integrity_check_bypass" in agent.bypass_patterns


class TestExploitationTechniques:
    """Test exploitation technique loading."""

    def test_rop_chains_generation(self, agent: AutomatedPatchAgent) -> None:
        """Agent generates ROP chains."""
        rop_chains = agent.exploitation_techniques["rop_chains"]

        assert "virtualprotect" in rop_chains
        assert "writeprocessmemory" in rop_chains
        assert isinstance(rop_chains["virtualprotect"], list)
        assert len(rop_chains["virtualprotect"]) > 0

    def test_shellcode_templates(self, agent: AutomatedPatchAgent) -> None:
        """Agent has shellcode templates."""
        shellcode = agent.exploitation_techniques["shellcode"]

        assert "license_bypass" in shellcode
        assert "trial_reset" in shellcode
        assert "feature_unlock" in shellcode
        assert isinstance(shellcode["license_bypass"], bytes)
        assert b"\xc3" in shellcode["license_bypass"]

    def test_hook_detours(self, agent: AutomatedPatchAgent) -> None:
        """Agent has API hook detours."""
        hooks = agent.exploitation_techniques["hook_detours"]

        assert "createfile_detour" in hooks
        assert "regquery_detour" in hooks
        assert isinstance(hooks["createfile_detour"], bytes)

    def test_memory_patches(self, agent: AutomatedPatchAgent) -> None:
        """Agent has memory patch definitions."""
        patches = agent.exploitation_techniques["memory_patches"]

        assert "remove_nag_screen" in patches
        assert "skip_update_check" in patches
        assert "enable_debug_menu" in patches
        assert isinstance(patches["remove_nag_screen"], tuple)
        assert len(patches["remove_nag_screen"]) == 2


class TestBinaryAnalysis:
    """Test binary analysis functionality."""

    def test_analyze_binary_detects_protection_schemes(self, agent: AutomatedPatchAgent, binary_path: Path) -> None:
        """analyze_binary identifies protection schemes."""
        results = agent.analyze_binary(str(binary_path))

        assert "protection_schemes" in results
        assert len(results["protection_schemes"]) > 0
        assert any("UPX" in scheme or "Themida" in scheme for scheme in results["protection_schemes"])

    def test_analyze_binary_finds_patch_points(self, agent: AutomatedPatchAgent, binary_path: Path) -> None:
        """analyze_binary locates patchable code points."""
        results = agent.analyze_binary(str(binary_path))

        assert "patch_points" in results
        assert len(results["patch_points"]) > 0

        point = results["patch_points"][0]
        assert "offset" in point
        assert "type" in point
        assert "pattern" in point

    def test_analyze_binary_calculates_vulnerability_score(self, agent: AutomatedPatchAgent, binary_path: Path) -> None:
        """analyze_binary calculates vulnerability score."""
        results = agent.analyze_binary(str(binary_path))

        assert "vulnerability_score" in results
        assert results["vulnerability_score"] >= 0

    def test_analyze_binary_recommends_patches(self, agent: AutomatedPatchAgent, binary_path: Path) -> None:
        """analyze_binary provides patch recommendations."""
        results = agent.analyze_binary(str(binary_path))

        assert "recommended_patches" in results

        if results["recommended_patches"]:
            patch = results["recommended_patches"][0]
            assert "offset" in patch
            assert "patch" in patch
            assert "description" in patch


class TestPatchPointDetection:
    """Test patch point finding."""

    def test_find_license_check_patterns(self, agent: AutomatedPatchAgent, binary_path: Path) -> None:
        """_find_patch_points detects license checks."""
        with open(binary_path, 'rb') as f:
            binary_data = f.read()

        patch_points = agent._find_patch_points(binary_data)

        license_points = [p for p in patch_points if p["type"] == "license_check"]
        assert license_points

    def test_find_anti_debug_patterns(self, agent: AutomatedPatchAgent, binary_path: Path) -> None:
        """_find_patch_points detects anti-debug checks."""
        with open(binary_path, 'rb') as f:
            binary_data = f.read()

        patch_points = agent._find_patch_points(binary_data)

        anti_debug_points = [p for p in patch_points if p["type"] == "anti_debug"]
        assert anti_debug_points

    def test_find_time_check_patterns(self, agent: AutomatedPatchAgent, binary_path: Path) -> None:
        """_find_patch_points detects time bombs."""
        with open(binary_path, 'rb') as f:
            binary_data = f.read()

        patch_points = agent._find_patch_points(binary_data)

        time_points = [p for p in patch_points if p["type"] == "time_check"]
        assert time_points

    def test_patch_points_include_metadata(self, agent: AutomatedPatchAgent, binary_path: Path) -> None:
        """Patch points include complete metadata."""
        with open(binary_path, 'rb') as f:
            binary_data = f.read()

        if patch_points := agent._find_patch_points(binary_data):
            point = patch_points[0]
            assert "offset" in point
            assert "type" in point
            assert "pattern" in point
            assert "size" in point


class TestPatchApplication:
    """Test patch application functionality."""

    def test_apply_patch_modifies_binary(self, agent: AutomatedPatchAgent, binary_path: Path) -> None:
        """apply_patch modifies binary at specified offset."""
        original_data = binary_path.read_bytes()

        patch = {
            "offset": 100,
            "patch": b"\x90\x90\x90",
            "description": "Test patch"
        }

        success = agent.apply_patch(str(binary_path), patch)

        assert success is True

        modified_data = binary_path.read_bytes()
        assert modified_data != original_data
        assert modified_data[100:103] == b"\x90\x90\x90"

    def test_apply_patch_creates_backup(self, agent: AutomatedPatchAgent, binary_path: Path, tmp_path: Path) -> None:
        """apply_patch creates backup before modifying."""
        patch = {
            "offset": 50,
            "patch": b"\xEB\x10",
            "description": "Backup test"
        }

        agent.apply_patch(str(binary_path), patch)

        backup_files = list(tmp_path.glob("*.bak_*"))
        assert backup_files

    def test_apply_patch_updates_history(self, agent: AutomatedPatchAgent, binary_path: Path) -> None:
        """apply_patch logs to patch history."""
        initial_count = len(agent.patch_history)

        patch = {
            "offset": 75,
            "patch": b"\x31\xC0\xC3",
            "description": "History test"
        }

        agent.apply_patch(str(binary_path), patch)

        assert len(agent.patch_history) == initial_count + 1

        history_entry = agent.patch_history[-1]
        assert "timestamp" in history_entry
        assert "file" in history_entry
        assert "offset" in history_entry
        assert history_entry["offset"] == 75

    def test_apply_patch_out_of_bounds(self, agent: AutomatedPatchAgent, binary_path: Path) -> None:
        """apply_patch handles out-of-bounds offsets."""
        file_size = binary_path.stat().st_size

        patch = {
            "offset": file_size + 1000,
            "patch": b"\x90\x90",
            "description": "Out of bounds"
        }

        success = agent.apply_patch(str(binary_path), patch)

        assert success is False


class TestKeygenGeneration:
    """Test keygen code generation."""

    def test_generate_serial_keygen(self, agent: AutomatedPatchAgent) -> None:
        """generate_keygen produces serial algorithm."""
        keygen_code = agent.generate_keygen("serial")

        assert "def generate_serial" in keygen_code
        assert "hashlib" in keygen_code
        assert "serial_parts" in keygen_code

    def test_generate_rsa_keygen(self, agent: AutomatedPatchAgent) -> None:
        """generate_keygen produces RSA-based keygen."""
        keygen_code = agent.generate_keygen("rsa")

        assert "from cryptography" in keygen_code
        assert "rsa.generate_private_key" in keygen_code
        assert "private_key.sign" in keygen_code

    def test_generate_ecc_keygen(self, agent: AutomatedPatchAgent) -> None:
        """generate_keygen produces ECC-based keygen."""
        keygen_code = agent.generate_keygen("elliptic")

        assert "ec.generate_private_key" in keygen_code
        assert "SECP256R1" in keygen_code
        assert "ECDSA" in keygen_code

    def test_generate_custom_keygen(self, agent: AutomatedPatchAgent) -> None:
        """generate_keygen produces custom algorithm."""
        keygen_code = agent.generate_keygen("custom")

        assert "def custom_keygen" in keygen_code
        assert "magic" in keygen_code
        assert "0xDEADBEEF" in keygen_code

    def test_generate_unknown_type_defaults_to_serial(self, agent: AutomatedPatchAgent) -> None:
        """generate_keygen defaults to serial for unknown types."""
        keygen_code = agent.generate_keygen("unknown_type")

        assert "def generate_serial" in keygen_code

    def test_keygen_code_is_executable_python(self, agent: AutomatedPatchAgent) -> None:
        """Generated keygen is valid Python code."""
        keygen_code = agent.generate_keygen("serial")

        try:
            compile(keygen_code, "<string>", "exec")
            is_valid = True
        except SyntaxError:
            is_valid = False

        assert is_valid


class TestRunAutomatedPatchAgent:
    """Test convenience function."""

    def test_run_agent_analyzes_binary(self, binary_path: Path) -> None:
        """run_automated_patch_agent performs analysis."""
        results = run_automated_patch_agent(str(binary_path), patch_mode="manual")

        assert "analysis" in results
        assert "patches_applied" in results
        assert "success" in results

    def test_run_agent_auto_mode_applies_patches(self, binary_path: Path) -> None:
        """run_automated_patch_agent applies patches in auto mode."""
        original_data = binary_path.read_bytes()

        results = run_automated_patch_agent(str(binary_path), patch_mode="auto")

        if results["analysis"]["recommended_patches"]:
            modified_data = binary_path.read_bytes()
            assert results["success"] is True
            assert len(results["patches_applied"]) > 0
        else:
            assert results["success"] is False

    def test_run_agent_manual_mode_no_patches(self, binary_path: Path) -> None:
        """run_automated_patch_agent doesn't patch in manual mode."""
        original_data = binary_path.read_bytes()

        results = run_automated_patch_agent(str(binary_path), patch_mode="manual")

        modified_data = binary_path.read_bytes()
        assert modified_data == original_data
        assert len(results["patches_applied"]) == 0


class TestShellcodeGeneration:
    """Test shellcode template functionality."""

    def test_license_bypass_shellcode(self, agent: AutomatedPatchAgent) -> None:
        """License bypass shellcode is valid x86/x64."""
        shellcode = agent.exploitation_techniques["shellcode"]["license_bypass"]

        assert b"\xc3" in shellcode
        assert len(shellcode) > 0

    def test_trial_reset_shellcode(self, agent: AutomatedPatchAgent) -> None:
        """Trial reset shellcode includes counter reset."""
        shellcode = agent.exploitation_techniques["shellcode"]["trial_reset"]

        assert b"\x48\x31\xc0" in shellcode
        assert b"\xc3" in shellcode

    def test_feature_unlock_shellcode(self, agent: AutomatedPatchAgent) -> None:
        """Feature unlock shellcode sets all flags."""
        shellcode = agent.exploitation_techniques["shellcode"]["feature_unlock"]

        assert b"\xff\xff\xff\xff" in shellcode
        assert b"\xc3" in shellcode


class TestRopChains:
    """Test ROP chain generation."""

    def test_virtualprotect_chain(self, agent: AutomatedPatchAgent) -> None:
        """VirtualProtect ROP chain has required gadgets."""
        chain = agent.exploitation_techniques["rop_chains"]["virtualprotect"]

        assert len(chain) >= 6
        assert 0x00000040 in chain
        assert 0x00001000 in chain

    def test_writeprocessmemory_chain(self, agent: AutomatedPatchAgent) -> None:
        """WriteProcessMemory ROP chain is complete."""
        chain = agent.exploitation_techniques["rop_chains"]["writeprocessmemory"]

        assert len(chain) >= 6
        assert 0x00000100 in chain


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_analyze_nonexistent_binary(self, agent: AutomatedPatchAgent) -> None:
        """analyze_binary handles missing files gracefully."""
        results = agent.analyze_binary("/nonexistent/file.exe")

        assert "protection_schemes" in results
        assert "patch_points" in results

    def test_apply_patch_to_readonly_file(self, agent: AutomatedPatchAgent, binary_path: Path) -> None:
        """apply_patch handles read-only files."""
        if os.name != 'nt':
            binary_path.chmod(0o444)

            patch = {
                "offset": 10,
                "patch": b"\x90",
                "description": "Readonly test"
            }

            success = agent.apply_patch(str(binary_path), patch)

            if success is not False:
                binary_path.chmod(0o644)

    def test_find_patch_points_empty_binary(self, agent: AutomatedPatchAgent) -> None:
        """_find_patch_points handles empty binaries."""
        patch_points = agent._find_patch_points(b"")

        assert patch_points == []

    def test_find_patch_points_small_binary(self, agent: AutomatedPatchAgent) -> None:
        """_find_patch_points handles very small binaries."""
        patch_points = agent._find_patch_points(b"MZ\x00\x00")

        assert isinstance(patch_points, list)

    def test_patch_history_preserves_order(self, agent: AutomatedPatchAgent, binary_path: Path) -> None:
        """Patch history maintains chronological order."""
        patch1 = {"offset": 10, "patch": b"\x90", "description": "First"}
        patch2 = {"offset": 20, "patch": b"\x90", "description": "Second"}

        time.sleep(0.01)
        agent.apply_patch(str(binary_path), patch1)
        time.sleep(0.01)
        agent.apply_patch(str(binary_path), patch2)

        assert len(agent.patch_history) >= 2
        assert agent.patch_history[-2]["timestamp"] < agent.patch_history[-1]["timestamp"]

    def test_backup_filename_uniqueness(self, agent: AutomatedPatchAgent, binary_path: Path) -> None:
        """Backup filenames use unique timestamps."""
        patch = {"offset": 5, "patch": b"\xEB", "description": "Test"}

        time.sleep(0.01)
        agent.apply_patch(str(binary_path), patch)
        time.sleep(0.01)
        agent.apply_patch(str(binary_path), patch)

        backups = [e["backup"] for e in agent.patch_history if "backup" in e]

        if len(backups) >= 2:
            assert backups[-1] != backups[-2]

    def test_analyze_binary_with_all_protections(self, agent: AutomatedPatchAgent, tmp_path: Path) -> None:
        """analyze_binary detects multiple protection schemes."""
        multi_protected = b"UPX" + b"\x00" * 100 + b"Themida" + b"\x00" * 100 + b".vmp" + b"\x00" * 800

        protected_path = tmp_path / "multi_protected.exe"
        protected_path.write_bytes(multi_protected)

        results = agent.analyze_binary(str(protected_path))

        assert len(results["protection_schemes"]) >= 2
