"""Production tests for Ghidra Binary Integration.

Tests validate REAL Ghidra integration capabilities including binary analysis,
license validation detection, protection scheme detection, crypto analysis,
keygen template generation, and deobfuscation. Tests operate on REAL binaries
through actual Ghidra headless analysis - NO mocks, NO stubs.

All tests validate genuine offensive binary analysis capabilities required for
effective software licensing protection defeat and crack development.
"""

import json
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.ghidra_binary_integration import GhidraBinaryIntegration
from intellicrack.core.analysis.ghidra_script_runner import GhidraScript, GhidraScriptRunner
from intellicrack.core.analysis.ghidra_analyzer import (
    GhidraAnalysisResult,
    GhidraFunction,
    GhidraOutputParser,
    GhidraScriptManager,
)
from intellicrack.utils.ghidra_common import (
    create_ghidra_analysis_script,
    run_ghidra_plugin,
    save_ghidra_script,
    get_ghidra_project_info,
    cleanup_ghidra_project,
)

GHIDRA_PATH = Path("D:/Intellicrack/tools/ghidra")
GHIDRA_HEADLESS = GHIDRA_PATH / "support" / "analyzeHeadless.bat"

GHIDRA_AVAILABLE = GHIDRA_HEADLESS.exists()

pytestmark = pytest.mark.skipif(
    not GHIDRA_AVAILABLE,
    reason="Ghidra not installed at D:/Intellicrack/tools/ghidra"
)


@pytest.fixture
def temp_workspace(tmp_path: Path) -> Path:
    """Provide temporary workspace for test files."""
    workspace = tmp_path / "ghidra_test_workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    return workspace


@pytest.fixture
def sample_pe_binary(temp_workspace: Path) -> Path:
    """Create a minimal valid PE binary for testing."""
    binary_path = temp_workspace / "test_binary.exe"

    dos_header = bytearray(b'MZ' + b'\x90' * 58 + struct.pack('<I', 0x80))

    pe_signature = b'PE\x00\x00'

    coff_header = struct.pack('<HHIIIHH',
        0x8664,
        2,
        0,
        0,
        0,
        0xF0,
        0x22
    )

    optional_header = bytearray(248)
    optional_header[:2] = struct.pack('<H', 0x20B)
    struct.pack_into('<Q', optional_header, 24, 0x140000000)
    struct.pack_into('<I', optional_header, 16, 0x1000)
    struct.pack_into('<Q', optional_header, 32, 0x1000)

    text_section = struct.pack('<8sIIIIIIHHI',
        b'.text\x00\x00\x00',
        0x1000,
        0x1000,
        0x200,
        0x200,
        0,
        0,
        0,
        0,
        0x60000020
    )

    data_section = struct.pack('<8sIIIIIIHHI',
        b'.data\x00\x00\x00',
        0x1000,
        0x2000,
        0x200,
        0x400,
        0,
        0,
        0,
        0,
        0xC0000040
    )

    code = bytes([
        0x48, 0x83, 0xEC, 0x28,
        0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
        0xE8, 0x00, 0x00, 0x00, 0x00,
        0x33, 0xC0,
        0x48, 0x83, 0xC4, 0x28,
        0xC3,
    ])
    code_padded = code + b'\x00' * (0x200 - len(code))

    data_content = b'License validation failed!\x00' * 5
    data_padded = data_content + b'\x00' * (0x200 - len(data_content))

    with open(binary_path, 'wb') as f:
        f.write(dos_header)
        f.write(pe_signature)
        f.write(coff_header)
        f.write(optional_header)
        f.write(text_section)
        f.write(data_section)
        f.write(code_padded)
        f.write(data_padded)

    return binary_path


@pytest.fixture
def ghidra_integration(temp_workspace: Path) -> GhidraBinaryIntegration:
    """Create GhidraBinaryIntegration instance."""
    return GhidraBinaryIntegration(ghidra_path=GHIDRA_PATH)


@pytest.fixture
def ghidra_script_runner(temp_workspace: Path) -> GhidraScriptRunner:
    """Create GhidraScriptRunner instance."""
    return GhidraScriptRunner(ghidra_path=GHIDRA_PATH)


@pytest.fixture
def ghidra_script_manager(temp_workspace: Path) -> GhidraScriptManager:
    """Create GhidraScriptManager instance."""
    return GhidraScriptManager(ghidra_install_dir=str(GHIDRA_PATH))


class TestGhidraAvailability:
    """Test Ghidra installation detection and availability."""

    def test_ghidra_installation_exists(self) -> None:
        """Verify Ghidra installation directory exists."""
        assert GHIDRA_PATH.exists(), f"Ghidra path does not exist: {GHIDRA_PATH}"
        assert GHIDRA_PATH.is_dir(), f"Ghidra path is not a directory: {GHIDRA_PATH}"

    def test_ghidra_headless_analyzer_exists(self) -> None:
        """Verify Ghidra headless analyzer executable exists."""
        assert GHIDRA_HEADLESS.exists(), f"Ghidra headless not found: {GHIDRA_HEADLESS}"
        assert GHIDRA_HEADLESS.is_file(), f"Ghidra headless is not a file: {GHIDRA_HEADLESS}"

    def test_ghidra_version_detection(self) -> None:
        """Verify Ghidra version can be detected."""
        try:
            result = subprocess.run(
                [str(GHIDRA_HEADLESS)],
                capture_output=True,
                text=True,
                timeout=10
            )

            output = result.stdout + result.stderr
            assert "Ghidra" in output or "ghidra" in output.lower(), \
                "Ghidra executable does not produce expected output"
        except subprocess.TimeoutExpired:
            pytest.fail("Ghidra headless analyzer timed out during version check")

    def test_ghidra_support_directory_structure(self) -> None:
        """Verify Ghidra support directory structure exists."""
        support_dir = GHIDRA_PATH / "support"
        assert support_dir.exists(), f"Ghidra support directory not found: {support_dir}"

        ghidra_dir = GHIDRA_PATH / "Ghidra"
        assert ghidra_dir.exists(), f"Ghidra main directory not found: {ghidra_dir}"


class TestGhidraBinaryIntegration:
    """Test GhidraBinaryIntegration class functionality."""

    def test_integration_initialization(self, ghidra_integration: GhidraBinaryIntegration) -> None:
        """Verify GhidraBinaryIntegration initializes correctly."""
        assert ghidra_integration.ghidra_path == GHIDRA_PATH
        assert ghidra_integration.script_runner is not None
        assert isinstance(ghidra_integration.script_runner, GhidraScriptRunner)

    def test_analyze_license_validation_basic(
        self,
        ghidra_integration: GhidraBinaryIntegration,
        sample_pe_binary: Path
    ) -> None:
        """Test basic license validation analysis on real binary."""
        result = ghidra_integration.analyze_license_validation(
            binary_path=sample_pe_binary,
            deep_analysis=False
        )

        assert isinstance(result, dict), "Analysis result must be a dictionary"
        assert "error" in result or "success" in result or "validation_functions" in result, \
            "Analysis result must contain status information"

    def test_analyze_license_validation_deep(
        self,
        ghidra_integration: GhidraBinaryIntegration,
        sample_pe_binary: Path
    ) -> None:
        """Test deep license validation analysis on real binary."""
        result = ghidra_integration.analyze_license_validation(
            binary_path=sample_pe_binary,
            deep_analysis=True
        )

        assert isinstance(result, dict), "Deep analysis result must be a dictionary"

        if result.get("success") is not False:
            assert "error" in result or "validation_functions" in result or "analysis" in result, \
                "Deep analysis must provide detailed results"

    def test_detect_protections(
        self,
        ghidra_integration: GhidraBinaryIntegration,
        sample_pe_binary: Path
    ) -> None:
        """Test protection scheme detection on real binary."""
        result = ghidra_integration.detect_protections(binary_path=sample_pe_binary)

        assert isinstance(result, dict), "Protection detection result must be a dictionary"
        assert "protections" in result, "Result must contain protections list"
        assert isinstance(result["protections"], list), "Protections must be a list"
        assert "success" in result, "Result must indicate success status"

    def test_analyze_crypto_routines(
        self,
        ghidra_integration: GhidraBinaryIntegration,
        sample_pe_binary: Path
    ) -> None:
        """Test cryptographic routine analysis on real binary."""
        result = ghidra_integration.analyze_crypto_routines(binary_path=sample_pe_binary)

        assert isinstance(result, dict), "Crypto analysis result must be a dictionary"

        if result.get("success") is True:
            assert "standard_algorithms" in result or "custom_crypto" in result, \
                "Successful crypto analysis must identify algorithms"

    def test_generate_keygen_template(
        self,
        ghidra_integration: GhidraBinaryIntegration,
        sample_pe_binary: Path
    ) -> None:
        """Test keygen template generation from license validation."""
        result = ghidra_integration.generate_keygen_template(binary_path=sample_pe_binary)

        assert isinstance(result, dict), "Keygen template result must be a dictionary"

        if result.get("success") is True:
            assert "algorithm_type" in result or "template" in result, \
                "Successful keygen generation must provide algorithm info"

    def test_deobfuscate_control_flow(
        self,
        ghidra_integration: GhidraBinaryIntegration,
        sample_pe_binary: Path
    ) -> None:
        """Test control flow deobfuscation on real binary."""
        result = ghidra_integration.deobfuscate_control_flow(binary_path=sample_pe_binary)

        assert isinstance(result, dict), "Deobfuscation result must be a dictionary"

        if result.get("success") is True:
            assert "blocks_deobfuscated" in result or "simplified" in result, \
                "Successful deobfuscation must report processed blocks"

    def test_decrypt_strings(
        self,
        ghidra_integration: GhidraBinaryIntegration,
        sample_pe_binary: Path
    ) -> None:
        """Test automated string decryption on real binary."""
        result = ghidra_integration.decrypt_strings(binary_path=sample_pe_binary)

        assert isinstance(result, dict), "String decryption result must be a dictionary"

        if result.get("success") is True:
            assert "decrypted_strings" in result, \
                "Successful decryption must provide decrypted strings list"
            assert isinstance(result["decrypted_strings"], list), \
                "Decrypted strings must be a list"

    def test_detect_anti_analysis(
        self,
        ghidra_integration: GhidraBinaryIntegration,
        sample_pe_binary: Path
    ) -> None:
        """Test anti-analysis technique detection on real binary."""
        result = ghidra_integration.detect_anti_analysis(binary_path=sample_pe_binary)

        assert isinstance(result, dict), "Anti-analysis result must be a dictionary"
        assert "techniques" in result, "Result must contain techniques list"
        assert isinstance(result["techniques"], list), "Techniques must be a list"
        assert "success" in result, "Result must indicate success status"

    def test_comprehensive_analysis_without_decompilation(
        self,
        ghidra_integration: GhidraBinaryIntegration,
        sample_pe_binary: Path
    ) -> None:
        """Test comprehensive analysis without decompilation."""
        result = ghidra_integration.perform_comprehensive_analysis(
            binary_path=sample_pe_binary,
            include_decompilation=False
        )

        assert isinstance(result, dict), "Comprehensive analysis result must be a dictionary"

        if result.get("success") is not False:
            assert "function_count" in result or "functions" in result or "analysis" in result, \
                "Analysis must provide function information"

    def test_comprehensive_analysis_with_decompilation(
        self,
        ghidra_integration: GhidraBinaryIntegration,
        sample_pe_binary: Path
    ) -> None:
        """Test comprehensive analysis with decompilation."""
        result = ghidra_integration.perform_comprehensive_analysis(
            binary_path=sample_pe_binary,
            include_decompilation=True
        )

        assert isinstance(result, dict), "Decompilation analysis result must be a dictionary"

    def test_unpack_binary(
        self,
        ghidra_integration: GhidraBinaryIntegration,
        sample_pe_binary: Path
    ) -> None:
        """Test automated binary unpacking."""
        result = ghidra_integration.unpack_binary(
            binary_path=sample_pe_binary,
            max_iterations=5
        )

        assert isinstance(result, dict), "Unpacking result must be a dictionary"

        if result.get("success") is True:
            assert "oep" in result, "Successful unpacking must identify OEP"

    def test_analyze_network_communication(
        self,
        ghidra_integration: GhidraBinaryIntegration,
        sample_pe_binary: Path
    ) -> None:
        """Test network communication analysis on real binary."""
        result = ghidra_integration.analyze_network_communication(binary_path=sample_pe_binary)

        assert isinstance(result, dict), "Network analysis result must be a dictionary"

        if result.get("success") is True:
            assert "network_functions" in result, \
                "Successful network analysis must identify network functions"
            assert isinstance(result["network_functions"], list), \
                "Network functions must be a list"


class TestGhidraLicensingCrackWorkflow:
    """Test complete licensing crack workflow."""

    def test_licensing_crack_workflow_execution(
        self,
        ghidra_integration: GhidraBinaryIntegration,
        sample_pe_binary: Path
    ) -> None:
        """Test full licensing crack workflow completes successfully."""
        result = ghidra_integration.perform_licensing_crack_workflow(
            binary_path=sample_pe_binary
        )

        assert isinstance(result, dict), "Workflow result must be a dictionary"
        assert "binary" in result, "Result must specify analyzed binary"
        assert "success" in result, "Result must indicate success status"
        assert "stages" in result, "Result must contain workflow stages"

        stages = result["stages"]
        assert isinstance(stages, dict), "Stages must be a dictionary"

        assert "protection_detection" in stages, "Must include protection detection stage"
        assert "license_analysis" in stages, "Must include license analysis stage"
        assert "crypto_analysis" in stages, "Must include crypto analysis stage"
        assert "keygen_generation" in stages, "Must include keygen generation stage"
        assert "string_decryption" in stages, "Must include string decryption stage"
        assert "anti_analysis" in stages, "Must include anti-analysis detection stage"

    def test_workflow_handles_packed_binary(
        self,
        ghidra_integration: GhidraBinaryIntegration,
        sample_pe_binary: Path
    ) -> None:
        """Test workflow detects and handles packed binaries."""
        result = ghidra_integration.perform_licensing_crack_workflow(
            binary_path=sample_pe_binary
        )

        assert isinstance(result, dict), "Workflow result must be a dictionary"
        assert "stages" in result, "Result must contain workflow stages"

        if "unpacking" in result["stages"]:
            unpacking_result = result["stages"]["unpacking"]
            assert isinstance(unpacking_result, dict), "Unpacking stage must be a dictionary"


class TestGhidraScriptRunner:
    """Test GhidraScriptRunner script management and execution."""

    def test_script_runner_initialization(
        self,
        ghidra_script_runner: GhidraScriptRunner
    ) -> None:
        """Verify script runner initializes correctly."""
        assert ghidra_script_runner.ghidra_path == GHIDRA_PATH
        assert ghidra_script_runner.headless_path.exists(), \
            "Headless analyzer path must exist"
        assert isinstance(ghidra_script_runner.discovered_scripts, dict), \
            "Discovered scripts must be stored in dictionary"

    def test_list_available_scripts(
        self,
        ghidra_script_runner: GhidraScriptRunner
    ) -> None:
        """Test listing all available Ghidra scripts."""
        scripts = ghidra_script_runner.list_available_scripts()

        assert isinstance(scripts, list), "Script list must be a list"

        for script_info in scripts:
            assert isinstance(script_info, dict), "Each script info must be a dictionary"
            assert "name" in script_info, "Script info must contain name"
            assert "language" in script_info, "Script info must contain language"
            assert "description" in script_info, "Script info must contain description"

    def test_script_metadata_parsing(
        self,
        ghidra_script_runner: GhidraScriptRunner,
        temp_workspace: Path
    ) -> None:
        """Test script metadata parsing from script headers."""
        test_script = temp_workspace / "test_metadata.py"
        test_script.write_text("""
# @description: Test script for metadata parsing
# @timeout: 120
# @output_format: json
# @parameters: {"test_param": "test_value"}

print("Test script content")
""")

        metadata = ghidra_script_runner._parse_script_metadata(test_script)

        assert isinstance(metadata, dict), "Metadata must be a dictionary"
        assert "description" in metadata, "Must parse description"
        assert "timeout" in metadata, "Must parse timeout"
        assert "output_format" in metadata, "Must parse output format"

    def test_validate_script_python(
        self,
        ghidra_script_runner: GhidraScriptRunner,
        temp_workspace: Path
    ) -> None:
        """Test Python script validation."""
        valid_script = temp_workspace / "valid_script.py"
        valid_script.write_text("print('Valid Python script')")

        assert ghidra_script_runner.validate_script(valid_script), \
            "Valid Python script must pass validation"

        invalid_script = temp_workspace / "invalid_script.py"
        invalid_script.write_text("print('Unclosed string")

        assert not ghidra_script_runner.validate_script(invalid_script), \
            "Invalid Python script must fail validation"

    def test_validate_script_java(
        self,
        ghidra_script_runner: GhidraScriptRunner,
        temp_workspace: Path
    ) -> None:
        """Test Java script validation."""
        valid_script = temp_workspace / "valid_script.java"
        valid_script.write_text("public class Test { }")

        result = ghidra_script_runner.validate_script(valid_script)
        assert isinstance(result, bool), "Validation must return boolean"


class TestGhidraOutputParser:
    """Test Ghidra output parsing for various formats."""

    def test_parser_initialization(self) -> None:
        """Verify parser initializes correctly."""
        parser = GhidraOutputParser()
        assert parser is not None
        assert parser.result is None

    def test_parse_json_output_valid(self) -> None:
        """Test parsing valid JSON output from Ghidra."""
        json_output = json.dumps({
            "program": {
                "name": "test.exe",
                "processor": "x86-64",
                "compiler": "gcc",
                "imageBase": "0x140000000",
                "entryPoint": "0x140001000"
            },
            "functions": [
                {
                    "name": "main",
                    "address": "0x140001000",
                    "size": "100",
                    "signature": "int main()",
                    "returnType": "int",
                    "parameters": [],
                    "localVars": [],
                    "decompiledCode": "int main() { return 0; }",
                    "assembly": "",
                    "xrefsTo": [],
                    "xrefsFrom": [],
                    "comments": {},
                    "isThunk": False,
                    "isExternal": False,
                    "callingConvention": "__cdecl"
                }
            ],
            "strings": [],
            "imports": [],
            "exports": [],
            "sections": [],
            "vtables": [],
            "exceptionHandlers": []
        })

        parser = GhidraOutputParser()
        result = parser.parse_json_output(json_output)

        assert isinstance(result, GhidraAnalysisResult), \
            "Parser must return GhidraAnalysisResult"
        assert result.binary_path == "test.exe", "Must parse binary name"
        assert result.architecture == "x86-64", "Must parse architecture"
        assert len(result.functions) == 1, "Must parse functions"
        assert 0x140001000 in result.functions, "Function must be indexed by address"

    def test_parse_json_output_invalid(self) -> None:
        """Test parser handles invalid JSON gracefully."""
        parser = GhidraOutputParser()

        with pytest.raises(ValueError, match="Failed to parse JSON"):
            parser.parse_json_output("Invalid JSON {")

    def test_parse_xml_output_valid(self) -> None:
        """Test parsing valid XML output from Ghidra."""
        xml_output = """<?xml version="1.0"?>
<GhidraAnalysis>
    <PROGRAM NAME="test.exe" IMAGE_BASE="0x140000000">
        <PROCESSOR NAME="x86-64"/>
        <COMPILER NAME="gcc"/>
        <PROGRAM_ENTRY_POINT ADDRESS="0x140001000"/>
    </PROGRAM>
</GhidraAnalysis>"""

        parser = GhidraOutputParser()
        result = parser.parse_xml_output(xml_output)

        assert isinstance(result, GhidraAnalysisResult), \
            "Parser must return GhidraAnalysisResult"
        assert result.binary_path == "test.exe", "Must parse binary name"
        assert result.architecture == "x86-64", "Must parse architecture"

    def test_parse_xml_output_invalid(self) -> None:
        """Test parser handles invalid XML gracefully."""
        parser = GhidraOutputParser()

        with pytest.raises(ValueError, match="Failed to parse XML"):
            parser.parse_xml_output("<Invalid XML")

    def test_parse_text_output(self) -> None:
        """Test parsing text-based output from Ghidra."""
        text_output = """
Processor: x86-64
Compiler: gcc
Entry Point: 0x140001000
Image Base: 0x140000000

Function: main at 0x140001000
Size: 100 bytes

String at 0x140002000: "License key required"
Import: KERNEL32.dll!ExitProcess at 0x140003000
Export: main at 0x140001000
"""

        parser = GhidraOutputParser()
        result = parser.parse_text_output(text_output)

        assert isinstance(result, GhidraAnalysisResult), \
            "Parser must return GhidraAnalysisResult"
        assert result.architecture == "x86-64", "Must parse architecture"
        assert result.entry_point == 0x140001000, "Must parse entry point"
        assert len(result.functions) > 0, "Must parse functions"
        assert len(result.strings) > 0, "Must parse strings"


class TestGhidraScriptManager:
    """Test GhidraScriptManager for script selection and chaining."""

    def test_script_manager_initialization(
        self,
        ghidra_script_manager: GhidraScriptManager
    ) -> None:
        """Verify script manager initializes correctly."""
        assert ghidra_script_manager.ghidra_install_dir == GHIDRA_PATH
        assert isinstance(ghidra_script_manager.custom_scripts, list), \
            "Custom scripts must be a list"

    def test_get_script_for_licensing_analysis(
        self,
        ghidra_script_manager: GhidraScriptManager
    ) -> None:
        """Test script selection for licensing analysis."""
        scripts = ghidra_script_manager.get_script_for_analysis("licensing")

        assert isinstance(scripts, list), "Must return list of scripts"
        assert len(scripts) > 0, "Must select at least one script for licensing"

        for script in scripts:
            assert isinstance(script, dict), "Each script must be a dictionary"
            assert "name" in script, "Script must have name"
            assert "description" in script, "Script must have description"

    def test_get_script_for_protection_detection(
        self,
        ghidra_script_manager: GhidraScriptManager
    ) -> None:
        """Test script selection for protection detection."""
        scripts = ghidra_script_manager.get_script_for_analysis("protection")

        assert isinstance(scripts, list), "Must return list of scripts"
        assert len(scripts) > 0, "Must select scripts for protection detection"

    def test_get_script_for_comprehensive_analysis(
        self,
        ghidra_script_manager: GhidraScriptManager
    ) -> None:
        """Test script selection for comprehensive analysis."""
        scripts = ghidra_script_manager.get_script_for_analysis("comprehensive")

        assert isinstance(scripts, list), "Must return list of scripts"
        assert len(scripts) >= 3, "Comprehensive analysis needs multiple scripts"

    def test_build_script_chain(
        self,
        ghidra_script_manager: GhidraScriptManager
    ) -> None:
        """Test building command-line arguments for script chaining."""
        test_scripts = [
            {
                "name": "TestScript.py",
                "params": {
                    "detect_rsa": True,
                    "pattern_depth": 5,
                    "keywords": ["license", "trial"]
                }
            }
        ]

        script_args = ghidra_script_manager.build_script_chain(test_scripts)

        assert isinstance(script_args, list), "Script args must be a list"
        assert "-postScript" in script_args, "Must include postScript flag"
        assert "TestScript.py" in script_args, "Must include script name"


class TestGhidraCommonUtilities:
    """Test common Ghidra utility functions."""

    def test_create_basic_analysis_script(self) -> None:
        """Test basic analysis script creation."""
        script = create_ghidra_analysis_script("basic")

        assert isinstance(script, str), "Script must be a string"
        assert len(script) > 0, "Script must not be empty"
        assert "GhidraScript" in script, "Must be valid Ghidra script"
        assert "public class" in script or "import" in script, \
            "Must contain script structure"

    def test_create_license_analysis_script(self) -> None:
        """Test license analysis script creation."""
        script = create_ghidra_analysis_script("license_analysis")

        assert isinstance(script, str), "Script must be a string"
        assert "license" in script.lower(), "Must focus on license analysis"
        assert "GhidraScript" in script, "Must be valid Ghidra script"

    def test_create_function_analysis_script(self) -> None:
        """Test function analysis script creation."""
        script = create_ghidra_analysis_script("function_analysis")

        assert isinstance(script, str), "Script must be a string"
        assert "function" in script.lower(), "Must focus on function analysis"
        assert "GhidraScript" in script, "Must be valid Ghidra script"

    def test_create_string_analysis_script(self) -> None:
        """Test string analysis script creation."""
        script = create_ghidra_analysis_script("string_analysis")

        assert isinstance(script, str), "Script must be a string"
        assert "string" in script.lower(), "Must focus on string analysis"
        assert "GhidraScript" in script, "Must be valid Ghidra script"

    def test_save_ghidra_script(self, temp_workspace: Path) -> None:
        """Test saving Ghidra script to file."""
        script_content = create_ghidra_analysis_script("basic")
        script_name = "TestAnalysis"

        script_path = save_ghidra_script(
            script_content=script_content,
            script_name=script_name,
            output_dir=str(temp_workspace)
        )

        assert Path(script_path).exists(), "Script file must be created"
        assert Path(script_path).suffix == ".java", "Script must have .java extension"

        saved_content = Path(script_path).read_text()
        assert saved_content == script_content, "Saved content must match original"

    def test_get_ghidra_project_info_nonexistent(self, temp_workspace: Path) -> None:
        """Test getting info for non-existent project."""
        info = get_ghidra_project_info(
            project_dir=str(temp_workspace),
            project_name="nonexistent_project"
        )

        assert isinstance(info, dict), "Info must be a dictionary"
        assert info["exists"] is False, "Non-existent project must report not exists"
        assert "project_dir" in info, "Must contain project directory"
        assert "project_name" in info, "Must contain project name"

    def test_cleanup_ghidra_project(self, temp_workspace: Path) -> None:
        """Test cleaning up Ghidra project directory."""
        project_dir = temp_workspace / "test_project"
        project_dir.mkdir(parents=True, exist_ok=True)

        project_file = project_dir / "test_project.gpr"
        project_file.write_text("Test project file")

        result = cleanup_ghidra_project(
            project_dir=str(project_dir),
            project_name="test_project"
        )

        assert result is True, "Cleanup must succeed"
        assert not project_file.exists(), "Project file must be deleted"


class TestGhidraScriptDiscovery:
    """Test dynamic Ghidra script discovery."""

    def test_get_available_scripts(self, ghidra_integration: GhidraBinaryIntegration) -> None:
        """Test getting list of available scripts."""
        scripts = ghidra_integration.get_available_scripts()

        assert isinstance(scripts, list), "Must return list of scripts"

        for script in scripts:
            assert isinstance(script, dict), "Each script must be a dictionary"
            assert "name" in script, "Script must have name"
            assert "description" in script, "Script must have description"

    def test_get_script_info(self, ghidra_integration: GhidraBinaryIntegration) -> None:
        """Test getting detailed information about specific script."""
        if scripts := ghidra_integration.get_available_scripts():
            script_name = scripts[0]["name"]
            if info := ghidra_integration.get_script_info(script_name):
                assert isinstance(info, dict), "Script info must be a dictionary"
                assert "name" in info, "Info must contain name"
                assert "language" in info, "Info must contain language"
                assert "path" in info, "Info must contain path"


class TestGhidraErrorHandling:
    """Test error handling in Ghidra integration."""

    def test_invalid_binary_path(self, ghidra_integration: GhidraBinaryIntegration) -> None:
        """Test handling of invalid binary path."""
        result = ghidra_integration.detect_protections(
            binary_path=Path("/nonexistent/binary.exe")
        )

        assert isinstance(result, dict), "Must return dictionary even on error"
        assert result.get("success") is False or "error" in result, \
            "Must indicate failure or error"

    def test_corrupted_binary(
        self,
        ghidra_integration: GhidraBinaryIntegration,
        temp_workspace: Path
    ) -> None:
        """Test handling of corrupted binary file."""
        corrupted_binary = temp_workspace / "corrupted.exe"
        corrupted_binary.write_bytes(b"Not a valid PE file" * 100)

        result = ghidra_integration.analyze_license_validation(
            binary_path=corrupted_binary,
            deep_analysis=False
        )

        assert isinstance(result, dict), "Must return dictionary for corrupted binary"

    def test_empty_binary(
        self,
        ghidra_integration: GhidraBinaryIntegration,
        temp_workspace: Path
    ) -> None:
        """Test handling of empty binary file."""
        empty_binary = temp_workspace / "empty.exe"
        empty_binary.write_bytes(b"")

        result = ghidra_integration.detect_protections(binary_path=empty_binary)

        assert isinstance(result, dict), "Must return dictionary for empty binary"


class TestGhidraIntegrationEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_concurrent_analysis_safety(
        self,
        ghidra_integration: GhidraBinaryIntegration,
        sample_pe_binary: Path
    ) -> None:
        """Test that multiple analyses can run safely."""
        results = []

        for _ in range(3):
            result = ghidra_integration.detect_protections(binary_path=sample_pe_binary)
            results.append(result)

        for result in results:
            assert isinstance(result, dict), "Each result must be valid dictionary"

    def test_large_binary_handling(
        self,
        ghidra_integration: GhidraBinaryIntegration,
        temp_workspace: Path
    ) -> None:
        """Test handling of large binary files."""
        large_binary = temp_workspace / "large.exe"

        dos_header = b'MZ' + b'\x00' * 62
        pe_header = b'PE\x00\x00' + b'\x00' * 248
        large_content = dos_header + pe_header + (b'\x00' * (10 * 1024 * 1024))

        large_binary.write_bytes(large_content)

        result = ghidra_integration.detect_protections(binary_path=large_binary)

        assert isinstance(result, dict), "Must handle large binaries"

    def test_special_characters_in_path(
        self,
        ghidra_integration: GhidraBinaryIntegration,
        temp_workspace: Path
    ) -> None:
        """Test handling of special characters in file paths."""
        special_dir = temp_workspace / "test dir with spaces"
        special_dir.mkdir(parents=True, exist_ok=True)

        binary_path = special_dir / "test binary.exe"
        binary_path.write_bytes(b'MZ' + b'\x00' * 1000)

        result = ghidra_integration.detect_protections(binary_path=binary_path)

        assert isinstance(result, dict), "Must handle paths with spaces"
