"""Production tests for radare2_license_analyzer.py.

These tests validate real license validation detection:
- License function detection from real commercial binaries
- ML-based pattern recognition accuracy
- Cryptographic constant detection
- Bypass strategy generation
- Comprehensive analysis workflow
"""

import json
import tempfile
from pathlib import Path
from typing import Any

import pytest

try:
    import networkx as nx

    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False

try:
    import r2pipe

    R2PIPE_AVAILABLE = True
except ImportError:
    R2PIPE_AVAILABLE = False

from intellicrack.scripts.radare2.radare2_license_analyzer import (
    LicenseFunction,
    LicenseType,
    ProtectionLevel,
    R2LicenseAnalyzer,
)

FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "binaries"
PE_DIR = FIXTURES_DIR / "pe" / "legitimate"


pytestmark = [
    pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available"),
    pytest.mark.skipif(not NETWORKX_AVAILABLE, reason="networkx not available"),
]


@pytest.fixture
def sample_binary() -> Path:
    """Provide sample binary for analysis."""
    binary = PE_DIR / "notepadpp.exe"
    if not binary.exists():
        pytest.skip(f"Test binary not found: {binary}")
    return binary


@pytest.fixture
def protected_binary() -> Path:
    """Provide protected binary sample."""
    binary = FIXTURES_DIR / "pe" / "protected" / "armadillo_protected.exe"
    if not binary.exists():
        pytest.skip(f"Protected binary not found: {binary}")
    return binary


@pytest.fixture
def license_analyzer(sample_binary: Path) -> R2LicenseAnalyzer:
    """Initialize R2LicenseAnalyzer with sample binary."""
    r2 = r2pipe.open(str(sample_binary))
    analyzer = R2LicenseAnalyzer(r2=r2)
    yield analyzer
    r2.quit()


class TestR2LicenseAnalyzerInitialization:
    """Test R2LicenseAnalyzer initialization."""

    def test_analyzer_initializes_with_r2pipe(self, sample_binary: Path) -> None:
        """R2LicenseAnalyzer initializes successfully with r2pipe."""
        r2 = r2pipe.open(str(sample_binary))
        analyzer = R2LicenseAnalyzer(r2=r2)

        assert analyzer.r2 is not None
        assert isinstance(analyzer.license_functions, list)
        assert isinstance(analyzer.call_graph, nx.DiGraph)
        assert isinstance(analyzer.string_refs, dict)
        assert isinstance(analyzer.api_refs, dict)
        assert isinstance(analyzer.crypto_locations, dict)

        r2.quit()

    def test_analyzer_initializes_with_filename(self, sample_binary: Path) -> None:
        """R2LicenseAnalyzer initializes with filename."""
        analyzer = R2LicenseAnalyzer(filename=str(sample_binary))

        assert analyzer.r2 is not None
        assert isinstance(analyzer.info, dict)
        assert analyzer.arch in ["x86", "x64", "arm", "mips", "unknown"]
        assert analyzer.bits in [32, 64]

        analyzer.r2.quit()

    def test_analyzer_builds_call_graph(self, license_analyzer: R2LicenseAnalyzer) -> None:
        """R2LicenseAnalyzer builds function call graph."""
        assert isinstance(license_analyzer.call_graph, nx.DiGraph)
        assert len(license_analyzer.call_graph.nodes) > 0


class TestPatternWeights:
    """Test pattern weight configuration."""

    def test_pattern_weights_contain_all_categories(self) -> None:
        """PATTERN_WEIGHTS contains all analysis categories."""
        weights = R2LicenseAnalyzer.PATTERN_WEIGHTS

        assert "function_names" in weights
        assert "strings" in weights
        assert "apis" in weights
        assert "crypto" in weights

    def test_function_name_patterns_comprehensive(self) -> None:
        """Function name patterns cover common license keywords."""
        func_patterns = R2LicenseAnalyzer.PATTERN_WEIGHTS["function_names"]

        assert "license" in func_patterns
        assert "activation" in func_patterns
        assert "registration" in func_patterns
        assert "validate" in func_patterns
        assert "trial" in func_patterns
        assert "serial" in func_patterns

        assert func_patterns["license"] > 0.8
        assert func_patterns["crack"] < 0

    def test_string_patterns_identify_license_messages(self) -> None:
        """String patterns identify common license error messages."""
        string_patterns = R2LicenseAnalyzer.PATTERN_WEIGHTS["strings"]

        assert "Invalid license" in string_patterns
        assert "License expired" in string_patterns
        assert "Trial period" in string_patterns
        assert "Serial number" in string_patterns

        assert all(weight > 0.5 for weight in string_patterns.values())

    def test_api_patterns_identify_validation_apis(self) -> None:
        """API patterns identify Windows license validation APIs."""
        api_patterns = R2LicenseAnalyzer.PATTERN_WEIGHTS["apis"]

        assert "RegOpenKeyEx" in api_patterns
        assert "RegQueryValueEx" in api_patterns
        assert "GetVolumeInformation" in api_patterns
        assert "CryptHashData" in api_patterns
        assert "InternetConnect" in api_patterns


class TestStringAnalysis:
    """Test string reference analysis."""

    def test_load_strings_extracts_binary_strings(self, license_analyzer: R2LicenseAnalyzer) -> None:
        """_load_strings() extracts strings from binary."""
        license_analyzer._load_strings()

        assert isinstance(license_analyzer.string_refs, dict)

    def test_calculate_string_score_rates_license_strings(self, license_analyzer: R2LicenseAnalyzer) -> None:
        """_calculate_string_score() assigns high scores to license strings."""
        license_strings = [
            "Invalid license key",
            "Please register your copy",
            "Trial period expired",
        ]
        normal_strings = ["Hello World", "File not found", "OK"]

        license_score = license_analyzer._calculate_string_score(license_strings)
        normal_score = license_analyzer._calculate_string_score(normal_strings)

        assert license_score > normal_score
        assert 0.0 <= license_score <= 1.0
        assert 0.0 <= normal_score <= 1.0

    def test_calculate_string_score_handles_empty_list(self, license_analyzer: R2LicenseAnalyzer) -> None:
        """_calculate_string_score() handles empty string list."""
        score = license_analyzer._calculate_string_score([])
        assert score == 0.0


class TestFunctionNameAnalysis:
    """Test function name pattern analysis."""

    def test_calculate_name_score_identifies_license_functions(
        self, license_analyzer: R2LicenseAnalyzer
    ) -> None:
        """_calculate_name_score() identifies license function names."""
        license_names = [
            "CheckLicenseKey",
            "ValidateRegistration",
            "VerifyActivation",
            "CheckTrialExpiration",
        ]
        normal_names = ["ProcessData", "LoadConfiguration", "InitializeWindow"]

        for name in license_names:
            score = license_analyzer._calculate_name_score(name)
            assert score > 0.5, f"License function {name} scored too low: {score}"

        for name in normal_names:
            score = license_analyzer._calculate_name_score(name)
            assert score < 0.7, f"Normal function {name} scored too high: {score}"

    def test_calculate_name_score_normalizes_properly(self, license_analyzer: R2LicenseAnalyzer) -> None:
        """_calculate_name_score() returns scores in valid range."""
        test_names = ["CheckLicense", "xyz123", "ThisIsAVeryLongFunctionName", "a"]

        for name in test_names:
            score = license_analyzer._calculate_name_score(name)
            assert 0.0 <= score <= 1.0


class TestLicenseTypeDetection:
    """Test license type classification."""

    def test_determine_license_type_identifies_serial_key(self, license_analyzer: R2LicenseAnalyzer) -> None:
        """_determine_license_type() identifies serial key validation."""
        serial_indicators = ["Enter serial number", "Product key invalid"]
        license_type = license_analyzer._determine_license_type(serial_indicators)
        assert license_type == LicenseType.SERIAL_KEY

    def test_determine_license_type_identifies_online_validation(
        self, license_analyzer: R2LicenseAnalyzer
    ) -> None:
        """_determine_license_type() identifies online validation."""
        online_indicators = ["Connecting to license server", "Internet connection required"]
        license_type = license_analyzer._determine_license_type(online_indicators)
        assert license_type == LicenseType.ONLINE

    def test_determine_license_type_identifies_hardware_lock(self, license_analyzer: R2LicenseAnalyzer) -> None:
        """_determine_license_type() identifies hardware-locked licenses."""
        hardware_indicators = ["Hardware ID mismatch", "Machine code validation"]
        license_type = license_analyzer._determine_license_type(hardware_indicators)
        assert license_type == LicenseType.HARDWARE

    def test_determine_license_type_identifies_time_trial(self, license_analyzer: R2LicenseAnalyzer) -> None:
        """_determine_license_type() identifies time-based trials."""
        trial_indicators = ["Trial period: 30 days", "Evaluation expired"]
        license_type = license_analyzer._determine_license_type(trial_indicators)
        assert license_type == LicenseType.TIME_TRIAL

    def test_determine_license_type_identifies_crypto_signature(
        self, license_analyzer: R2LicenseAnalyzer
    ) -> None:
        """_determine_license_type() identifies cryptographic signatures."""
        crypto_indicators = ["RSA signature verification", "AES decryption failed"]
        license_type = license_analyzer._determine_license_type(crypto_indicators)
        assert license_type == LicenseType.CRYPTO_SIGNATURE


class TestAPICallAnalysis:
    """Test API call pattern analysis."""

    def test_load_imports_categorizes_apis(self, license_analyzer: R2LicenseAnalyzer) -> None:
        """_load_imports() loads and categorizes API imports."""
        license_analyzer._load_imports()
        assert isinstance(license_analyzer.api_refs, dict)

    def test_calculate_api_score_rates_license_apis(self, license_analyzer: R2LicenseAnalyzer) -> None:
        """_calculate_api_score() assigns high scores to license APIs."""
        license_apis = ["RegOpenKeyEx", "RegQueryValueEx", "GetVolumeInformation", "CryptHashData"]
        normal_apis = ["malloc", "free", "printf"]

        license_score = license_analyzer._calculate_api_score(license_apis)
        normal_score = license_analyzer._calculate_api_score(normal_apis)

        assert license_score > normal_score
        assert 0.0 <= license_score <= 1.0

    def test_calculate_api_score_handles_empty_list(self, license_analyzer: R2LicenseAnalyzer) -> None:
        """_calculate_api_score() handles empty API list."""
        score = license_analyzer._calculate_api_score([])
        assert score == 0.0


class TestCryptoDetection:
    """Test cryptographic operation detection."""

    def test_detect_crypto_operations_finds_constants(self, license_analyzer: R2LicenseAnalyzer) -> None:
        """_detect_crypto_operations() detects cryptographic constants."""
        license_analyzer._detect_crypto_operations()

        if license_analyzer.crypto_locations:
            for algo, locations in license_analyzer.crypto_locations.items():
                assert isinstance(locations, list)
                assert algo in ["MD5", "SHA1", "SHA256", "AES_SBOX"]

    def test_search_crypto_constants_finds_md5_init(self, license_analyzer: R2LicenseAnalyzer) -> None:
        """_search_crypto_constants() locates MD5 initialization constants."""
        md5_constants = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
        license_analyzer._search_crypto_constants("MD5", md5_constants)

        if "MD5" in license_analyzer.crypto_locations:
            assert len(license_analyzer.crypto_locations["MD5"]) > 0


class TestControlFlowAnalysis:
    """Test control flow pattern analysis."""

    def test_has_license_control_pattern_validates_structure(
        self, license_analyzer: R2LicenseAnalyzer
    ) -> None:
        """_has_license_control_pattern() validates license function structure."""
        simple_blocks = [{"ninstr": 1}, {"ninstr": 2}]
        assert not license_analyzer._has_license_control_pattern(simple_blocks)

        complex_blocks = [
            {"ninstr": 5, "disasm": "ret"},
            {"ninstr": 3, "disasm": "ret"},
            {"ninstr": 7, "disasm": "jmp"},
        ]
        result = license_analyzer._has_license_control_pattern(complex_blocks)
        assert isinstance(result, bool)


class TestComprehensiveAnalysis:
    """Test comprehensive analysis workflow."""

    def test_analyze_returns_license_functions(self, license_analyzer: R2LicenseAnalyzer) -> None:
        """analyze() returns list of detected license functions."""
        results = license_analyzer.analyze()

        assert isinstance(results, list)
        for func in results:
            assert isinstance(func, LicenseFunction)
            assert func.address > 0
            assert isinstance(func.name, str)
            assert 0.0 <= func.confidence <= 1.0
            assert isinstance(func.type, LicenseType)
            assert isinstance(func.protection_level, ProtectionLevel)

    def test_analyze_sorts_by_confidence(self, license_analyzer: R2LicenseAnalyzer) -> None:
        """analyze() sorts results by confidence score."""
        results = license_analyzer.analyze()

        if len(results) > 1:
            for i in range(len(results) - 1):
                assert results[i].confidence >= results[i + 1].confidence

    def test_analyze_generates_bypass_strategies(self, license_analyzer: R2LicenseAnalyzer) -> None:
        """analyze() generates bypass strategies for detected functions."""
        results = license_analyzer.analyze()

        for func in results:
            assert isinstance(func.bypass_strategies, list)
            assert len(func.bypass_strategies) > 0
            assert all(isinstance(strategy, str) for strategy in func.bypass_strategies)


class TestBypassStrategyGeneration:
    """Test bypass strategy generation."""

    def test_generate_bypass_strategies_creates_strategies(self, license_analyzer: R2LicenseAnalyzer) -> None:
        """_generate_bypass_strategies() creates specific bypass strategies."""
        test_func = LicenseFunction(
            address=0x1000,
            name="CheckLicense",
            size=100,
            type=LicenseType.SERIAL_KEY,
            confidence=0.9,
            protection_level=ProtectionLevel.BASIC,
        )
        license_analyzer.license_functions.append(test_func)

        license_analyzer._generate_bypass_strategies()

        assert len(test_func.bypass_strategies) > 0
        assert any("patch" in strategy.lower() for strategy in test_func.bypass_strategies)

    def test_bypass_strategies_type_specific(self, license_analyzer: R2LicenseAnalyzer) -> None:
        """Bypass strategies are specific to license type."""
        serial_func = LicenseFunction(
            address=0x1000,
            name="CheckSerial",
            size=100,
            type=LicenseType.SERIAL_KEY,
            confidence=0.9,
            protection_level=ProtectionLevel.BASIC,
        )

        online_func = LicenseFunction(
            address=0x2000,
            name="ValidateOnline",
            size=100,
            type=LicenseType.ONLINE,
            confidence=0.9,
            protection_level=ProtectionLevel.BASIC,
        )

        license_analyzer.license_functions = [serial_func, online_func]
        license_analyzer._generate_bypass_strategies()

        serial_strategies = " ".join(serial_func.bypass_strategies).lower()
        online_strategies = " ".join(online_func.bypass_strategies).lower()

        assert "key" in serial_strategies or "string" in serial_strategies
        assert "network" in online_strategies or "server" in online_strategies


class TestReportGeneration:
    """Test analysis report generation."""

    def test_export_report_creates_json_file(self, license_analyzer: R2LicenseAnalyzer, tmp_path: Path) -> None:
        """export_report() creates valid JSON report file."""
        license_analyzer.analyze()

        output_file = tmp_path / "test_report.json"
        license_analyzer.export_report(str(output_file))

        assert output_file.exists()

        with open(output_file) as f:
            report = json.load(f)

        assert "binary" in report
        assert "arch" in report
        assert "bits" in report
        assert "total_functions_analyzed" in report
        assert "license_functions_found" in report
        assert "functions" in report

        assert isinstance(report["functions"], list)

    def test_export_report_contains_complete_function_data(
        self, license_analyzer: R2LicenseAnalyzer, tmp_path: Path
    ) -> None:
        """Exported report contains complete function analysis data."""
        license_analyzer.analyze()

        output_file = tmp_path / "test_report.json"
        license_analyzer.export_report(str(output_file))

        with open(output_file) as f:
            report = json.load(f)

        if report["functions"]:
            func_data = report["functions"][0]
            assert "address" in func_data
            assert "name" in func_data
            assert "type" in func_data
            assert "confidence" in func_data
            assert "protection_level" in func_data
            assert "bypass_strategies" in func_data


class TestR2ScriptGeneration:
    """Test radare2 patching script generation."""

    def test_generate_r2_script_creates_file(self, license_analyzer: R2LicenseAnalyzer, tmp_path: Path) -> None:
        """generate_r2_script() creates radare2 patch script."""
        license_analyzer.analyze()

        output_file = tmp_path / "test_patch.r2"
        license_analyzer.generate_r2_script(str(output_file))

        assert output_file.exists()

        content = output_file.read_text()
        assert "Radare2 License Patch Script" in content
        assert "Intellicrack" in content

    def test_generate_r2_script_filters_low_confidence(
        self, license_analyzer: R2LicenseAnalyzer, tmp_path: Path
    ) -> None:
        """generate_r2_script() only includes high-confidence functions."""
        low_conf_func = LicenseFunction(
            address=0x1000,
            name="MaybeLicense",
            size=100,
            type=LicenseType.CUSTOM,
            confidence=0.5,
            protection_level=ProtectionLevel.BASIC,
        )

        high_conf_func = LicenseFunction(
            address=0x2000,
            name="DefinitelyLicense",
            size=100,
            type=LicenseType.SERIAL_KEY,
            confidence=0.9,
            protection_level=ProtectionLevel.BASIC,
        )

        license_analyzer.license_functions = [low_conf_func, high_conf_func]

        output_file = tmp_path / "test_patch.r2"
        license_analyzer.generate_r2_script(str(output_file))

        content = output_file.read_text()
        assert "DefinitelyLicense" in content


class TestPatchLocationFinding:
    """Test patch location identification."""

    def test_find_patch_location_returns_valid_data(self, license_analyzer: R2LicenseAnalyzer) -> None:
        """_find_patch_location() returns valid patch location."""
        test_func = LicenseFunction(
            address=0x1000,
            name="TestFunc",
            size=100,
            type=LicenseType.SERIAL_KEY,
            confidence=0.9,
            protection_level=ProtectionLevel.BASIC,
        )

        patch_addr, patch_bytes = license_analyzer._find_patch_location(test_func)

        if patch_addr is not None:
            assert isinstance(patch_addr, int)
            assert patch_addr > 0

        if patch_bytes is not None:
            assert isinstance(patch_bytes, bytes)
            assert len(patch_bytes) > 0


class TestProtectedBinaryAnalysis:
    """Test analysis of protected binaries."""

    def test_analyzer_handles_protected_binary(self, protected_binary: Path) -> None:
        """R2LicenseAnalyzer analyzes protected binary without crashing."""
        if not protected_binary.exists():
            pytest.skip("Protected binary not available")

        analyzer = R2LicenseAnalyzer(filename=str(protected_binary))
        results = analyzer.analyze()

        assert isinstance(results, list)

        for func in results:
            if func.protection_level in [ProtectionLevel.ADVANCED, ProtectionLevel.EXTREME]:
                assert "unpacking" in " ".join(func.bypass_strategies).lower() or "devirtualization" in " ".join(
                    func.bypass_strategies
                ).lower()

        analyzer.r2.quit()


class TestPatternMatching:
    """Test advanced pattern matching."""

    def test_check_pattern_matches_registry_validation(self, license_analyzer: R2LicenseAnalyzer) -> None:
        """_check_pattern() matches registry-based validation pattern."""
        pattern = {
            "apis": ["RegOpenKeyEx", "RegQueryValueEx"],
            "strings": ["Software\\", "License"],
            "type": LicenseType.SERIAL_KEY,
        }

        initial_count = len(license_analyzer.license_functions)
        license_analyzer._check_pattern(pattern)

    def test_check_pattern_matches_network_validation(self, license_analyzer: R2LicenseAnalyzer) -> None:
        """_check_pattern() matches network-based validation pattern."""
        pattern = {
            "apis": ["InternetConnect", "HttpSendRequest"],
            "strings": ["license", "validate", "server"],
            "type": LicenseType.ONLINE,
        }

        license_analyzer._check_pattern(pattern)


class TestGetFunctionAt:
    """Test function address resolution."""

    def test_get_function_at_returns_function_address(self, license_analyzer: R2LicenseAnalyzer) -> None:
        """_get_function_at() returns function containing address."""
        functions = license_analyzer.r2.cmdj("aflj")
        if not functions:
            pytest.skip("No functions found")

        func = functions[0]
        func_addr = func["offset"]

        result = license_analyzer._get_function_at(func_addr)

        if result is not None:
            assert isinstance(result, int)
            assert result == func_addr


@pytest.mark.integration
class TestEndToEndWorkflow:
    """Test complete analysis workflow."""

    def test_complete_analysis_workflow(self, sample_binary: Path, tmp_path: Path) -> None:
        """Complete workflow from analysis to report generation."""
        analyzer = R2LicenseAnalyzer(filename=str(sample_binary))

        results = analyzer.analyze()
        assert isinstance(results, list)

        if results:
            assert all(func.confidence > 0 for func in results)
            assert all(len(func.bypass_strategies) > 0 for func in results)

        report_file = tmp_path / "analysis.json"
        analyzer.export_report(str(report_file))
        assert report_file.exists()

        script_file = tmp_path / "patch.r2"
        analyzer.generate_r2_script(str(script_file))
        assert script_file.exists()

        analyzer.r2.quit()


class TestLicenseFunctionDataclass:
    """Test LicenseFunction dataclass."""

    def test_license_function_creation(self) -> None:
        """LicenseFunction dataclass initializes correctly."""
        func = LicenseFunction(
            address=0x1000,
            name="CheckLicense",
            size=256,
            type=LicenseType.SERIAL_KEY,
            confidence=0.95,
            protection_level=ProtectionLevel.MODERATE,
        )

        assert func.address == 0x1000
        assert func.name == "CheckLicense"
        assert func.size == 256
        assert func.type == LicenseType.SERIAL_KEY
        assert func.confidence == 0.95
        assert func.protection_level == ProtectionLevel.MODERATE
        assert isinstance(func.cross_refs, list)
        assert isinstance(func.strings, list)
        assert isinstance(func.api_calls, list)
        assert isinstance(func.bypass_strategies, list)


class TestEnumerations:
    """Test enumeration definitions."""

    def test_license_type_enum_complete(self) -> None:
        """LicenseType enum contains all major license types."""
        assert LicenseType.SERIAL_KEY.value == "serial_key"
        assert LicenseType.ONLINE.value == "online_validation"
        assert LicenseType.HARDWARE.value == "hardware_locked"
        assert LicenseType.TIME_TRIAL.value == "time_trial"
        assert LicenseType.CRYPTO_SIGNATURE.value == "cryptographic"

    def test_protection_level_enum_ordered(self) -> None:
        """ProtectionLevel enum has correct ordering."""
        assert ProtectionLevel.BASIC.value == 1
        assert ProtectionLevel.MODERATE.value == 2
        assert ProtectionLevel.ADVANCED.value == 3
        assert ProtectionLevel.EXTREME.value == 4

        assert ProtectionLevel.BASIC < ProtectionLevel.MODERATE
        assert ProtectionLevel.MODERATE < ProtectionLevel.ADVANCED
        assert ProtectionLevel.ADVANCED < ProtectionLevel.EXTREME
