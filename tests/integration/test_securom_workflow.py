"""Integration tests for complete SecuROM workflow.

Tests end-to-end workflow from detection through analysis to bypass using real
SecuROM-protected binaries and actual protection analysis capabilities.
"""

import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

from intellicrack.core.analysis.securom_analyzer import SecuROMAnalyzer, SecuROMAnalysis
from intellicrack.core.protection_bypass.securom_bypass import (
    BypassResult,
    SecuROMBypass,
    SecuROMRemovalResult,
)
from intellicrack.core.protection_detection.securom_detector import (
    SecuROMActivation,
    SecuROMDetection,
    SecuROMDetector,
    SecuROMVersion,
)


class TestSecuROMCompleteWorkflow:
    """Integration tests for complete SecuROM cracking workflow."""

    @pytest.fixture
    def securom_binary(self) -> Path:
        """Provide path to SecuROM protected test binary."""
        binary_path = Path(__file__).parent.parent / "fixtures" / "binaries" / "pe" / "protected" / "securom_protected.exe"
        assert binary_path.exists(), f"SecuROM test binary not found at {binary_path}"
        return binary_path

    @pytest.fixture
    def temp_working_dir(self) -> Generator[Path, None, None]:
        """Provide temporary directory for test operations."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def detector(self) -> SecuROMDetector:
        """Provide initialized SecuROM detector."""
        return SecuROMDetector()

    @pytest.fixture
    def analyzer(self) -> SecuROMAnalyzer:
        """Provide initialized SecuROM analyzer."""
        return SecuROMAnalyzer()

    @pytest.fixture
    def bypass(self) -> SecuROMBypass:
        """Provide initialized SecuROM bypass system."""
        return SecuROMBypass()

    def test_detection_to_analysis_workflow(
        self, securom_binary: Path, detector: SecuROMDetector, analyzer: SecuROMAnalyzer
    ) -> None:
        """Test workflow from detection to analysis on real SecuROM binary."""
        detection_result: SecuROMDetection = detector.detect(securom_binary)

        assert isinstance(detection_result, SecuROMDetection)
        assert detection_result.confidence >= 0.0
        assert isinstance(detection_result.drivers, list)
        assert isinstance(detection_result.services, list)
        assert isinstance(detection_result.registry_keys, list)
        assert isinstance(detection_result.protected_sections, list)

        if detection_result.version is not None:
            assert isinstance(detection_result.version, SecuROMVersion)
            assert detection_result.version.major in [7, 8]

        if detection_result.activation_state is not None:
            assert isinstance(detection_result.activation_state, SecuROMActivation)
            assert isinstance(detection_result.activation_state.is_activated, bool)
            assert isinstance(detection_result.activation_state.activation_count, int)

        analysis_result: SecuROMAnalysis = analyzer.analyze(securom_binary)

        assert isinstance(analysis_result, SecuROMAnalysis)
        assert analysis_result.target_path == securom_binary
        assert isinstance(analysis_result.version, str)
        assert isinstance(analysis_result.activation_mechanisms, list)
        assert isinstance(analysis_result.trigger_points, list)
        assert isinstance(analysis_result.product_keys, list)
        assert isinstance(analysis_result.disc_auth_routines, list)
        assert isinstance(analysis_result.phone_home_mechanisms, list)
        assert isinstance(analysis_result.challenge_response_flows, list)
        assert isinstance(analysis_result.license_validation_functions, list)
        assert isinstance(analysis_result.encryption_techniques, list)
        assert isinstance(analysis_result.obfuscation_methods, list)
        assert isinstance(analysis_result.details, dict)

    def test_detection_to_bypass_workflow(
        self, securom_binary: Path, detector: SecuROMDetector, bypass: SecuROMBypass
    ) -> None:
        """Test workflow from detection to bypass on real SecuROM binary."""
        detection_result: SecuROMDetection = detector.detect(securom_binary)

        assert isinstance(detection_result, SecuROMDetection)
        assert isinstance(detection_result.drivers, list)
        assert isinstance(detection_result.services, list)
        assert isinstance(detection_result.registry_keys, list)

        if detection_result.activation_state is not None:
            assert isinstance(detection_result.activation_state, SecuROMActivation)

        bypass_result: SecuROMRemovalResult = bypass.remove_securom()

        assert isinstance(bypass_result, SecuROMRemovalResult)
        assert isinstance(bypass_result.drivers_removed, list)
        assert isinstance(bypass_result.services_stopped, list)
        assert isinstance(bypass_result.registry_cleaned, list)
        assert isinstance(bypass_result.files_deleted, list)
        assert isinstance(bypass_result.activation_bypassed, bool)
        assert isinstance(bypass_result.triggers_removed, int)
        assert isinstance(bypass_result.success, bool)
        assert isinstance(bypass_result.errors, list)

    def test_analysis_to_bypass_workflow(
        self, securom_binary: Path, temp_working_dir: Path, analyzer: SecuROMAnalyzer, bypass: SecuROMBypass
    ) -> None:
        """Test workflow from analysis to bypass on real SecuROM binary."""
        analysis_result: SecuROMAnalysis = analyzer.analyze(securom_binary)

        assert isinstance(analysis_result, SecuROMAnalysis)
        assert len(analysis_result.trigger_points) >= 0

        import shutil

        test_binary: Path = temp_working_dir / "test_securom.exe"
        shutil.copy2(securom_binary, test_binary)

        bypass_result: BypassResult = bypass.bypass_activation(test_binary)

        assert isinstance(bypass_result, BypassResult)
        assert isinstance(bypass_result.success, bool)
        assert isinstance(bypass_result.technique, str)
        assert bypass_result.technique == "Activation Bypass"
        assert isinstance(bypass_result.details, str)
        assert isinstance(bypass_result.errors, list)

    def test_complete_end_to_end_workflow(
        self,
        securom_binary: Path,
        temp_working_dir: Path,
        detector: SecuROMDetector,
        analyzer: SecuROMAnalyzer,
        bypass: SecuROMBypass,
    ) -> None:
        """Test complete end-to-end workflow: detect, analyze, bypass on real binary."""
        detection_result: SecuROMDetection = detector.detect(securom_binary)

        assert isinstance(detection_result, SecuROMDetection)
        assert isinstance(detection_result.drivers, list)
        assert isinstance(detection_result.services, list)
        assert isinstance(detection_result.registry_keys, list)

        if detection_result.version is not None:
            assert isinstance(detection_result.version, SecuROMVersion)
            assert detection_result.version.major in [7, 8]

        analysis_result: SecuROMAnalysis = analyzer.analyze(securom_binary)

        assert isinstance(analysis_result, SecuROMAnalysis)
        assert isinstance(analysis_result.version, str)
        assert isinstance(analysis_result.activation_mechanisms, list)

        import shutil

        test_binary: Path = temp_working_dir / "test_complete_workflow.exe"
        shutil.copy2(securom_binary, test_binary)

        activation_bypass: BypassResult = bypass.bypass_activation(test_binary)

        assert isinstance(activation_bypass, BypassResult)
        assert isinstance(activation_bypass.success, bool)
        assert isinstance(activation_bypass.errors, list)

        disc_bypass: BypassResult = bypass.bypass_disc_check(test_binary)

        assert isinstance(disc_bypass, BypassResult)
        assert isinstance(disc_bypass.success, bool)
        assert isinstance(disc_bypass.errors, list)

    def test_trigger_identification_and_removal(
        self, securom_binary: Path, temp_working_dir: Path, analyzer: SecuROMAnalyzer, bypass: SecuROMBypass
    ) -> None:
        """Test identification and removal of validation triggers on real binary."""
        analysis_result: SecuROMAnalysis = analyzer.analyze(securom_binary)

        triggers = analysis_result.trigger_points
        assert isinstance(triggers, list)

        for trigger in triggers:
            assert hasattr(trigger, "address")
            assert hasattr(trigger, "trigger_type")
            assert hasattr(trigger, "description")
            assert isinstance(trigger.address, int)
            assert isinstance(trigger.trigger_type, str)

        import shutil

        test_binary: Path = temp_working_dir / "test_trigger_removal.exe"
        shutil.copy2(securom_binary, test_binary)

        bypass_result: BypassResult = bypass.remove_triggers(test_binary)

        assert isinstance(bypass_result, BypassResult)
        assert bypass_result.technique == "Trigger Removal"
        assert isinstance(bypass_result.success, bool)
        assert isinstance(bypass_result.details, str)
        assert isinstance(bypass_result.errors, list)

    def test_product_key_and_challenge_response_bypass(
        self, securom_binary: Path, temp_working_dir: Path, analyzer: SecuROMAnalyzer, bypass: SecuROMBypass
    ) -> None:
        """Test product key and challenge-response bypass on real binary."""
        analysis_result: SecuROMAnalysis = analyzer.analyze(securom_binary)

        product_keys = analysis_result.product_keys
        challenge_flows = analysis_result.challenge_response_flows

        assert isinstance(product_keys, list)
        assert isinstance(challenge_flows, list)

        for key in product_keys:
            assert hasattr(key, "key_format")
            assert hasattr(key, "key_length")
            assert hasattr(key, "validation_algorithm")
            assert isinstance(key.key_format, str)
            assert isinstance(key.key_length, int)

        for flow in challenge_flows:
            assert hasattr(flow, "challenge_generation_addr")
            assert hasattr(flow, "response_validation_addr")
            assert hasattr(flow, "crypto_operations")
            assert isinstance(flow.challenge_generation_addr, int)
            assert isinstance(flow.response_validation_addr, int)

        import shutil

        test_binary: Path = temp_working_dir / "test_key_bypass.exe"
        shutil.copy2(securom_binary, test_binary)

        key_bypass: BypassResult = bypass.bypass_product_key_validation(test_binary)

        assert isinstance(key_bypass, BypassResult)
        assert isinstance(key_bypass.success, bool)
        assert isinstance(key_bypass.errors, list)

        test_binary2: Path = temp_working_dir / "test_challenge_bypass.exe"
        shutil.copy2(securom_binary, test_binary2)

        challenge_bypass: BypassResult = bypass.defeat_challenge_response(test_binary2)

        assert isinstance(challenge_bypass, BypassResult)
        assert isinstance(challenge_bypass.success, bool)
        assert isinstance(challenge_bypass.errors, list)

    def test_phone_home_detection_and_blocking(
        self, securom_binary: Path, temp_working_dir: Path, analyzer: SecuROMAnalyzer, bypass: SecuROMBypass
    ) -> None:
        """Test phone-home detection and blocking on real binary."""
        analysis_result: SecuROMAnalysis = analyzer.analyze(securom_binary)

        phone_home = analysis_result.phone_home_mechanisms
        assert isinstance(phone_home, list)

        server_urls: list[str] = []
        for mechanism in phone_home:
            assert hasattr(mechanism, "mechanism_type")
            assert hasattr(mechanism, "server_urls")
            assert hasattr(mechanism, "protocol")
            assert isinstance(mechanism.mechanism_type, str)
            assert isinstance(mechanism.server_urls, list)
            server_urls.extend(mechanism.server_urls)

        import shutil

        test_binary: Path = temp_working_dir / "test_phone_home_block.exe"
        shutil.copy2(securom_binary, test_binary)

        bypass_result: BypassResult = bypass.block_phone_home(test_binary, server_urls)

        assert isinstance(bypass_result, BypassResult)
        assert isinstance(bypass_result.success, bool)
        assert isinstance(bypass_result.technique, str)
        assert bypass_result.technique == "Phone-Home Blocking"
        assert isinstance(bypass_result.details, str)
        assert isinstance(bypass_result.errors, list)


class TestSecuROMVersionSpecificWorkflows:
    """Test version-specific workflows for SecuROM v7 and v8."""

    @pytest.fixture
    def securom_binary(self) -> Path:
        """Provide path to SecuROM protected test binary."""
        binary_path = Path(__file__).parent.parent / "fixtures" / "binaries" / "pe" / "protected" / "securom_protected.exe"
        assert binary_path.exists(), f"SecuROM test binary not found at {binary_path}"
        return binary_path

    @pytest.fixture
    def detector(self) -> SecuROMDetector:
        """Provide initialized SecuROM detector."""
        return SecuROMDetector()

    @pytest.fixture
    def analyzer(self) -> SecuROMAnalyzer:
        """Provide initialized SecuROM analyzer."""
        return SecuROMAnalyzer()

    def test_securom_detection_workflow(self, securom_binary: Path, detector: SecuROMDetector) -> None:
        """Test detection of SecuROM protection on real binary."""
        result: SecuROMDetection = detector.detect(securom_binary)

        assert isinstance(result, SecuROMDetection)
        assert isinstance(result.confidence, float)
        assert 0.0 <= result.confidence <= 1.0
        assert isinstance(result.drivers, list)
        assert isinstance(result.services, list)
        assert isinstance(result.registry_keys, list)
        assert isinstance(result.protected_sections, list)

        if result.version is not None:
            assert isinstance(result.version, SecuROMVersion)
            assert isinstance(result.version.major, int)
            assert isinstance(result.version.minor, int)
            assert isinstance(result.version.build, int)
            assert isinstance(result.version.variant, str)

    def test_securom_analysis_workflow(self, securom_binary: Path, analyzer: SecuROMAnalyzer) -> None:
        """Test analysis of SecuROM protection on real binary."""
        result: SecuROMAnalysis = analyzer.analyze(securom_binary)

        assert isinstance(result, SecuROMAnalysis)
        assert result.target_path == securom_binary
        assert isinstance(result.version, str)

        assert isinstance(result.activation_mechanisms, list)
        for mechanism in result.activation_mechanisms:
            assert hasattr(mechanism, "activation_type")
            assert hasattr(mechanism, "online_validation")
            assert hasattr(mechanism, "challenge_response")
            assert isinstance(mechanism.activation_type, str)
            assert isinstance(mechanism.online_validation, bool)
            assert isinstance(mechanism.challenge_response, bool)

        assert isinstance(result.details, dict)
        assert "imports" in result.details
        assert "exports" in result.details
        assert isinstance(result.details["imports"], list)
        assert isinstance(result.details["exports"], list)


class TestSecuROMBinaryAnalysisDetails:
    """Test detailed binary analysis capabilities on real SecuROM samples."""

    @pytest.fixture
    def securom_binary(self) -> Path:
        """Provide path to SecuROM protected test binary."""
        binary_path = Path(__file__).parent.parent / "fixtures" / "binaries" / "pe" / "protected" / "securom_protected.exe"
        assert binary_path.exists(), f"SecuROM test binary not found at {binary_path}"
        return binary_path

    @pytest.fixture
    def analyzer(self) -> SecuROMAnalyzer:
        """Provide initialized SecuROM analyzer."""
        return SecuROMAnalyzer()

    def test_activation_mechanism_analysis(self, securom_binary: Path, analyzer: SecuROMAnalyzer) -> None:
        """Test activation mechanism analysis on real binary."""
        result: SecuROMAnalysis = analyzer.analyze(securom_binary)

        assert isinstance(result.activation_mechanisms, list)

        for mechanism in result.activation_mechanisms:
            assert isinstance(mechanism.activation_type, str)
            assert isinstance(mechanism.online_validation, bool)
            assert isinstance(mechanism.challenge_response, bool)
            assert isinstance(mechanism.max_activations, int)
            assert isinstance(mechanism.hardware_binding, list)

            if mechanism.activation_server_url is not None:
                assert isinstance(mechanism.activation_server_url, str)

            if mechanism.encryption_algorithm is not None:
                assert isinstance(mechanism.encryption_algorithm, str)

    def test_disc_authentication_analysis(self, securom_binary: Path, analyzer: SecuROMAnalyzer) -> None:
        """Test disc authentication routine analysis on real binary."""
        result: SecuROMAnalysis = analyzer.analyze(securom_binary)

        assert isinstance(result.disc_auth_routines, list)

        for routine in result.disc_auth_routines:
            assert isinstance(routine.routine_address, int)
            assert isinstance(routine.scsi_commands, list)
            assert isinstance(routine.signature_checks, list)
            assert isinstance(routine.fingerprint_method, str)
            assert isinstance(routine.bypass_difficulty, str)

    def test_license_validation_analysis(self, securom_binary: Path, analyzer: SecuROMAnalyzer) -> None:
        """Test license validation function analysis on real binary."""
        result: SecuROMAnalysis = analyzer.analyze(securom_binary)

        assert isinstance(result.license_validation_functions, list)

        for func in result.license_validation_functions:
            assert isinstance(func.address, int)
            assert isinstance(func.name, str)
            assert isinstance(func.function_type, str)
            assert isinstance(func.checks_performed, list)
            assert isinstance(func.return_values, dict)

    def test_encryption_obfuscation_detection(self, securom_binary: Path, analyzer: SecuROMAnalyzer) -> None:
        """Test encryption and obfuscation detection on real binary."""
        result: SecuROMAnalysis = analyzer.analyze(securom_binary)

        assert isinstance(result.encryption_techniques, list)
        assert isinstance(result.obfuscation_methods, list)

        for technique in result.encryption_techniques:
            assert isinstance(technique, str)

        for method in result.obfuscation_methods:
            assert isinstance(method, str)


class TestSecuROMBypassCapabilities:
    """Test bypass capabilities on real SecuROM binaries."""

    @pytest.fixture
    def securom_binary(self) -> Path:
        """Provide path to SecuROM protected test binary."""
        binary_path = Path(__file__).parent.parent / "fixtures" / "binaries" / "pe" / "protected" / "securom_protected.exe"
        assert binary_path.exists(), f"SecuROM test binary not found at {binary_path}"
        return binary_path

    @pytest.fixture
    def temp_working_dir(self) -> Generator[Path, None, None]:
        """Provide temporary directory for test operations."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def bypass(self) -> SecuROMBypass:
        """Provide initialized SecuROM bypass system."""
        return SecuROMBypass()

    def test_activation_bypass_execution(
        self, securom_binary: Path, temp_working_dir: Path, bypass: SecuROMBypass
    ) -> None:
        """Test activation bypass execution on real binary."""
        import shutil

        test_binary: Path = temp_working_dir / "test_activation.exe"
        shutil.copy2(securom_binary, test_binary)

        result: BypassResult = bypass.bypass_activation(test_binary, "TEST-PRODUCT-ID")

        assert isinstance(result, BypassResult)
        assert result.technique == "Activation Bypass"
        assert isinstance(result.success, bool)
        assert isinstance(result.details, str)
        assert isinstance(result.errors, list)

        backup_exists: bool = (temp_working_dir / "test_activation.exe.bak").exists()
        assert isinstance(backup_exists, bool)

    def test_disc_check_bypass_execution(
        self, securom_binary: Path, temp_working_dir: Path, bypass: SecuROMBypass
    ) -> None:
        """Test disc check bypass execution on real binary."""
        import shutil

        test_binary: Path = temp_working_dir / "test_disc_check.exe"
        shutil.copy2(securom_binary, test_binary)

        result: BypassResult = bypass.bypass_disc_check(test_binary)

        assert isinstance(result, BypassResult)
        assert result.technique == "Disc Check Bypass"
        assert isinstance(result.success, bool)
        assert isinstance(result.details, str)
        assert isinstance(result.errors, list)

    def test_trigger_removal_execution(
        self, securom_binary: Path, temp_working_dir: Path, bypass: SecuROMBypass
    ) -> None:
        """Test trigger removal execution on real binary."""
        import shutil

        test_binary: Path = temp_working_dir / "test_triggers.exe"
        shutil.copy2(securom_binary, test_binary)

        result: BypassResult = bypass.remove_triggers(test_binary)

        assert isinstance(result, BypassResult)
        assert result.technique == "Trigger Removal"
        assert isinstance(result.success, bool)
        assert isinstance(result.details, str)
        assert "triggers" in result.details.lower()
        assert isinstance(result.errors, list)

    def test_system_removal_execution(self, bypass: SecuROMBypass) -> None:
        """Test system-wide SecuROM removal execution."""
        result: SecuROMRemovalResult = bypass.remove_securom()

        assert isinstance(result, SecuROMRemovalResult)
        assert isinstance(result.drivers_removed, list)
        assert isinstance(result.services_stopped, list)
        assert isinstance(result.registry_cleaned, list)
        assert isinstance(result.files_deleted, list)
        assert isinstance(result.activation_bypassed, bool)
        assert isinstance(result.triggers_removed, int)
        assert isinstance(result.success, bool)
        assert isinstance(result.errors, list)
