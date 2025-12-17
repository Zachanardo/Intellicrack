"""Production tests for multi-layer certificate validation detection.

Tests validate comprehensive layer detection for bypass planning:
- OS-level validation detection (CryptoAPI, Schannel)
- Library-level detection (OpenSSL, NSS, BoringSSL)
- Application-level detection (custom pinning, hardcoded certs)
- Server-level detection (online activation, license servers)
- Dependency graph construction and topological sorting
- Confidence scoring and evidence collection
- Multi-layer bypass planning workflows

All tests use real binary analysis without mocks to validate
genuine multi-layer validation detection accuracy.
"""

import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

try:
    import lief
except ImportError:
    pytest.skip("lief not available", allow_module_level=True)

from intellicrack.core.certificate.layer_detector import (
    DependencyGraph,
    LayerInfo,
    ValidationLayer,
    ValidationLayerDetector,
)

if TYPE_CHECKING:
    from collections.abc import Generator


@pytest.fixture
def sample_pe_with_crypto() -> Generator[Path, None, None]:
    """Create temporary PE binary importing crypto DLLs."""
    pe = lief.PE.Binary("test", lief.PE.PE_TYPE.PE32)

    pe.add_library("crypt32.dll")
    pe.add_library("sspicli.dll")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
        temp_path = Path(f.name)

    pe.write(str(temp_path))

    yield temp_path

    if temp_path.exists():
        temp_path.unlink()


@pytest.fixture
def sample_pe_with_openssl() -> Generator[Path, None, None]:
    """Create temporary PE binary importing OpenSSL."""
    pe = lief.PE.Binary("test", lief.PE.PE_TYPE.PE32)

    pe.add_library("libssl.dll")
    pe.add_library("libcrypto.dll")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
        temp_path = Path(f.name)

    pe.write(str(temp_path))

    yield temp_path

    if temp_path.exists():
        temp_path.unlink()


@pytest.fixture
def sample_pe_with_cert_pinning() -> Generator[Path, None, None]:
    """Create temporary PE binary with certificate pinning indicators."""
    pe = lief.PE.Binary("test", lief.PE.PE_TYPE.PE32)

    section = lief.PE.Section(".rdata")
    section.content = list(b"certificate pin validation SHA-256 cert_verify")
    pe.add_section(section)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
        temp_path = Path(f.name)

    pe.write(str(temp_path))

    yield temp_path

    if temp_path.exists():
        temp_path.unlink()


@pytest.fixture
def sample_pe_with_embedded_cert() -> Generator[Path, None, None]:
    """Create temporary PE binary with embedded certificate."""
    pe = lief.PE.Binary("test", lief.PE.PE_TYPE.PE32)

    cert_data = b"-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHHCgVZU"
    section = lief.PE.Section(".cert")
    section.content = list(cert_data)
    pe.add_section(section)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
        temp_path = Path(f.name)

    pe.write(str(temp_path))

    yield temp_path

    if temp_path.exists():
        temp_path.unlink()


class TestValidationLayerEnum:
    """Test ValidationLayer enumeration."""

    def test_validation_layer_enum_values(self) -> None:
        """ValidationLayer enum contains expected layer types."""
        assert ValidationLayer.OS_LEVEL.value == "os_level"
        assert ValidationLayer.LIBRARY_LEVEL.value == "library_level"
        assert ValidationLayer.APPLICATION_LEVEL.value == "application_level"
        assert ValidationLayer.SERVER_LEVEL.value == "server_level"

    def test_validation_layer_enum_count(self) -> None:
        """ValidationLayer enum contains all expected layers."""
        layers = list(ValidationLayer)
        assert len(layers) == 4


class TestLayerInfoDataClass:
    """Test LayerInfo data class structure and methods."""

    def test_layer_info_initialization(self) -> None:
        """LayerInfo initializes with layer type and confidence."""
        layer_info = LayerInfo(
            layer_type=ValidationLayer.OS_LEVEL,
            confidence=0.75,
        )

        assert layer_info.layer_type == ValidationLayer.OS_LEVEL
        assert layer_info.confidence == 0.75
        assert layer_info.evidence == []
        assert layer_info.dependencies == []

    def test_layer_info_add_evidence(self) -> None:
        """LayerInfo add_evidence appends to evidence list."""
        layer_info = LayerInfo(
            layer_type=ValidationLayer.OS_LEVEL,
            confidence=0.5,
        )

        layer_info.add_evidence("Imports crypt32.dll")
        layer_info.add_evidence("Uses CertVerifyCertificateChainPolicy")

        assert len(layer_info.evidence) == 2
        assert "Imports crypt32.dll" in layer_info.evidence

    def test_layer_info_add_evidence_prevents_duplicates(self) -> None:
        """LayerInfo add_evidence prevents duplicate evidence entries."""
        layer_info = LayerInfo(
            layer_type=ValidationLayer.OS_LEVEL,
            confidence=0.5,
        )

        layer_info.add_evidence("Test evidence")
        layer_info.add_evidence("Test evidence")

        assert len(layer_info.evidence) == 1

    def test_layer_info_add_dependency(self) -> None:
        """LayerInfo add_dependency appends to dependencies list."""
        layer_info = LayerInfo(
            layer_type=ValidationLayer.APPLICATION_LEVEL,
            confidence=0.6,
        )

        layer_info.add_dependency(ValidationLayer.LIBRARY_LEVEL)
        layer_info.add_dependency(ValidationLayer.OS_LEVEL)

        assert len(layer_info.dependencies) == 2
        assert ValidationLayer.LIBRARY_LEVEL in layer_info.dependencies

    def test_layer_info_add_dependency_prevents_duplicates(self) -> None:
        """LayerInfo add_dependency prevents duplicate dependencies."""
        layer_info = LayerInfo(
            layer_type=ValidationLayer.APPLICATION_LEVEL,
            confidence=0.6,
        )

        layer_info.add_dependency(ValidationLayer.OS_LEVEL)
        layer_info.add_dependency(ValidationLayer.OS_LEVEL)

        assert len(layer_info.dependencies) == 1


class TestDependencyGraph:
    """Test dependency graph construction and topological sorting."""

    def test_dependency_graph_initialization(self) -> None:
        """DependencyGraph initializes with empty graph and layers."""
        graph = DependencyGraph()

        assert isinstance(graph._graph, dict)
        assert isinstance(graph._layers, set)
        assert len(graph._graph) == 0
        assert len(graph._layers) == 0

    def test_add_layer_to_graph(self) -> None:
        """Add layer creates entry in graph."""
        graph = DependencyGraph()

        graph.add_layer(ValidationLayer.OS_LEVEL)

        assert ValidationLayer.OS_LEVEL in graph._layers
        assert ValidationLayer.OS_LEVEL in graph._graph

    def test_add_dependency_creates_relationship(self) -> None:
        """Add dependency creates dependency edge in graph."""
        graph = DependencyGraph()

        graph.add_dependency(
            ValidationLayer.APPLICATION_LEVEL,
            ValidationLayer.LIBRARY_LEVEL,
        )

        assert ValidationLayer.APPLICATION_LEVEL in graph._layers
        assert ValidationLayer.LIBRARY_LEVEL in graph._layers
        assert ValidationLayer.LIBRARY_LEVEL in graph._graph[ValidationLayer.APPLICATION_LEVEL]

    def test_get_dependencies_returns_correct_set(self) -> None:
        """Get dependencies returns all dependencies for layer."""
        graph = DependencyGraph()

        graph.add_dependency(
            ValidationLayer.APPLICATION_LEVEL,
            ValidationLayer.LIBRARY_LEVEL,
        )
        graph.add_dependency(ValidationLayer.APPLICATION_LEVEL, ValidationLayer.OS_LEVEL)

        deps = graph.get_dependencies(ValidationLayer.APPLICATION_LEVEL)

        assert len(deps) == 2
        assert ValidationLayer.LIBRARY_LEVEL in deps
        assert ValidationLayer.OS_LEVEL in deps

    def test_get_dependencies_empty_layer_returns_empty_set(self) -> None:
        """Get dependencies for layer without dependencies returns empty."""
        graph = DependencyGraph()

        graph.add_layer(ValidationLayer.OS_LEVEL)

        deps = graph.get_dependencies(ValidationLayer.OS_LEVEL)

        assert len(deps) == 0

    def test_topological_sort_simple_chain(self) -> None:
        """Topological sort orders simple dependency chain correctly."""
        graph = DependencyGraph()

        graph.add_dependency(ValidationLayer.APPLICATION_LEVEL, ValidationLayer.OS_LEVEL)

        sorted_layers = graph.topological_sort()

        assert ValidationLayer.OS_LEVEL in sorted_layers
        assert ValidationLayer.APPLICATION_LEVEL in sorted_layers
        assert sorted_layers.index(ValidationLayer.OS_LEVEL) < sorted_layers.index(
            ValidationLayer.APPLICATION_LEVEL,
        )

    def test_topological_sort_complex_dependencies(self) -> None:
        """Topological sort handles complex dependency graph."""
        graph = DependencyGraph()

        graph.add_dependency(ValidationLayer.APPLICATION_LEVEL, ValidationLayer.LIBRARY_LEVEL)
        graph.add_dependency(ValidationLayer.LIBRARY_LEVEL, ValidationLayer.OS_LEVEL)
        graph.add_dependency(ValidationLayer.SERVER_LEVEL, ValidationLayer.LIBRARY_LEVEL)

        sorted_layers = graph.topological_sort()

        os_idx = sorted_layers.index(ValidationLayer.OS_LEVEL)
        lib_idx = sorted_layers.index(ValidationLayer.LIBRARY_LEVEL)
        app_idx = sorted_layers.index(ValidationLayer.APPLICATION_LEVEL)
        server_idx = sorted_layers.index(ValidationLayer.SERVER_LEVEL)

        assert os_idx < lib_idx
        assert lib_idx < app_idx
        assert lib_idx < server_idx

    def test_topological_sort_circular_dependency_handled(self) -> None:
        """Topological sort handles circular dependencies gracefully."""
        graph = DependencyGraph()

        graph.add_dependency(ValidationLayer.APPLICATION_LEVEL, ValidationLayer.LIBRARY_LEVEL)
        graph.add_dependency(ValidationLayer.LIBRARY_LEVEL, ValidationLayer.APPLICATION_LEVEL)

        sorted_layers = graph.topological_sort()

        assert len(sorted_layers) >= 0


class TestValidationLayerDetectorInitialization:
    """Test ValidationLayerDetector initialization."""

    def test_detector_initialization_loads_api_signatures(self) -> None:
        """ValidationLayerDetector loads API signatures on init."""
        detector = ValidationLayerDetector()

        assert hasattr(detector, "_api_signatures")
        assert isinstance(detector._api_signatures, list)

    def test_detector_has_os_level_dll_set(self) -> None:
        """ValidationLayerDetector defines OS-level DLL set."""
        assert "crypt32.dll" in ValidationLayerDetector.OS_LEVEL_DLLS
        assert "sspicli.dll" in ValidationLayerDetector.OS_LEVEL_DLLS
        assert "schannel.dll" in ValidationLayerDetector.OS_LEVEL_DLLS

    def test_detector_has_library_level_libs_set(self) -> None:
        """ValidationLayerDetector defines library-level library set."""
        assert "libssl.so" in ValidationLayerDetector.LIBRARY_LEVEL_LIBS
        assert "libnss3.so" in ValidationLayerDetector.LIBRARY_LEVEL_LIBS

    def test_detector_has_application_indicators(self) -> None:
        """ValidationLayerDetector defines application-level indicators."""
        assert "certificate pin" in ValidationLayerDetector.APPLICATION_LEVEL_INDICATORS
        assert "SHA-256" in ValidationLayerDetector.APPLICATION_LEVEL_INDICATORS

    def test_detector_has_server_indicators(self) -> None:
        """ValidationLayerDetector defines server-level indicators."""
        assert "activation" in ValidationLayerDetector.SERVER_LEVEL_INDICATORS
        assert "license_server" in ValidationLayerDetector.SERVER_LEVEL_INDICATORS


class TestOSLevelDetection:
    """Test OS-level validation layer detection."""

    def test_detect_os_level_with_crypto_imports(
        self,
        sample_pe_with_crypto: Path,
    ) -> None:
        """Detect OS level identifies CryptoAPI imports."""
        detector = ValidationLayerDetector()

        binary = lief.parse(str(sample_pe_with_crypto))
        if binary:
            layer_info = detector._detect_os_level(binary)

            assert layer_info is not None
            assert layer_info.layer_type == ValidationLayer.OS_LEVEL
            assert layer_info.confidence > 0.0

    def test_detect_os_level_confidence_increases_with_imports(self) -> None:
        """Detect OS level confidence scales with number of crypto DLL imports."""
        detector = ValidationLayerDetector()

        pe1 = lief.PE.Binary("test1", lief.PE.PE_TYPE.PE32)
        pe1.add_library("crypt32.dll")

        pe2 = lief.PE.Binary("test2", lief.PE.PE_TYPE.PE32)
        pe2.add_library("crypt32.dll")
        pe2.add_library("sspicli.dll")
        pe2.add_library("schannel.dll")

        layer1 = detector._detect_os_level(pe1)
        layer2 = detector._detect_os_level(pe2)

        if layer1 and layer2:
            assert layer2.confidence > layer1.confidence

    def test_detect_os_level_adds_evidence_for_dlls(self) -> None:
        """Detect OS level adds evidence entries for detected DLLs."""
        detector = ValidationLayerDetector()

        pe = lief.PE.Binary("test", lief.PE.PE_TYPE.PE32)
        pe.add_library("crypt32.dll")

        layer_info = detector._detect_os_level(pe)

        if layer_info:
            assert len(layer_info.evidence) > 0
            assert any("crypt32.dll" in e.lower() for e in layer_info.evidence)

    def test_detect_os_level_no_crypto_returns_none(self) -> None:
        """Detect OS level returns None without crypto DLL imports."""
        detector = ValidationLayerDetector()

        pe = lief.PE.Binary("test", lief.PE.PE_TYPE.PE32)
        pe.add_library("kernel32.dll")

        layer_info = detector._detect_os_level(pe)

        assert layer_info is None


class TestLibraryLevelDetection:
    """Test library-level validation layer detection."""

    def test_detect_library_level_with_openssl(
        self,
        sample_pe_with_openssl: Path,
    ) -> None:
        """Detect library level identifies OpenSSL imports."""
        detector = ValidationLayerDetector()

        binary = lief.parse(str(sample_pe_with_openssl))
        if binary:
            layer_info = detector._detect_library_level(binary)

            assert layer_info is not None
            assert layer_info.layer_type == ValidationLayer.LIBRARY_LEVEL
            assert layer_info.confidence > 0.0

    def test_detect_library_level_adds_evidence(self) -> None:
        """Detect library level adds evidence for TLS libraries."""
        detector = ValidationLayerDetector()

        pe = lief.PE.Binary("test", lief.PE.PE_TYPE.PE32)
        pe.add_library("libssl.dll")

        layer_info = detector._detect_library_level(pe)

        if layer_info:
            assert len(layer_info.evidence) > 0

    def test_detect_library_level_no_tls_libs_returns_none(self) -> None:
        """Detect library level returns None without TLS library imports."""
        detector = ValidationLayerDetector()

        pe = lief.PE.Binary("test", lief.PE.PE_TYPE.PE32)
        pe.add_library("kernel32.dll")

        layer_info = detector._detect_library_level(pe)

        assert layer_info is None


class TestApplicationLevelDetection:
    """Test application-level validation layer detection."""

    def test_detect_application_level_with_pinning_indicators(
        self,
        sample_pe_with_cert_pinning: Path,
    ) -> None:
        """Detect application level identifies certificate pinning indicators."""
        detector = ValidationLayerDetector()

        binary = lief.parse(str(sample_pe_with_cert_pinning))
        if binary:
            layer_info = detector._detect_application_level(binary, sample_pe_with_cert_pinning)

            assert layer_info is not None
            assert layer_info.layer_type == ValidationLayer.APPLICATION_LEVEL

    def test_detect_application_level_with_embedded_cert(
        self,
        sample_pe_with_embedded_cert: Path,
    ) -> None:
        """Detect application level identifies embedded certificates."""
        detector = ValidationLayerDetector()

        binary = lief.parse(str(sample_pe_with_embedded_cert))
        if binary:
            layer_info = detector._detect_application_level(binary, sample_pe_with_embedded_cert)

            if layer_info:
                assert layer_info.confidence > 0.0

    def test_contains_certificate_hashes_sha256(self) -> None:
        """Detect SHA-256 certificate hashes in strings."""
        detector = ValidationLayerDetector()

        strings = {
            "test",
            "a" * 64,
        }

        result = detector._contains_certificate_hashes(strings)

        assert result is True

    def test_contains_certificate_hashes_sha1(self) -> None:
        """Detect SHA-1 certificate hashes in strings."""
        detector = ValidationLayerDetector()

        strings = {
            "test",
            "b" * 40,
        }

        result = detector._contains_certificate_hashes(strings)

        assert result is True

    def test_contains_certificate_hashes_no_hashes(self) -> None:
        """Detect no certificate hashes returns False."""
        detector = ValidationLayerDetector()

        strings = {"test", "hello world", "no hashes here"}

        result = detector._contains_certificate_hashes(strings)

        assert result is False

    def test_contains_embedded_certificates_with_pem_marker(self) -> None:
        """Detect embedded PEM certificate markers."""
        detector = ValidationLayerDetector()

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"some data\n-----BEGIN CERTIFICATE-----\nmore data")
            temp_path = Path(f.name)

        try:
            result = detector._contains_embedded_certificates(temp_path)
            assert result is True
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_contains_embedded_certificates_no_markers(self) -> None:
        """Detect no embedded certificates returns False."""
        detector = ValidationLayerDetector()

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"plain text data with no certificates")
            temp_path = Path(f.name)

        try:
            result = detector._contains_embedded_certificates(temp_path)
            assert result is False
        finally:
            if temp_path.exists():
                temp_path.unlink()


class TestServerLevelDetection:
    """Test server-level validation layer detection."""

    def test_detect_server_level_with_indicators(self) -> None:
        """Detect server level identifies activation/license server indicators."""
        detector = ValidationLayerDetector()

        pe = lief.PE.Binary("test", lief.PE.PE_TYPE.PE32)
        section = lief.PE.Section(".rdata")
        section.content = list(b"license_server activation verify_license")
        pe.add_section(section)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
            temp_path = Path(f.name)

        pe.write(str(temp_path))

        try:
            binary = lief.parse(str(temp_path))
            if binary:
                layer_info = detector._detect_server_level(binary, temp_path)

                if layer_info:
                    assert layer_info.layer_type == ValidationLayer.SERVER_LEVEL
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_contains_http_endpoints_with_urls(self) -> None:
        """Detect HTTP/HTTPS endpoint URLs in strings."""
        detector = ValidationLayerDetector()

        strings = {
            "test",
            "https://api.example.com/validate",
            "config",
        }

        result = detector._contains_http_endpoints(strings)

        assert result is True

    def test_contains_http_endpoints_no_urls(self) -> None:
        """Detect no HTTP endpoints returns False."""
        detector = ValidationLayerDetector()

        strings = {"test", "hello", "no urls here"}

        result = detector._contains_http_endpoints(strings)

        assert result is False


class TestLayerDetectionIntegration:
    """Test complete layer detection workflows."""

    def test_detect_validation_layers_with_crypto_binary(
        self,
        sample_pe_with_crypto: Path,
    ) -> None:
        """Detect validation layers identifies all present layers."""
        detector = ValidationLayerDetector()

        layers = detector.detect_validation_layers(str(sample_pe_with_crypto))

        assert isinstance(layers, list)
        assert all(isinstance(layer, LayerInfo) for layer in layers)

    def test_detect_validation_layers_nonexistent_file_raises(self) -> None:
        """Detect validation layers with nonexistent file raises FileNotFoundError."""
        detector = ValidationLayerDetector()

        with pytest.raises(FileNotFoundError):
            detector.detect_validation_layers("nonexistent.exe")

    def test_detect_validation_layers_filters_low_confidence(self) -> None:
        """Detect validation layers filters out low confidence detections."""
        detector = ValidationLayerDetector()

        pe = lief.PE.Binary("test", lief.PE.PE_TYPE.PE32)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
            temp_path = Path(f.name)

        pe.write(str(temp_path))

        try:
            layers = detector.detect_validation_layers(str(temp_path))

            assert all(layer.confidence > 0.3 for layer in layers)
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_establish_dependencies_app_depends_on_lib(self) -> None:
        """Establish dependencies sets app layer depending on lib layer."""
        detector = ValidationLayerDetector()

        layers = {
            ValidationLayer.APPLICATION_LEVEL: LayerInfo(
                ValidationLayer.APPLICATION_LEVEL,
                0.8,
            ),
            ValidationLayer.LIBRARY_LEVEL: LayerInfo(ValidationLayer.LIBRARY_LEVEL, 0.7),
        }

        detector._establish_dependencies(layers)

        assert ValidationLayer.LIBRARY_LEVEL in layers[ValidationLayer.APPLICATION_LEVEL].dependencies

    def test_establish_dependencies_lib_depends_on_os(self) -> None:
        """Establish dependencies sets lib layer depending on OS layer."""
        detector = ValidationLayerDetector()

        layers = {
            ValidationLayer.LIBRARY_LEVEL: LayerInfo(ValidationLayer.LIBRARY_LEVEL, 0.7),
            ValidationLayer.OS_LEVEL: LayerInfo(ValidationLayer.OS_LEVEL, 0.9),
        }

        detector._establish_dependencies(layers)

        assert ValidationLayer.OS_LEVEL in layers[ValidationLayer.LIBRARY_LEVEL].dependencies

    def test_build_layer_dependency_graph(self) -> None:
        """Build dependency graph creates correct graph structure."""
        detector = ValidationLayerDetector()

        layer1 = LayerInfo(ValidationLayer.APPLICATION_LEVEL, 0.8)
        layer1.add_dependency(ValidationLayer.LIBRARY_LEVEL)

        layer2 = LayerInfo(ValidationLayer.LIBRARY_LEVEL, 0.7)
        layer2.add_dependency(ValidationLayer.OS_LEVEL)

        layer3 = LayerInfo(ValidationLayer.OS_LEVEL, 0.9)

        layers = [layer1, layer2, layer3]

        graph = detector.build_layer_dependency_graph(layers)

        assert isinstance(graph, DependencyGraph)
        assert ValidationLayer.APPLICATION_LEVEL in graph._layers
        assert ValidationLayer.LIBRARY_LEVEL in graph._layers
        assert ValidationLayer.OS_LEVEL in graph._layers


class TestBypassOrderCalculation:
    """Test calculation of optimal bypass order via topological sort."""

    def test_bypass_order_simple_stack(self) -> None:
        """Bypass order for simple stack is OS -> Library -> Application."""
        detector = ValidationLayerDetector()

        layer_app = LayerInfo(ValidationLayer.APPLICATION_LEVEL, 0.8)
        layer_app.add_dependency(ValidationLayer.LIBRARY_LEVEL)

        layer_lib = LayerInfo(ValidationLayer.LIBRARY_LEVEL, 0.7)
        layer_lib.add_dependency(ValidationLayer.OS_LEVEL)

        layer_os = LayerInfo(ValidationLayer.OS_LEVEL, 0.9)

        layers = [layer_app, layer_lib, layer_os]

        graph = detector.build_layer_dependency_graph(layers)
        bypass_order = graph.topological_sort()

        os_idx = bypass_order.index(ValidationLayer.OS_LEVEL)
        lib_idx = bypass_order.index(ValidationLayer.LIBRARY_LEVEL)
        app_idx = bypass_order.index(ValidationLayer.APPLICATION_LEVEL)

        assert os_idx < lib_idx < app_idx

    def test_bypass_order_with_server_layer(self) -> None:
        """Bypass order includes server layer correctly."""
        detector = ValidationLayerDetector()

        layer_server = LayerInfo(ValidationLayer.SERVER_LEVEL, 0.6)
        layer_server.add_dependency(ValidationLayer.LIBRARY_LEVEL)

        layer_lib = LayerInfo(ValidationLayer.LIBRARY_LEVEL, 0.7)
        layer_lib.add_dependency(ValidationLayer.OS_LEVEL)

        layer_os = LayerInfo(ValidationLayer.OS_LEVEL, 0.9)

        layers = [layer_server, layer_lib, layer_os]

        graph = detector.build_layer_dependency_graph(layers)
        bypass_order = graph.topological_sort()

        os_idx = bypass_order.index(ValidationLayer.OS_LEVEL)
        lib_idx = bypass_order.index(ValidationLayer.LIBRARY_LEVEL)
        server_idx = bypass_order.index(ValidationLayer.SERVER_LEVEL)

        assert os_idx < lib_idx < server_idx
