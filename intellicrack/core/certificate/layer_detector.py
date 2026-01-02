"""Multi-layer certificate validation detection for comprehensive bypass planning.

CAPABILITIES:
- Detects multiple validation layers (OS, library, application, server)
- Builds dependency graphs between layers
- Topological sorting for staged bypass
- Layer confidence scoring
- Evidence tracking for each layer
- Hierarchical layer analysis

LIMITATIONS:
- Heuristic-based layer detection (may have false positives)
- Cannot detect all custom layer implementations
- Dependency graph assumes standard architectures
- No runtime layer detection
- Limited server-level detection (requires network analysis)

USAGE EXAMPLES:
    # Detect validation layers
    from intellicrack.core.certificate.layer_detector import (
        ValidationLayerDetector
    )

    detector = ValidationLayerDetector()
    layers = detector.detect_validation_layers("target.exe")

    for layer_info in layers:
        print(f"Layer: {layer_info.layer_type.value}")
        print(f"Confidence: {layer_info.confidence:.2f}")
        print(f"Evidence: {layer_info.evidence}")
        print(f"Dependencies: {[d.value for d in layer_info.dependencies]}")

    # Build dependency graph
    graph = detector.build_layer_dependency_graph(layers)
    sorted_layers = graph.topological_sort()
    print(f"Bypass order: {[l.value for l in sorted_layers]}")

RELATED MODULES:
- multilayer_bypass.py: Executes staged bypasses using detected layers
- validation_detector.py: Detects specific validation functions
- bypass_orchestrator.py: Coordinates multi-layer bypass execution

VALIDATION LAYERS:
    OS_LEVEL:
        - CryptoAPI (crypt32.dll)
        - Schannel (sspicli.dll)
        - System trust store validation

    LIBRARY_LEVEL:
        - OpenSSL (libssl.so)
        - NSS (libnss3.so)
        - BoringSSL (Android)

    APPLICATION_LEVEL:
        - Custom pinning logic
        - Hardcoded certificate checks
        - Application-specific validation

    SERVER_LEVEL:
        - Server-side certificate validation
        - Mutual TLS authentication
        - Online activation checks
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import lief

from intellicrack.core.certificate.api_signatures import get_all_signatures


logger = logging.getLogger(__name__)


class ValidationLayer(Enum):
    """Certificate validation layer types in order of hierarchy."""

    OS_LEVEL = "os_level"
    LIBRARY_LEVEL = "library_level"
    APPLICATION_LEVEL = "application_level"
    SERVER_LEVEL = "server_level"


@dataclass
class LayerInfo:
    """Information about a detected validation layer."""

    layer_type: ValidationLayer
    confidence: float
    evidence: list[str] = field(default_factory=list)
    dependencies: list[ValidationLayer] = field(default_factory=list)

    def add_evidence(self, evidence: str) -> None:
        """Add evidence for this layer detection.

        Args:
            evidence: Evidence string to add if not already present

        Returns:
            None
        """
        if evidence not in self.evidence:
            self.evidence.append(evidence)

    def add_dependency(self, layer: ValidationLayer) -> None:
        """Add a layer dependency.

        Args:
            layer: Validation layer to add as dependency if not already present

        Returns:
            None
        """
        if layer not in self.dependencies:
            self.dependencies.append(layer)


class DependencyGraph:
    """Represents dependencies between validation layers."""

    def __init__(self) -> None:
        """Initialize empty dependency graph."""
        self._graph: dict[ValidationLayer, set[ValidationLayer]] = {}
        self._layers: set[ValidationLayer] = set()

    def add_layer(self, layer: ValidationLayer) -> None:
        """Add a layer to the graph.

        Args:
            layer: Validation layer to add to the graph

        Returns:
            None
        """
        self._layers.add(layer)
        if layer not in self._graph:
            self._graph[layer] = set()

    def add_dependency(self, dependent: ValidationLayer, dependency: ValidationLayer) -> None:
        """Add a dependency relationship: dependent depends on dependency.

        Args:
            dependent: Layer that has the dependency
            dependency: Layer that is depended on

        Returns:
            None
        """
        self.add_layer(dependent)
        self.add_layer(dependency)
        self._graph[dependent].add(dependency)

    def get_dependencies(self, layer: ValidationLayer) -> set[ValidationLayer]:
        """Get all dependencies for a layer.

        Args:
            layer: Validation layer to retrieve dependencies for

        Returns:
            Set of ValidationLayer objects that the given layer depends on
        """
        return self._graph.get(layer, set())

    def topological_sort(self) -> list[ValidationLayer]:
        """Return layers in topologically sorted order (dependencies first).

        Performs depth-first search with cycle detection to produce an ordering
        where all dependencies of a layer appear before the layer itself.

        Returns:
            List of ValidationLayer objects sorted topologically such that
                dependencies appear before dependents. If a cycle is detected,
                warning is logged and the cycle is skipped.
        """
        visited = set()
        temp_mark = set()
        result = []

        def visit(layer: ValidationLayer) -> None:
            if layer in temp_mark:
                logger.warning("Circular dependency detected involving %s", layer.value)
                return
            if layer in visited:
                return

            temp_mark.add(layer)
            for dependency in self._graph.get(layer, set()):
                visit(dependency)
            temp_mark.remove(layer)
            visited.add(layer)
            result.append(layer)

        for layer in self._layers:
            if layer not in visited:
                visit(layer)

        return result


class ValidationLayerDetector:
    """Detects multiple layers of certificate validation in a target."""

    OS_LEVEL_DLLS = {
        "crypt32.dll",
        "sspicli.dll",
        "schannel.dll",
        "bcrypt.dll",
        "ncrypt.dll",
        "cryptsp.dll",
        "rsaenh.dll",
    }

    LIBRARY_LEVEL_LIBS = {
        "libssl.so",
        "libssl.dylib",
        "libssl.so.1.1",
        "libssl.so.3",
        "libnss3.so",
        "libnss3.dylib",
        "libnspr4.so",
        "libboringssl.so",
        "libboringssl.dylib",
    }

    APPLICATION_LEVEL_INDICATORS = {
        "certificate pin",
        "cert pin",
        "public key pin",
        "SHA-256",
        "SHA-1",
        "X509_verify",
        "cert_verify",
    }

    SERVER_LEVEL_INDICATORS = {
        "activation",
        "license_server",
        "validation_endpoint",
        "auth_server",
        "verify_license",
    }

    def __init__(self) -> None:
        """Initialize the layer detector."""
        self._api_signatures = get_all_signatures()

    def detect_validation_layers(self, target: str) -> list[LayerInfo]:
        """Detect all validation layers in the target binary.

        Args:
            target: Path to binary file or process name

        Returns:
            List of detected LayerInfo objects with confidence scores

        Raises:
            FileNotFoundError: If target file doesn't exist
            ValueError: If target format is unsupported

        """
        target_path = Path(target)
        if not target_path.exists():
            raise FileNotFoundError(f"Target not found: {target}")

        detected_layers: dict[ValidationLayer, LayerInfo] = {}

        try:
            binary = lief.parse(str(target_path))
            if not binary:
                raise ValueError(f"Failed to parse binary: {target}")

            os_layer = self._detect_os_level(binary)
            if os_layer and os_layer.confidence > 0.3:
                detected_layers[ValidationLayer.OS_LEVEL] = os_layer

            lib_layer = self._detect_library_level(binary)
            if lib_layer and lib_layer.confidence > 0.3:
                detected_layers[ValidationLayer.LIBRARY_LEVEL] = lib_layer

            app_layer = self._detect_application_level(binary, target_path)
            if app_layer and app_layer.confidence > 0.3:
                detected_layers[ValidationLayer.APPLICATION_LEVEL] = app_layer

            server_layer = self._detect_server_level(binary, target_path)
            if server_layer and server_layer.confidence > 0.3:
                detected_layers[ValidationLayer.SERVER_LEVEL] = server_layer

            self._establish_dependencies(detected_layers)

        except Exception as e:
            logger.exception("Error detecting validation layers: %s", e)
            raise

        return list(detected_layers.values())

    def _detect_os_level(
        self,
        binary: lief.PE.Binary | lief.ELF.Binary | lief.MachO.Binary | lief.COFF.Binary,
    ) -> LayerInfo | None:
        """Detect OS-level validation (CryptoAPI, Schannel, system trust store).

        Analyzes binary imports for Windows CryptoAPI and Schannel libraries
        that indicate OS-level certificate validation mechanisms.

        Args:
            binary: Parsed binary object (PE, ELF, Mach-O, or COFF format)
                to analyze for OS-level certificate validation

        Returns:
            LayerInfo with OS_LEVEL validation type and confidence score,
                populated with evidence of OS-level validation functions.
                Returns None if no OS-level validation indicators detected.
        """
        layer_info = LayerInfo(
            layer_type=ValidationLayer.OS_LEVEL,
            confidence=0.0,
        )

        imported_libs: set[str] = set()
        if hasattr(binary, "imports"):
            for imported_lib in binary.imports:
                if hasattr(imported_lib, "name"):
                    lib_name_raw = imported_lib.name
                    if isinstance(lib_name_raw, bytes):
                        lib_name = lib_name_raw.decode("utf-8", errors="ignore").lower()
                    else:
                        lib_name = str(lib_name_raw).lower()
                    imported_libs.add(lib_name)

        if os_dll_matches := imported_libs.intersection(
            {dll.lower() for dll in self.OS_LEVEL_DLLS},
        ):
            layer_info.confidence = min(len(os_dll_matches) * 0.25, 1.0)
            for dll in os_dll_matches:
                layer_info.add_evidence(f"Imports OS-level crypto library: {dll}")

        os_api_signatures = [sig for sig in self._api_signatures if sig.library.lower() in {dll.lower() for dll in self.OS_LEVEL_DLLS}]

        if os_api_signatures and hasattr(binary, "imports"):
            for sig in os_api_signatures[:5]:
                layer_info.add_evidence(f"Uses OS-level API: {sig.name}")

        return layer_info if layer_info.confidence > 0.0 else None

    def _detect_library_level(
        self,
        binary: lief.PE.Binary | lief.ELF.Binary | lief.MachO.Binary | lief.COFF.Binary,
    ) -> LayerInfo | None:
        """Detect library-level validation (OpenSSL, NSS, BoringSSL).

        Analyzes binary imports for cryptographic libraries (OpenSSL, NSS,
        BoringSSL) that provide TLS/SSL certificate validation mechanisms.

        Args:
            binary: Parsed binary object (PE, ELF, Mach-O, or COFF format)
                to analyze for library-level certificate validation

        Returns:
            LayerInfo with LIBRARY_LEVEL validation type and confidence score,
                populated with evidence of TLS/SSL library usage. Returns None
                if no library-level validation indicators detected.
        """
        layer_info = LayerInfo(
            layer_type=ValidationLayer.LIBRARY_LEVEL,
            confidence=0.0,
        )

        imported_libs: set[str] = set()
        if hasattr(binary, "imports"):
            for imported_lib in binary.imports:
                if hasattr(imported_lib, "name"):
                    lib_name_raw = imported_lib.name
                    if isinstance(lib_name_raw, bytes):
                        lib_name = lib_name_raw.decode("utf-8", errors="ignore").lower()
                    else:
                        lib_name = str(lib_name_raw).lower()
                    imported_libs.add(lib_name)

        if lib_matches := imported_libs.intersection(
            {lib.lower() for lib in self.LIBRARY_LEVEL_LIBS},
        ):
            layer_info.confidence = min(len(lib_matches) * 0.3, 1.0)
            for lib in lib_matches:
                layer_info.add_evidence(f"Imports TLS library: {lib}")

        lib_api_signatures = [
            sig
            for sig in self._api_signatures
            if any(lib_keyword in sig.library.lower() for lib_keyword in ["ssl", "tls", "nss", "boring"])
        ]

        if lib_api_signatures and hasattr(binary, "imports"):
            for sig in lib_api_signatures[:5]:
                layer_info.add_evidence(f"Uses TLS library API: {sig.name}")

        return layer_info if layer_info.confidence > 0.0 else None

    def _detect_application_level(
        self,
        binary: lief.PE.Binary | lief.ELF.Binary | lief.MachO.Binary | lief.COFF.Binary,
        target_path: Path,
    ) -> LayerInfo | None:
        """Detect application-level pinning (hardcoded certs, custom logic).

        Searches for indicators of certificate pinning and custom validation
        logic including hardcoded certificate hashes, embedded certificates,
        and pinning-related string identifiers.

        Args:
            binary: Parsed binary object (PE, ELF, Mach-O, or COFF format)
                to analyze for application-level certificate pinning
            target_path: Path to the binary file for embedded certificate
                detection

        Returns:
            LayerInfo with APPLICATION_LEVEL validation type and confidence
                score, populated with evidence of application-level pinning.
                Returns None if no application-level pinning detected.
        """
        layer_info = LayerInfo(
            layer_type=ValidationLayer.APPLICATION_LEVEL,
            confidence=0.0,
        )

        try:
            strings_found: set[str] = set()
            if hasattr(binary, "strings"):
                for string in binary.strings:
                    if isinstance(string, bytes):
                        strings_found.add(string.decode("utf-8", errors="ignore").lower())
                    else:
                        strings_found.add(str(string).lower())

            if indicator_matches := [
                indicator for indicator in self.APPLICATION_LEVEL_INDICATORS if any(indicator.lower() in s for s in strings_found)
            ]:
                layer_info.confidence = min(len(indicator_matches) * 0.2, 0.9)
                for indicator in indicator_matches[:5]:
                    layer_info.add_evidence(
                        f"Found application-level indicator: {indicator}",
                    )

            if self._contains_certificate_hashes(strings_found):
                layer_info.confidence = min(layer_info.confidence + 0.3, 1.0)
                layer_info.add_evidence(
                    "Found hardcoded certificate hash (SHA-256 or SHA-1)",
                )

            if self._contains_embedded_certificates(target_path):
                layer_info.confidence = min(layer_info.confidence + 0.25, 1.0)
                layer_info.add_evidence("Found embedded certificate data")

        except Exception as e:
            logger.warning("Error in application-level detection: %s", e)

        return layer_info if layer_info.confidence > 0.0 else None

    def _detect_server_level(
        self,
        binary: lief.PE.Binary | lief.ELF.Binary | lief.MachO.Binary | lief.COFF.Binary,
        target_path: Path,
    ) -> LayerInfo | None:
        """Detect server-level validation (network-based license checking).

        Identifies server-side validation mechanisms through analysis of
        activation keywords, license server indicators, and HTTP/HTTPS
        endpoint references in binary strings.

        Args:
            binary: Parsed binary object (PE, ELF, Mach-O, or COFF format)
                to analyze for server-level validation indicators
            target_path: Path to the binary file for embedded certificate
                analysis

        Returns:
            LayerInfo with SERVER_LEVEL validation type and confidence
                score, populated with evidence of network-based validation.
                Returns None if no server-level validation detected.
        """
        layer_info = LayerInfo(
            layer_type=ValidationLayer.SERVER_LEVEL,
            confidence=0.0,
        )

        try:
            strings_found: set[str] = set()
            if hasattr(binary, "strings"):
                for string in binary.strings:
                    if isinstance(string, bytes):
                        strings_found.add(string.decode("utf-8", errors="ignore").lower())
                    else:
                        strings_found.add(str(string).lower())

            if indicator_matches := [
                indicator for indicator in self.SERVER_LEVEL_INDICATORS if any(indicator.lower() in s for s in strings_found)
            ]:
                layer_info.confidence = min(len(indicator_matches) * 0.25, 0.9)
                for indicator in indicator_matches[:3]:
                    layer_info.add_evidence(
                        f"Found server-level indicator: {indicator}",
                    )

            if self._contains_http_endpoints(strings_found):
                layer_info.confidence = min(layer_info.confidence + 0.2, 1.0)
                layer_info.add_evidence("Found HTTP/HTTPS endpoint URLs")

        except Exception as e:
            logger.warning("Error in server-level detection: %s", e)

        return layer_info if layer_info.confidence > 0.0 else None

    def _contains_certificate_hashes(self, strings: set[str]) -> bool:
        """Check if strings contain certificate hashes (SHA-256 or SHA-1).

        Examines strings for hexadecimal patterns matching SHA-256 (64 chars)
        and SHA-1 (40 chars) hash lengths.

        Args:
            strings: Set of strings to search for hexadecimal certificate
                hashes

        Returns:
            True if valid SHA-256 or SHA-1 format hashes are found in
                strings, False otherwise
        """
        for string in strings:
            clean_string = "".join(c for c in string if c.isalnum())

            if len(clean_string) == 64 and all(c in "0123456789abcdef" for c in clean_string):
                return True

            if len(clean_string) == 40 and all(c in "0123456789abcdef" for c in clean_string):
                return True

        return False

    def _contains_embedded_certificates(self, target_path: Path) -> bool:
        """Check if binary contains embedded certificate data.

        Searches binary file for PEM-format certificate markers (BEGIN
        CERTIFICATE, RSA PRIVATE KEY) and DER-format indicators (MII prefix).

        Args:
            target_path: Path to the binary file to check for embedded
                certificate data

        Returns:
            True if certificate PEM or DER format markers are found in
                binary, False otherwise
        """
        try:
            with open(target_path, "rb") as f:
                content = f.read()

            cert_markers = [
                b"-----BEGIN CERTIFICATE-----",
                b"-----BEGIN RSA PRIVATE KEY-----",
                b"-----BEGIN PUBLIC KEY-----",
                b"MII",
            ]

            return any(marker in content for marker in cert_markers)
        except Exception as e:
            logger.warning("Error checking for embedded certificates: %s", e)
            return False

    def _contains_http_endpoints(self, strings: set[str]) -> bool:
        """Check if strings contain HTTP/HTTPS endpoints.

        Searches for protocol schemes (http://, https://) and common API
        path patterns (/api/, /v1/, /v2/, etc.) in string set.

        Args:
            strings: Set of strings to search for HTTP/HTTPS endpoint URLs
                and API paths

        Returns:
            True if HTTP/HTTPS protocols or common API path indicators are
                found in strings, False otherwise
        """
        http_indicators = ["http://", "https://", "api.", "/api/", "/v1/", "/v2/"]

        return any(any(indicator in string for indicator in http_indicators) for string in strings)

    def _establish_dependencies(self, layers: dict[ValidationLayer, LayerInfo]) -> None:
        """Establish dependency relationships between detected layers.

        Builds hierarchical dependencies where application-level validation
        depends on library/OS validation, and library validation depends
        on OS validation.

        Args:
            layers: Dictionary mapping ValidationLayer enum types to their
                corresponding LayerInfo objects with detected confidence and
                evidence

        Returns:
            None
        """
        if ValidationLayer.APPLICATION_LEVEL in layers and ValidationLayer.LIBRARY_LEVEL in layers:
            layers[ValidationLayer.APPLICATION_LEVEL].add_dependency(
                ValidationLayer.LIBRARY_LEVEL,
            )

        if (
            ValidationLayer.APPLICATION_LEVEL in layers
            and ValidationLayer.OS_LEVEL in layers
            and ValidationLayer.LIBRARY_LEVEL not in layers
        ):
            layers[ValidationLayer.APPLICATION_LEVEL].add_dependency(
                ValidationLayer.OS_LEVEL,
            )

        if ValidationLayer.LIBRARY_LEVEL in layers and ValidationLayer.OS_LEVEL in layers:
            layers[ValidationLayer.LIBRARY_LEVEL].add_dependency(
                ValidationLayer.OS_LEVEL,
            )

        if ValidationLayer.SERVER_LEVEL in layers:
            if ValidationLayer.LIBRARY_LEVEL in layers:
                layers[ValidationLayer.SERVER_LEVEL].add_dependency(
                    ValidationLayer.LIBRARY_LEVEL,
                )
            elif ValidationLayer.OS_LEVEL in layers:
                layers[ValidationLayer.SERVER_LEVEL].add_dependency(
                    ValidationLayer.OS_LEVEL,
                )

    def build_layer_dependency_graph(
        self,
        layers: list[LayerInfo],
    ) -> DependencyGraph:
        """Build a dependency graph from detected layers.

        Constructs a directed graph where edges represent dependency
        relationships between validation layers, enabling topological
        sorting for staged bypass planning.

        Args:
            layers: List of detected LayerInfo objects with populated
                dependency information

        Returns:
            DependencyGraph object representing all layer dependency
                relationships for topological analysis
        """
        graph = DependencyGraph()

        for layer_info in layers:
            graph.add_layer(layer_info.layer_type)

            for dependency in layer_info.dependencies:
                graph.add_dependency(layer_info.layer_type, dependency)

        return graph
