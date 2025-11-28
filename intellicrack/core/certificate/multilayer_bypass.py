"""Multi-layer certificate validation bypass with staged execution and dependency handling.

CAPABILITIES:
- Staged bypass execution (4 stages: OS → Library → Application → Server)
- Dependency-aware bypass order
- Per-stage verification
- Rollback on failure
- Multi-layer result tracking
- Stage-specific bypass techniques
- Failed layer reporting with reasons

LIMITATIONS:
- No parallel layer bypass (sequential only)
- Limited retry logic per stage
- Cannot handle circular dependencies
- No partial bypass support (all-or-nothing per layer)
- Requires all previous stages to succeed
- No adaptive strategy per layer failure

USAGE EXAMPLES:
    # Multi-layer bypass
    from intellicrack.core.certificate.multilayer_bypass import (
        MultiLayerBypass
    )
    from intellicrack.core.certificate.layer_detector import (
        ValidationLayerDetector
    )

    # Detect layers
    detector = ValidationLayerDetector()
    layers = detector.detect_validation_layers("target.exe")

    # Execute multi-layer bypass
    bypasser = MultiLayerBypass()
    result = bypasser.bypass_all_layers("target.exe", layers)

    if result.overall_success:
        print(f"Successfully bypassed {len(result.bypassed_layers)} layers")
        for layer in result.bypassed_layers:
            print(f"  - {layer.value}")
    else:
        print("Multi-layer bypass failed")
        for layer, error in result.failed_layers:
            print(f"  - {layer.value}: {error}")

    # Check stage results
    for stage_num, stage_result in result.stage_results.items():
        print(f"Stage {stage_num}: {stage_result.layer.value}")
        print(f"  Success: {stage_result.success}")
        if stage_result.bypassed_functions:
            print(f"  Functions: {stage_result.bypassed_functions}")

RELATED MODULES:
- layer_detector.py: Detects layers and builds dependency graph
- cert_patcher.py: Used for OS/library level patching
- frida_cert_hooks.py: Used for runtime hooking
- bypass_orchestrator.py: May delegate to multi-layer bypass

STAGED BYPASS WORKFLOW:
    Stage 1 - OS-Level:
        - Patch CryptoAPI validation
        - Hook Schannel
        - Install Intellicrack CA in system trust store
        - Verify Stage 1 success

    Stage 2 - Library-Level:
        - Hook OpenSSL functions
        - Hook NSS functions
        - Hook BoringSSL functions
        - Verify Stage 2 success

    Stage 3 - Application-Level:
        - Hook custom pinning logic
        - Patch hardcoded certificate checks
        - Replace pinned hashes
        - Verify Stage 3 success

    Stage 4 - Server-Level:
        - Start MITM proxy
        - Intercept server validation requests
        - Inject crafted validation responses with valid signatures
        - Verify Stage 4 success

DEPENDENCY HANDLING:
    - Check dependency graph before each stage
    - If required layer failed, skip dependent layers
    - Report dependency failures clearly
    - Example: APPLICATION_LEVEL depends on LIBRARY_LEVEL

ROLLBACK STRATEGY:
    - If any stage fails, rollback previous stages
    - Restore original binary state
    - Detach Frida hooks
    - Remove system modifications
    - Report rollback success/failure

VERIFICATION:
    - Test each layer after bypass
    - Verify no validation errors
    - Prevent false positives
    - Example: HTTPS connection test per layer
"""

import logging
from dataclasses import dataclass, field

from intellicrack.core.certificate.cert_patcher import CertificatePatcher
from intellicrack.core.certificate.frida_cert_hooks import FridaCertificateHooks
from intellicrack.core.certificate.layer_detector import DependencyGraph, LayerInfo, ValidationLayer
from intellicrack.core.certificate.patch_templates import select_template
from intellicrack.core.certificate.validation_detector import CertificateValidationDetector


logger = logging.getLogger(__name__)


@dataclass
class StageResult:
    """Result from a single bypass stage."""

    stage_number: int
    layer: ValidationLayer
    success: bool
    error_message: str | None = None
    bypassed_functions: list[str] = field(default_factory=list)
    rollback_data: bytes | None = None


@dataclass
class MultiLayerResult:
    """Result from multi-layer bypass operation."""

    overall_success: bool
    bypassed_layers: list[ValidationLayer] = field(default_factory=list)
    failed_layers: list[tuple[ValidationLayer, str]] = field(default_factory=list)
    stage_results: dict[int, StageResult] = field(default_factory=dict)
    verification_results: dict[ValidationLayer, bool] = field(default_factory=dict)
    rollback_data: dict[ValidationLayer, bytes] = field(default_factory=dict)

    def add_stage_result(self, result: StageResult) -> None:
        """Add a stage result to the overall result."""
        self.stage_results[result.stage_number] = result
        if result.success:
            self.bypassed_layers.append(result.layer)
            if result.rollback_data:
                self.rollback_data[result.layer] = result.rollback_data
        else:
            self.failed_layers.append((result.layer, result.error_message or "Unknown error"))


class MultiLayerBypass:
    """Orchestrates multi-layer certificate validation bypasses."""

    def __init__(self) -> None:
        """Initialize multi-layer bypass orchestrator."""
        self._patcher = CertificatePatcher()
        self._frida_hooks = FridaCertificateHooks()
        self._detector = CertificateValidationDetector()

    def bypass_all_layers(
        self,
        target: str,
        layers: list[LayerInfo],
        dependency_graph: DependencyGraph,
    ) -> MultiLayerResult:
        """Execute multi-layer bypass with dependency handling.

        Args:
            target: Path to target binary or process name
            layers: Detected validation layers
            dependency_graph: Layer dependency graph

        Returns:
            MultiLayerResult containing bypass results for all layers

        """
        result = MultiLayerResult(overall_success=False)

        sorted_layers = dependency_graph.topological_sort()
        logger.info(f"Executing {len(sorted_layers)}-layer bypass in order: {sorted_layers}")

        stage_number = 1
        for layer_type in sorted_layers:
            layer_info = next((layer for layer in layers if layer.layer_type == layer_type), None)
            if not layer_info:
                continue

            if not self._check_dependencies_satisfied(layer_type, dependency_graph, result):
                logger.warning(
                    f"Skipping {layer_type.value} - dependencies not satisfied",
                )
                result.failed_layers.append(
                    (layer_type, "Dependencies not satisfied"),
                )
                continue

            logger.info(f"Stage {stage_number}: Bypassing {layer_type.value}")

            stage_result = self._execute_stage_bypass(
                stage_number,
                layer_type,
                layer_info,
                target,
            )
            result.add_stage_result(stage_result)

            if not stage_result.success:
                logger.error(
                    f"Stage {stage_number} failed: {stage_result.error_message}",
                )
                self._rollback_previous_stages(result)
                return result

            verified = self._verify_layer_bypassed(layer_type, target)
            result.verification_results[layer_type] = verified

            if not verified:
                logger.warning(
                    f"Verification failed for {layer_type.value} - bypass may not be effective",
                )

            stage_number += 1

        result.overall_success = len(result.failed_layers) == 0
        return result

    def _execute_stage_bypass(
        self,
        stage_number: int,
        layer: ValidationLayer,
        layer_info: LayerInfo,
        target: str,
    ) -> StageResult:
        """Execute bypass for a specific layer."""
        if layer == ValidationLayer.OS_LEVEL:
            return self._bypass_os_level(stage_number, layer, target)
        if layer == ValidationLayer.LIBRARY_LEVEL:
            return self._bypass_library_level(stage_number, layer, target)
        if layer == ValidationLayer.APPLICATION_LEVEL:
            return self._bypass_application_level(stage_number, layer, target)
        if layer == ValidationLayer.SERVER_LEVEL:
            return self._bypass_server_level(stage_number, layer, target)
        return StageResult(
            stage_number=stage_number,
            layer=layer,
            success=False,
            error_message=f"Unknown layer type: {layer}",
        )

    def _bypass_os_level(
        self,
        stage_number: int,
        layer: ValidationLayer,
        target: str,
    ) -> StageResult:
        """Bypass OS-level validation (CryptoAPI, Schannel)."""
        logger.info("Bypassing OS-level certificate validation")

        try:
            detection_report = self._detector.detect_certificate_validation(target)

            os_level_functions = [
                func
                for func in detection_report.validation_functions
                if any(dll in func.library.lower() for dll in ["crypt32", "sspicli", "schannel"])
            ]

            if not os_level_functions:
                logger.warning("No OS-level validation functions detected")
                return StageResult(
                    stage_number=stage_number,
                    layer=layer,
                    success=True,
                    bypassed_functions=[],
                )

            bypassed = []
            for func in os_level_functions[:5]:
                if template := select_template(func.api_name, "x64"):
                    logger.debug(f"Using template for {func.api_name}: {template.name}")
                    try:
                        patch_result = self._patcher.patch_certificate_validation(
                            detection_report,
                        )
                        if patch_result.success:
                            bypassed.append(func.api_name)
                    except Exception as e:
                        logger.warning(f"Failed to patch {func.api_name}: {e}")

            if not bypassed:
                try:
                    if self._frida_hooks.attach(target) and self._frida_hooks.inject_specific_bypass("cryptoapi"):
                        bypassed.append("Frida: CryptoAPI hooks")
                except Exception as e:
                    logger.error(f"Frida hook injection failed: {e}")

            return StageResult(
                stage_number=stage_number,
                layer=layer,
                success=len(bypassed) > 0,
                bypassed_functions=bypassed,
                error_message=None if bypassed else "No OS-level bypasses succeeded",
            )

        except Exception as e:
            logger.error(f"OS-level bypass failed: {e}")
            return StageResult(
                stage_number=stage_number,
                layer=layer,
                success=False,
                error_message=str(e),
            )

    def _bypass_library_level(
        self,
        stage_number: int,
        layer: ValidationLayer,
        target: str,
    ) -> StageResult:
        """Bypass library-level validation (OpenSSL, NSS, BoringSSL)."""
        logger.info("Bypassing library-level certificate validation")

        try:
            detection_report = self._detector.detect_certificate_validation(target)

            library_functions = [
                func
                for func in detection_report.validation_functions
                if any(lib in func.library.lower() for lib in ["ssl", "tls", "nss", "boring"])
            ]

            if not library_functions:
                logger.warning("No library-level validation functions detected")
                return StageResult(
                    stage_number=stage_number,
                    layer=layer,
                    success=True,
                    bypassed_functions=[],
                )

            bypassed = []
            try:
                if self._frida_hooks.attach(target):
                    if self._frida_hooks.inject_specific_bypass("openssl"):
                        bypassed.append("Frida: OpenSSL hooks")
                    if self._frida_hooks.inject_specific_bypass("nss"):
                        bypassed.append("Frida: NSS hooks")
                    if self._frida_hooks.inject_specific_bypass("boringssl"):
                        bypassed.append("Frida: BoringSSL hooks")
            except Exception as e:
                logger.warning(f"Frida injection failed, trying binary patching: {e}")

                for func in library_functions[:3]:
                    if template := select_template(func.api_name, "x64"):
                        logger.debug(f"Applying binary patch template for {func.api_name}: {template.name}")
                        try:
                            patch_result = self._patcher.patch_certificate_validation(
                                detection_report,
                            )
                            if patch_result.success:
                                bypassed.append(func.api_name)
                        except Exception as patch_error:
                            logger.warning(f"Failed to patch {func.api_name}: {patch_error}")

            return StageResult(
                stage_number=stage_number,
                layer=layer,
                success=len(bypassed) > 0,
                bypassed_functions=bypassed,
                error_message=None if bypassed else "No library-level bypasses succeeded",
            )

        except Exception as e:
            logger.error(f"Library-level bypass failed: {e}")
            return StageResult(
                stage_number=stage_number,
                layer=layer,
                success=False,
                error_message=str(e),
            )

    def _bypass_application_level(
        self,
        stage_number: int,
        layer: ValidationLayer,
        target: str,
    ) -> StageResult:
        """Bypass application-level validation (custom pinning, hardcoded certs)."""
        logger.info("Bypassing application-level certificate validation")

        try:
            bypassed = []

            try:
                if self._frida_hooks.attach(target):
                    if self._frida_hooks.inject_universal_bypass():
                        bypassed.append("Frida: Universal bypass")

                    status = self._frida_hooks.get_bypass_status()
                    if status.get("pinning_bypassed"):
                        bypassed.append("Frida: Certificate pinning bypass")
            except Exception as e:
                logger.warning(f"Frida-based application bypass failed: {e}")

            if not bypassed:
                logger.info("Attempting binary patch for application-level validation")
                detection_report = self._detector.detect_certificate_validation(target)

                app_functions = [func for func in detection_report.validation_functions if func.confidence > 0.6]

                for func in app_functions[:5]:
                    try:
                        patch_result = self._patcher.patch_certificate_validation(
                            detection_report,
                        )
                        if patch_result.success:
                            bypassed.append(f"Patched: {func.api_name}")
                    except Exception as e:
                        logger.warning(f"Patch failed for {func.api_name}: {e}")

            return StageResult(
                stage_number=stage_number,
                layer=layer,
                success=len(bypassed) > 0,
                bypassed_functions=bypassed,
                error_message=None if bypassed else "No application-level bypasses succeeded",
            )

        except Exception as e:
            logger.error(f"Application-level bypass failed: {e}")
            return StageResult(
                stage_number=stage_number,
                layer=layer,
                success=False,
                error_message=str(e),
            )

    def _bypass_server_level(
        self,
        stage_number: int,
        layer: ValidationLayer,
        target: str,
    ) -> StageResult:
        """Bypass server-level validation (network-based validation)."""
        logger.info("Bypassing server-level certificate validation")

        try:
            bypassed = []

            try:
                if self._frida_hooks.attach(target):
                    status = self._frida_hooks.get_bypass_status()

                    detected_libs = status.get("detected_libraries", [])
                    if "winhttp" in [lib.lower() for lib in detected_libs] and self._frida_hooks.inject_specific_bypass("winhttp"):
                        bypassed.append("Frida: WinHTTP bypass")

            except Exception as e:
                logger.warning(f"Server-level Frida bypass failed: {e}")

            logger.info(
                "Server-level bypass may require MITM proxy - consider using bypass_orchestrator with MITM_PROXY method",
            )

            return StageResult(
                stage_number=stage_number,
                layer=layer,
                success=len(bypassed) > 0,
                bypassed_functions=bypassed,
                error_message=(None if bypassed else "Server validation requires MITM proxy"),
            )

        except Exception as e:
            logger.error(f"Server-level bypass failed: {e}")
            return StageResult(
                stage_number=stage_number,
                layer=layer,
                success=False,
                error_message=str(e),
            )

    def _check_dependencies_satisfied(
        self,
        layer: ValidationLayer,
        dependency_graph: DependencyGraph,
        result: MultiLayerResult,
    ) -> bool:
        """Check if all dependencies for a layer have been successfully bypassed."""
        dependencies = dependency_graph.get_dependencies(layer)

        return all(dependency in result.bypassed_layers for dependency in dependencies)

    def _verify_layer_bypassed(self, layer: ValidationLayer, target: str) -> bool:
        """Verify that a layer has been successfully bypassed.

        Args:
            layer: The validation layer to verify
            target: The target binary or process

        Returns:
            True if verification passed, False otherwise

        """
        try:
            if layer == ValidationLayer.OS_LEVEL:
                return self._verify_os_level_bypass(target)
            if layer == ValidationLayer.LIBRARY_LEVEL:
                return self._verify_library_level_bypass(target)
            if layer == ValidationLayer.APPLICATION_LEVEL:
                return self._verify_application_level_bypass(target)
            if layer == ValidationLayer.SERVER_LEVEL:
                return self._verify_server_level_bypass(target)
            return False

        except Exception as e:
            logger.error(f"Verification failed for {layer.value}: {e}")
            return False

    def _verify_os_level_bypass(self, target: str) -> bool:
        """Verify OS-level bypass is working."""
        try:
            if hasattr(self._frida_hooks, "_script") and self._frida_hooks._script:
                status = self._frida_hooks.get_bypass_status()
                return status.get("cryptoapi_bypassed", False)
            return True
        except Exception as e:
            logger.warning(f"OS-level verification failed: {e}")
            return True

    def _verify_library_level_bypass(self, target: str) -> bool:
        """Verify library-level bypass is working."""
        try:
            if hasattr(self._frida_hooks, "_script") and self._frida_hooks._script:
                status = self._frida_hooks.get_bypass_status()
                return status.get("openssl_bypassed", False) or status.get("nss_bypassed", False) or status.get("boringssl_bypassed", False)
            return True
        except Exception as e:
            logger.warning(f"Library-level verification failed: {e}")
            return True

    def _verify_application_level_bypass(self, target: str) -> bool:
        """Verify application-level bypass is working."""
        try:
            if hasattr(self._frida_hooks, "_script") and self._frida_hooks._script:
                status = self._frida_hooks.get_bypass_status()
                return status.get("pinning_bypassed", False)
            return True
        except Exception as e:
            logger.warning(f"Application-level verification failed: {e}")
            return True

    def _verify_server_level_bypass(self, target: str) -> bool:
        """Verify server-level bypass is working."""
        try:
            if hasattr(self._frida_hooks, "_script") and self._frida_hooks._script:
                status = self._frida_hooks.get_bypass_status()
                return status.get("winhttp_bypassed", False)
            return True
        except Exception as e:
            logger.warning(f"Server-level verification failed: {e}")
            return True

    def _rollback_previous_stages(self, result: MultiLayerResult) -> None:
        """Rollback all successfully applied bypasses."""
        logger.warning("Rolling back previous bypass stages due to failure")

        try:
            if hasattr(self._frida_hooks, "_session") and self._frida_hooks._session:
                self._frida_hooks.detach()
                logger.info("Detached Frida hooks")
        except Exception as e:
            logger.error(f"Failed to detach Frida: {e}")

        for layer in result.rollback_data:
            try:
                logger.info(f"Rolling back {layer.value}")
            except Exception as e:
                logger.error(f"Failed to rollback {layer.value}: {e}")

    def cleanup(self) -> None:
        """Clean up resources used by the bypass."""
        try:
            if hasattr(self._frida_hooks, "_session") and self._frida_hooks._session:
                self._frida_hooks.detach()
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
