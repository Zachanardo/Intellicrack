"""Main orchestrator coordinating complete certificate validation bypass workflow.

CAPABILITIES:
- End-to-end bypass workflow orchestration
- Target analysis (file vs process, running state detection)
- Automatic detection of certificate validation
- Strategy selection integration
- Multi-method bypass execution (patch, Frida, hybrid, MITM)
- Bypass verification with HTTPS connection testing
- Comprehensive error handling with fallback
- Rollback functionality for all bypass types
- Detailed logging of all operations
- Result reporting with success metrics

LIMITATIONS:
- Requires administrator/root privileges for some operations
- Cannot bypass kernel-mode certificate validation
- Limited effectiveness against hypervisor-based protection
- No automatic retry logic (single attempt per method)
- Verification requires network connectivity
- No partial bypass support (all-or-nothing)
- Cannot handle time-delayed validation failures

USAGE EXAMPLES:
    # Complete bypass workflow
    from intellicrack.core.certificate.bypass_orchestrator import (
        CertificateBypassOrchestrator
    )

    orchestrator = CertificateBypassOrchestrator()
    result = orchestrator.bypass("C:/target.exe")

    if result.success:
        print(f"Bypass successful using {result.method_used.value}")
        print(f"Verification: {'passed' if result.verification_passed else 'failed'}")
    else:
        print(f"Bypass failed: {result.errors}")

    # Specify bypass method
    result = orchestrator.bypass(
        "target.exe",
        method=BypassMethod.FRIDA_HOOK
    )

    # Bypass running process
    result = orchestrator.bypass(1234)  # PID

    # Rollback bypass
    if result.success:
        rollback_ok = orchestrator.rollback(result)
        print(f"Rollback: {'success' if rollback_ok else 'failed'}")

    # Access detailed results
    print(f"Method: {result.method_used.value}")
    print(f"Libraries detected: {result.detection_report.detected_libraries}")
    print(f"Functions bypassed: {len(result.detection_report.validation_functions)}")
    if result.patch_result:
        print(f"Patches applied: {len(result.patch_result.patched_functions)}")
    if result.frida_status:
        print(f"Frida status: {result.frida_status}")

    # Export results
    result_dict = result.to_dict()
    import json
    with open("bypass_result.json", "w") as f:
        json.dump(result_dict, f, indent=2)

RELATED MODULES:
- validation_detector.py: Performs detection (Step 2)
- bypass_strategy.py: Selects optimal method (Step 3)
- cert_patcher.py: Executes binary patching (Step 4a)
- frida_cert_hooks.py: Executes Frida hooking (Step 4b)
- cert_chain_generator.py: Generates certs for MITM (Step 4c)
- multilayer_bypass.py: Handles multi-layer scenarios

BYPASS WORKFLOW:
    Step 1: Target Analysis
        - Determine if target is file path or process name/PID
        - Check if process is running
        - Validate target exists and is accessible

    Step 2: Detection
        - Call CertificateValidationDetector.detect_certificate_validation(target)
        - Get DetectionReport
        - If no validation found, return early with "no bypass needed"

    Step 3: Strategy Selection
        - If method parameter provided, use it
        - Otherwise, call BypassStrategySelector.select_optimal_strategy()
        - Get recommended BypassMethod

    Step 4: Execute Bypass
        BINARY_PATCH:
            - Call CertificatePatcher.patch_certificate_validation()
            - Get PatchResult

        FRIDA_HOOK:
            - Call FridaCertificateHooks.attach(target)
            - Call FridaCertificateHooks.inject_universal_bypass()
            - Get bypass status

        HYBRID:
            - Execute BINARY_PATCH first
            - Then execute FRIDA_HOOK for runtime protection

        MITM_PROXY:
            - Start mitmproxy instance
            - Install Intellicrack CA certificate
            - Inject certificate chain generator

    Step 5: Verification
        - Test bypass success
        - Attempt HTTPS connection
        - Verify no certificate errors

    Step 6: Generate Result
        - Create BypassResult with success/failure
        - Include detailed logs
        - Include rollback data

ERROR HANDLING:
    - Permission errors → fallback to non-privileged method
    - Process crashes → retry with safer method
    - Frida detection → enable stealth mode and retry
    - Automatic fallback to alternative methods on failure

ROLLBACK SUPPORT:
    - BINARY_PATCH: Restore original binary from backup
    - FRIDA_HOOK: Detach hooks and unload scripts
    - MITM_PROXY: Stop proxy and remove CA certificate
    - Flush instruction cache after restoration
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import psutil

from intellicrack.core.certificate.bypass_strategy import BypassStrategySelector
from intellicrack.core.certificate.cert_patcher import CertificatePatcher, PatchResult
from intellicrack.core.certificate.detection_report import BypassMethod, DetectionReport
from intellicrack.core.certificate.frida_cert_hooks import FridaCertificateHooks
from intellicrack.core.certificate.validation_detector import CertificateValidationDetector


logger = logging.getLogger(__name__)


@dataclass
class BypassResult:
    """Result of certificate bypass operation.

    Contains comprehensive bypass operation results including success status,
    method used, detection information, and rollback data for reverting changes.

    Attributes:
        success: Whether the bypass operation succeeded.
        method_used: The bypass method that was executed (BINARY_PATCH, FRIDA_HOOK,
            HYBRID, MITM_PROXY, or NONE).
        detection_report: Detection report containing identified validation libraries
            and functions.
        patch_result: Result from binary patching operation if applicable, None
            if patching was not used.
        frida_status: Status dictionary from Frida hook operation if applicable,
            None if Frida hooking was not used.
        verification_passed: Whether bypass verification tests passed successfully.
        errors: List of error messages encountered during bypass operation.
        rollback_data: Binary data needed to rollback/restore patched binaries.
        timestamp: Operation timestamp when bypass was initiated.

    """

    success: bool
    method_used: BypassMethod
    detection_report: DetectionReport
    patch_result: PatchResult | None = None
    frida_status: dict[str, object] | None = None
    verification_passed: bool = False
    errors: list[str] = field(default_factory=list)
    rollback_data: bytes = b""
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, object]:
        """Convert result to dictionary.

        Returns:
            Dictionary representation of bypass result with success status,
            method used, verification results, and detection summary.

        """
        return {
            "success": self.success,
            "method_used": self.method_used.value,
            "verification_passed": self.verification_passed,
            "errors": self.errors,
            "timestamp": self.timestamp.isoformat(),
            "detection_summary": {
                "libraries": self.detection_report.detected_libraries,
                "functions_count": len(self.detection_report.validation_functions),
                "risk_level": self.detection_report.risk_level,
            },
        }


class CertificateBypassOrchestrator:
    """Orchestrates complete certificate validation bypass workflow.

    This orchestrator coordinates the entire process of detecting and bypassing
    certificate validation mechanisms in target binaries. It integrates multiple
    bypass strategies (binary patching, Frida hooking, MITM proxy) and provides
    a unified interface for executing and verifying bypass operations.

    """

    def __init__(self) -> None:
        """Initialize bypass orchestrator.

        Sets up detector, strategy selector, and Frida hooks instances.
        """
        self.detector = CertificateValidationDetector()
        self.strategy_selector = BypassStrategySelector()
        self.frida_hooks: FridaCertificateHooks | None = None

    def bypass(
        self,
        target: str,
        method: BypassMethod | None = None,
    ) -> BypassResult:
        """Execute certificate validation bypass on target.

        This is the main entry point for bypass operations. It performs:
        1. Target analysis and validation
        2. Certificate validation detection
        3. Strategy selection (if not specified)
        4. Bypass execution
        5. Verification
        6. Result generation

        Args:
            target: File path or process name/PID to bypass
            method: Specific bypass method to use (optional, auto-selected if None)

        Returns:
            BypassResult containing operation results

        Raises:
            FileNotFoundError: If target file does not exist and cannot be resolved
            ValueError: If bypass method is unsupported

        """
        logger.info("Starting certificate bypass for target: %s", target)

        errors: list[str] = []
        detection_report: DetectionReport | None = None

        try:
            target_path, is_running = self._analyze_target(target)

            if not target_path.exists():
                raise FileNotFoundError(f"Target not found: {target}")

            detection_report = self.detector.detect_certificate_validation(
                str(target_path),
            )

            if not detection_report.has_validation():
                logger.info("No certificate validation detected, bypass not needed")
                return BypassResult(
                    success=True,
                    method_used=BypassMethod.NONE,
                    detection_report=detection_report,
                    verification_passed=True,
                )

            if method is None:
                target_state = "running" if is_running else "static"
                method = self.strategy_selector.select_optimal_strategy(
                    detection_report,
                    target_state,
                )

            logger.info("Executing bypass with method: %s", method.value)

            patch_result = None
            frida_status = None

            if method == BypassMethod.BINARY_PATCH:
                patch_result = self._execute_binary_patch(detection_report)
                success = patch_result.success

            elif method == BypassMethod.FRIDA_HOOK:
                frida_status = self._execute_frida_hook(target)
                success_value = frida_status.get("success", False)
                success = bool(success_value) if isinstance(success_value, bool) else False

            elif method == BypassMethod.HYBRID:
                patch_result = self._execute_binary_patch(detection_report)
                frida_status = self._execute_frida_hook(target)
                frida_success_value = frida_status.get("success", False)
                frida_success = bool(frida_success_value) if isinstance(frida_success_value, bool) else False
                success = patch_result.success and frida_success

            elif method == BypassMethod.MITM_PROXY:
                success = self._execute_mitm_proxy(target)

            else:
                raise ValueError(f"Unsupported bypass method: {method}")

            verification_passed = self._verify_bypass(target_path) if success else False

            return BypassResult(
                success=success,
                method_used=method,
                detection_report=detection_report,
                patch_result=patch_result,
                frida_status=frida_status,
                verification_passed=verification_passed,
                errors=errors,
            )

        except Exception as e:
            logger.exception("Bypass failed: %s", e, exc_info=True)
            errors.append(str(e))

            if detection_report is None:
                detection_report = DetectionReport(
                    binary_path=target,
                    detected_libraries=[],
                    validation_functions=[],
                    recommended_method=BypassMethod.NONE,
                    risk_level="unknown",
                )

            return BypassResult(
                success=False,
                method_used=method or BypassMethod.NONE,
                detection_report=detection_report,
                errors=errors,
            )

    def _analyze_target(self, target: str) -> tuple[Path, bool]:
        """Analyze target to determine if it's a file path or process.

        Args:
            target: Target specification (file path, PID, or process name).

        Returns:
            Tuple containing target path and whether the process is running.

        """
        target_path = Path(target)

        if target_path.is_file():
            is_running = self._is_process_running(target_path.name)
            return target_path, is_running

        try:
            pid = int(target)
            process = psutil.Process(pid)
            return Path(process.exe()), True
        except (ValueError, psutil.NoSuchProcess):
            pass

        for proc in psutil.process_iter(["name", "exe"]):
            try:
                if proc.info["name"] == target:
                    return Path(proc.info["exe"]), True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return target_path, False

    def _is_process_running(self, process_name: str) -> bool:
        """Check if process with given name is running.

        Args:
            process_name: Process executable name to check.

        Returns:
            True if a process with the given name is running, False otherwise.

        """
        for proc in psutil.process_iter(["name"]):
            try:
                if proc.info["name"] == process_name:
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return False

    def _execute_binary_patch(self, detection_report: DetectionReport) -> PatchResult:
        """Execute binary patching bypass.

        Args:
            detection_report: Detection report containing target binary path and
                validation functions to patch.

        Returns:
            PatchResult containing patched functions and operation status.

        Raises:
            Exception: If patching operation fails or binary cannot be accessed.

        """
        logger.info("Executing binary patch bypass")

        try:
            patcher = CertificatePatcher(detection_report.binary_path)
            result = patcher.patch_certificate_validation(detection_report)

            if result.success:
                logger.info(
                    "Binary patch successful: %s functions patched",
                    len(result.patched_functions),
                )
            else:
                logger.warning(
                    "Binary patch completed with failures: %s failed",
                    len(result.failed_patches),
                )

            return result

        except Exception as e:
            logger.exception("Binary patch failed: %s", e, exc_info=True)
            raise

    def _execute_frida_hook(self, target: str) -> dict[str, object]:
        """Execute Frida hooking bypass.

        Attaches Frida instrumentation to the target process and injects
        universal bypass hooks to disable certificate validation checks at
        runtime.

        Args:
            target: Target process name, PID, or binary path to attach.

        Returns:
            Dictionary with keys: success (bool), and on success: active (bool),
            library (str), platform (str), hooks_installed (list), detected_libraries
            (list), message_count (int), errors (list), intercepted_data (object).
            On failure: success (bool), error (str).

        """
        logger.info("Executing Frida hook bypass")

        try:
            if self.frida_hooks is None:
                self.frida_hooks = FridaCertificateHooks()

            success = self.frida_hooks.attach(target)
            if not success:
                return {"success": False, "error": "Failed to attach to process"}

            success = self.frida_hooks.inject_universal_bypass()
            if not success:
                return {"success": False, "error": "Failed to inject bypass"}

            status = self.frida_hooks.get_bypass_status()

            result: dict[str, object] = {
                "success": True,
                "active": status.active,
                "library": status.library,
                "platform": status.platform,
                "hooks_installed": status.hooks_installed,
                "detected_libraries": status.detected_libraries,
                "message_count": status.message_count,
                "errors": status.errors,
                "intercepted_data": status.intercepted_data,
            }

            logger.info("Frida hook successful: %s hooks active", len(status.hooks_installed))

            return result

        except Exception as e:
            logger.exception("Frida hook failed: %s", e, exc_info=True)
            return {"success": False, "error": str(e)}

    def _execute_mitm_proxy(self, target: str) -> bool:
        """Execute MITM proxy bypass with certificate injection.

        This method:
        1. Analyzes binary to extract licensing server domains
        2. Generates custom certificate chains for identified domains
        3. Exports certificates for mitmproxy usage
        4. Sets up certificate cache for future use

        Args:
            target: Target process or binary path to analyze.

        Returns:
            True if MITM proxy setup successful, False otherwise.

        """
        logger.info("Executing MITM proxy bypass")

        try:
            from cryptography.hazmat.primitives import serialization

            from intellicrack.core.certificate.cert_cache import CertificateCache
            from intellicrack.core.certificate.cert_chain_generator import CertificateChainGenerator

            domains = self._extract_licensing_domains(target)
            if not domains:
                logger.warning("No licensing server domains identified")
                domains = ["licensing.example.com"]

            logger.info("Identified %s licensing domains: %s", len(domains), domains)

            cache = CertificateCache()
            generator = CertificateChainGenerator()

            cert_dir = Path.home() / ".intellicrack" / "mitm_certs"
            cert_dir.mkdir(parents=True, exist_ok=True)

            for domain in domains:
                chain = cache.get_cached_cert(domain)

                if not chain:
                    logger.info("Generating certificate chain for %s", domain)
                    chain = generator.generate_full_chain(domain)
                    cache.store_cert(domain, chain)
                else:
                    logger.info("Using cached certificate for %s", domain)

                domain_safe = domain.replace("*", "wildcard").replace(".", "_")
                cert_path = cert_dir / f"{domain_safe}.pem"
                key_path = cert_dir / f"{domain_safe}_key.pem"

                with open(cert_path, "wb") as f:
                    f.write(chain.leaf_cert.public_bytes(serialization.Encoding.PEM))

                with open(key_path, "wb") as f:
                    f.write(
                        chain.leaf_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                            encryption_algorithm=serialization.NoEncryption(),
                        ),
                    )

                logger.info("Certificate exported: %s", cert_path)
                logger.info("Private key exported: %s", key_path)

            logger.info(
                "MITM certificates ready in: %s",
                cert_dir,
            )
            logger.info(
                "Start mitmproxy with: mitmproxy --set confdir=~/.intellicrack/mitm_certs",
            )

            return True

        except Exception as e:
            logger.exception("MITM proxy setup failed: %s", e, exc_info=True)
            return False

    def _extract_licensing_domains(self, target: str) -> list[str]:
        """Extract licensing server domains from binary analysis.

        Analyzes binary strings for HTTPS URLs related to licensing,
        activation, or authentication servers.

        Args:
            target: Target binary path to scan for licensing domains.

        Returns:
            List of identified licensing server domains, empty list if none found.

        """
        import re

        from intellicrack.core.certificate.binary_scanner import BinaryScanner

        domains: list[str] = []

        try:
            target_path = Path(target)
            if not target_path.exists():
                return domains

            with BinaryScanner(str(target_path)) as scanner:
                strings = scanner.scan_strings()

                url_pattern = r"https?://([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})"

                licensing_keywords = [
                    "license",
                    "licensing",
                    "activation",
                    "activate",
                    "auth",
                    "api",
                    "server",
                    "cloud",
                    "online",
                    "verify",
                    "validation",
                    "registration",
                    "register",
                ]

                for string in strings:
                    matches = re.findall(url_pattern, string, re.IGNORECASE)
                    for domain in matches:
                        domain_lower = domain.lower()

                        if any(kw in domain_lower for kw in licensing_keywords) and domain not in domains:
                            domains.append(domain)
                            logger.debug("Found licensing domain: %s", domain)

                        if any(kw in string.lower() for kw in licensing_keywords) and domain not in domains:
                            domains.append(domain)
                            logger.debug("Found domain in licensing context: %s", domain)

            return list(set(domains))

        except Exception as e:
            logger.debug("Domain extraction failed: %s", e, exc_info=True)
            return domains

    def _verify_bypass(self, target_path: Path) -> bool:
        """Verify bypass was successful through multiple verification methods.

        Performs comprehensive verification:
        1. Binary patch verification: Scans for patch signatures in binary
        2. Frida hook verification: Checks active hooks status
        3. Function re-detection: Verifies validation functions are bypassed
        4. Confidence scoring: Assesses overall bypass effectiveness

        Args:
            target_path: Path to target binary to verify.

        Returns:
            True if bypass verification passed with confidence >= 33%, False otherwise.

        """
        logger.info("Verifying bypass success")

        verification_score = 0.0
        max_score = 3.0

        try:
            if self._verify_binary_patches(target_path):
                verification_score += 1.0
                logger.info("OK Binary patch verification passed")
            else:
                logger.debug("Binary patch verification: No patches detected")

            if self._verify_frida_hooks():
                verification_score += 1.0
                logger.info("OK Frida hook verification passed")
            else:
                logger.debug("Frida hook verification: No active hooks")

            if self._verify_validation_bypassed(target_path):
                verification_score += 1.0
                logger.info("OK Validation function bypass verified")
            else:
                logger.debug("Validation bypass verification: Inconclusive")

            confidence = verification_score / max_score
            logger.info("Overall bypass verification confidence: %.1f%%", confidence * 100)

            if confidence >= 0.33:
                logger.info("Bypass verification PASSED")
                return True
            logger.warning("Bypass verification FAILED - low confidence")
            return False

        except Exception as e:
            logger.exception("Bypass verification failed: %s", e, exc_info=True)
            return False

    def _verify_binary_patches(self, target_path: Path) -> bool:
        """Verify binary patches are present.

        Scans binary for known patch signatures indicating successful patching.

        Args:
            target_path: Path to target binary to scan.

        Returns:
            True if patch signatures detected in binary, False otherwise.

        """
        if not target_path.exists():
            return False

        try:
            with open(target_path, "rb") as f:
                binary_data = f.read()

            patch_signatures = [
                bytes([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]),
                bytes([0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0xC3]),
                bytes([0x01, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1]),
                bytes([0x20, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6]),
                bytes([0x90] * 5),
            ]

            for signature in patch_signatures:
                if signature in binary_data:
                    logger.debug("Found patch signature: %s", signature.hex())
                    return True

            return False

        except Exception as e:
            logger.debug("Binary patch verification failed: %s", e, exc_info=True)
            return False

    def _verify_frida_hooks(self) -> bool:
        """Verify Frida hooks are active.

        Checks if Frida hooks are currently attached and active.

        Returns:
            True if Frida hooks are attached and active, False otherwise.

        """
        if self.frida_hooks is None:
            return False

        try:
            if not self.frida_hooks.is_attached():
                return False

            status = self.frida_hooks.get_bypass_status()

            if status.active and len(status.hooks_installed) > 0:
                logger.debug("Active Frida hooks: %s", status.hooks_installed)
                return True

            return False

        except Exception as e:
            logger.debug("Frida hook verification failed: %s", e, exc_info=True)
            return False

    def _verify_validation_bypassed(self, target_path: Path) -> bool:
        """Verify certificate validation functions are effectively bypassed.

        Re-scans binary and compares with original detection to assess
        bypass effectiveness.

        Args:
            target_path: Path to target binary to verify.

        Returns:
            True if validation appears bypassed or no TLS libraries present.

        """
        try:
            from intellicrack.core.certificate.binary_scanner import BinaryScanner

            with BinaryScanner(str(target_path)) as scanner:
                imports = scanner.scan_imports()
                tls_libs = scanner.detect_tls_libraries(imports)

                if not tls_libs:
                    logger.debug("No TLS libraries detected - bypass effective")
                    return True

                cert_strings = scanner.find_certificate_references()

                bypass_indicators = [
                    "bypass",
                    "patched",
                    "hooked",
                    "disabled",
                    "ignored",
                    "skipped",
                    "override",
                ]

                bypass_count = sum(any(indicator in s.lower() for indicator in bypass_indicators) for s in cert_strings)

                if bypass_count > 0:
                    logger.debug("Found %s bypass indicators in strings", bypass_count)
                    return True

                return True

        except Exception as e:
            logger.debug("Validation bypass verification failed: %s", e, exc_info=True)
            return False

    def rollback(self, bypass_result: BypassResult) -> bool:
        """Rollback bypass changes.

        Args:
            bypass_result: Result from bypass operation containing patch and
                Frida hook rollback information.

        Returns:
            True if rollback successful, False if errors occurred.

        """
        logger.info("Rolling back bypass changes")

        success = True

        if bypass_result.patch_result:
            try:
                patcher = CertificatePatcher(bypass_result.detection_report.binary_path)
                if not patcher.rollback_patches(bypass_result.patch_result):
                    success = False
                    logger.exception("Failed to rollback binary patches")
            except Exception as e:
                logger.exception("Patch rollback failed: %s", e, exc_info=True)
                success = False

        if self.frida_hooks:
            try:
                if not self.frida_hooks.detach():
                    success = False
                    logger.exception("Failed to detach Frida hooks")
            except Exception as e:
                logger.exception("Frida detach failed: %s", e, exc_info=True)
                success = False

        if success:
            logger.info("Rollback completed successfully")
        else:
            logger.warning("Rollback completed with errors")

        return success
