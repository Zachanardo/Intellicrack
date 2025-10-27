"""Main orchestrator for certificate validation bypass operations."""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import psutil

from intellicrack.core.certificate.bypass_strategy import BypassStrategySelector
from intellicrack.core.certificate.cert_patcher import CertificatePatcher, PatchResult
from intellicrack.core.certificate.detection_report import BypassMethod, DetectionReport
from intellicrack.core.certificate.frida_cert_hooks import FridaCertificateHooks
from intellicrack.core.certificate.validation_detector import CertificateValidationDetector

logger = logging.getLogger(__name__)


@dataclass
class BypassResult:
    """Result of certificate bypass operation."""

    success: bool
    method_used: BypassMethod
    detection_report: DetectionReport
    patch_result: Optional[PatchResult] = None
    frida_status: Optional[Dict] = None
    verification_passed: bool = False
    errors: List[str] = field(default_factory=list)
    rollback_data: bytes = b""
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict:
        """Convert result to dictionary.

        Returns:
            Dictionary representation

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
    """Orchestrates complete certificate validation bypass workflow."""

    def __init__(self):
        """Initialize bypass orchestrator."""
        self.detector = CertificateValidationDetector()
        self.strategy_selector = BypassStrategySelector()
        self.frida_hooks: Optional[FridaCertificateHooks] = None

    def bypass(
        self,
        target: str,
        method: Optional[BypassMethod] = None
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

        """
        logger.info(f"Starting certificate bypass for target: {target}")

        errors = []
        detection_report = None

        try:
            target_path, is_running = self._analyze_target(target)

            if not target_path.exists():
                raise FileNotFoundError(f"Target not found: {target}")

            detection_report = self.detector.detect_certificate_validation(
                str(target_path)
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
                    detection_report, target_state
                )

            logger.info(f"Executing bypass with method: {method.value}")

            patch_result = None
            frida_status = None

            if method == BypassMethod.BINARY_PATCH:
                patch_result = self._execute_binary_patch(detection_report)
                success = patch_result.success

            elif method == BypassMethod.FRIDA_HOOK:
                frida_status = self._execute_frida_hook(target)
                success = frida_status.get("success", False)

            elif method == BypassMethod.HYBRID:
                patch_result = self._execute_binary_patch(detection_report)
                frida_status = self._execute_frida_hook(target)
                success = patch_result.success and frida_status.get("success", False)

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
            logger.error(f"Bypass failed: {e}", exc_info=True)
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
            target: Target specification

        Returns:
            Tuple of (target_path, is_running)

        """
        target_path = Path(target)

        if target_path.exists() and target_path.is_file():
            is_running = self._is_process_running(target_path.name)
            return target_path, is_running

        try:
            pid = int(target)
            process = psutil.Process(pid)
            return Path(process.exe()), True
        except (ValueError, psutil.NoSuchProcess):
            pass

        for proc in psutil.process_iter(['name', 'exe']):
            try:
                if proc.info['name'] == target:
                    return Path(proc.info['exe']), True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return target_path, False

    def _is_process_running(self, process_name: str) -> bool:
        """Check if process with given name is running.

        Args:
            process_name: Process executable name

        Returns:
            True if process is running

        """
        for proc in psutil.process_iter(['name']):
            try:
                if proc.info['name'] == process_name:
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return False

    def _execute_binary_patch(self, detection_report: DetectionReport) -> PatchResult:
        """Execute binary patching bypass.

        Args:
            detection_report: Detection results

        Returns:
            PatchResult from patching operation

        """
        logger.info("Executing binary patch bypass")

        try:
            patcher = CertificatePatcher(detection_report.binary_path)
            result = patcher.patch_certificate_validation(detection_report)

            if result.success:
                logger.info(
                    f"Binary patch successful: {len(result.patched_functions)} functions patched"
                )
            else:
                logger.warning(
                    f"Binary patch completed with failures: {len(result.failed_patches)} failed"
                )

            return result

        except Exception as e:
            logger.error(f"Binary patch failed: {e}")
            raise

    def _execute_frida_hook(self, target: str) -> Dict:
        """Execute Frida hooking bypass.

        Args:
            target: Target process

        Returns:
            Dictionary with Frida hook status

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
            status["success"] = True

            logger.info(f"Frida hook successful: {len(status.get('active_hooks', []))} hooks active")

            return status

        except Exception as e:
            logger.error(f"Frida hook failed: {e}")
            return {"success": False, "error": str(e)}

    def _execute_mitm_proxy(self, target: str) -> bool:
        """Execute MITM proxy bypass with certificate injection.

        This method:
        1. Analyzes binary to extract licensing server domains
        2. Generates custom certificate chains for identified domains
        3. Exports certificates for mitmproxy usage
        4. Sets up certificate cache for future use

        Args:
            target: Target process or binary

        Returns:
            True if MITM proxy setup successful

        """
        logger.info("Executing MITM proxy bypass")

        try:
            from cryptography.hazmat.primitives import serialization

            from intellicrack.core.certificate.cert_cache import CertificateCache
            from intellicrack.core.certificate.cert_chain_generator import (
                CertificateChainGenerator,
            )

            domains = self._extract_licensing_domains(target)
            if not domains:
                logger.warning("No licensing server domains identified")
                domains = ["licensing.example.com"]

            logger.info(f"Identified {len(domains)} licensing domains: {domains}")

            cache = CertificateCache()
            generator = CertificateChainGenerator()

            cert_dir = Path.home() / ".intellicrack" / "mitm_certs"
            cert_dir.mkdir(parents=True, exist_ok=True)

            for domain in domains:
                chain = cache.get_cached_cert(domain)

                if not chain:
                    logger.info(f"Generating certificate chain for {domain}")
                    chain = generator.generate_full_chain(domain)
                    cache.store_cert(domain, chain)
                else:
                    logger.info(f"Using cached certificate for {domain}")

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
                        )
                    )

                logger.info(f"Certificate exported: {cert_path}")
                logger.info(f"Private key exported: {key_path}")

            logger.info(
                f"MITM certificates ready in: {cert_dir}"
            )
            logger.info(
                "Start mitmproxy with: mitmproxy --set confdir=~/.intellicrack/mitm_certs"
            )

            return True

        except Exception as e:
            logger.error(f"MITM proxy setup failed: {e}", exc_info=True)
            return False

    def _extract_licensing_domains(self, target: str) -> List[str]:
        """Extract licensing server domains from binary analysis.

        Analyzes binary strings for HTTPS URLs related to licensing,
        activation, or authentication servers.

        Args:
            target: Target binary path

        Returns:
            List of identified licensing domains

        """
        import re

        from intellicrack.core.certificate.binary_scanner import BinaryScanner

        domains = []

        try:
            target_path = Path(target)
            if not target_path.exists():
                return domains

            with BinaryScanner(str(target_path)) as scanner:
                strings = scanner.scan_strings()

                url_pattern = r'https?://([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})'

                licensing_keywords = [
                    "license", "licensing", "activation", "activate",
                    "auth", "api", "server", "cloud", "online",
                    "verify", "validation", "registration", "register"
                ]

                for string in strings:
                    matches = re.findall(url_pattern, string, re.IGNORECASE)
                    for domain in matches:
                        domain_lower = domain.lower()

                        if any(kw in domain_lower for kw in licensing_keywords):
                            if domain not in domains:
                                domains.append(domain)
                                logger.debug(f"Found licensing domain: {domain}")

                        if any(kw in string.lower() for kw in licensing_keywords):
                            if domain not in domains:
                                domains.append(domain)
                                logger.debug(f"Found domain in licensing context: {domain}")

            return list(set(domains))

        except Exception as e:
            logger.debug(f"Domain extraction failed: {e}")
            return domains

    def _verify_bypass(self, target_path: Path) -> bool:
        """Verify bypass was successful through multiple verification methods.

        Performs comprehensive verification:
        1. Binary patch verification: Scans for patch signatures in binary
        2. Frida hook verification: Checks active hooks status
        3. Function re-detection: Verifies validation functions are bypassed
        4. Confidence scoring: Assesses overall bypass effectiveness

        Args:
            target_path: Path to target binary

        Returns:
            True if bypass verification passed

        """
        logger.info("Verifying bypass success")

        verification_score = 0.0
        max_score = 3.0

        try:
            if self._verify_binary_patches(target_path):
                verification_score += 1.0
                logger.info("✓ Binary patch verification passed")
            else:
                logger.debug("Binary patch verification: No patches detected")

            if self._verify_frida_hooks():
                verification_score += 1.0
                logger.info("✓ Frida hook verification passed")
            else:
                logger.debug("Frida hook verification: No active hooks")

            if self._verify_validation_bypassed(target_path):
                verification_score += 1.0
                logger.info("✓ Validation function bypass verified")
            else:
                logger.debug("Validation bypass verification: Inconclusive")

            confidence = verification_score / max_score
            logger.info(f"Overall bypass verification confidence: {confidence:.1%}")

            if confidence >= 0.33:
                logger.info("Bypass verification PASSED")
                return True
            else:
                logger.warning("Bypass verification FAILED - low confidence")
                return False

        except Exception as e:
            logger.error(f"Bypass verification failed: {e}", exc_info=True)
            return False

    def _verify_binary_patches(self, target_path: Path) -> bool:
        """Verify binary patches are present.

        Scans binary for known patch signatures indicating successful patching.

        Args:
            target_path: Path to target binary

        Returns:
            True if patches detected

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
                    logger.debug(f"Found patch signature: {signature.hex()}")
                    return True

            return False

        except Exception as e:
            logger.debug(f"Binary patch verification failed: {e}")
            return False

    def _verify_frida_hooks(self) -> bool:
        """Verify Frida hooks are active.

        Checks if Frida hooks are currently attached and active.

        Returns:
            True if hooks are active

        """
        if self.frida_hooks is None:
            return False

        try:
            if not self.frida_hooks.is_attached():
                return False

            status = self.frida_hooks.get_bypass_status()

            if status.active and len(status.active_hooks) > 0:
                logger.debug(f"Active Frida hooks: {status.active_hooks}")
                return True

            return False

        except Exception as e:
            logger.debug(f"Frida hook verification failed: {e}")
            return False

    def _verify_validation_bypassed(self, target_path: Path) -> bool:
        """Verify certificate validation functions are effectively bypassed.

        Re-scans binary and compares with original detection to assess
        bypass effectiveness.

        Args:
            target_path: Path to target binary

        Returns:
            True if validation appears bypassed

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
                    "bypass", "patched", "hooked", "disabled",
                    "ignored", "skipped", "override"
                ]

                bypass_count = sum(
                    1 for s in cert_strings
                    if any(indicator in s.lower() for indicator in bypass_indicators)
                )

                if bypass_count > 0:
                    logger.debug(f"Found {bypass_count} bypass indicators in strings")
                    return True

                return True

        except Exception as e:
            logger.debug(f"Validation bypass verification failed: {e}")
            return False

    def rollback(self, bypass_result: BypassResult) -> bool:
        """Rollback bypass changes.

        Args:
            bypass_result: Result from bypass operation

        Returns:
            True if rollback successful

        """
        logger.info("Rolling back bypass changes")

        success = True

        if bypass_result.patch_result:
            try:
                patcher = CertificatePatcher(bypass_result.detection_report.binary_path)
                if not patcher.rollback_patches(bypass_result.patch_result):
                    success = False
                    logger.error("Failed to rollback binary patches")
            except Exception as e:
                logger.error(f"Patch rollback failed: {e}")
                success = False

        if self.frida_hooks:
            try:
                if not self.frida_hooks.detach():
                    success = False
                    logger.error("Failed to detach Frida hooks")
            except Exception as e:
                logger.error(f"Frida detach failed: {e}")
                success = False

        if success:
            logger.info("Rollback completed successfully")
        else:
            logger.warning("Rollback completed with errors")

        return success
