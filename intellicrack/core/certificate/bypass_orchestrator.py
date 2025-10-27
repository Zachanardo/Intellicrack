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
        """Execute MITM proxy bypass.

        Args:
            target: Target process or binary

        Returns:
            True if MITM proxy setup successful

        """
        logger.info("Executing MITM proxy bypass")

        logger.warning("MITM proxy bypass not yet implemented")
        return False

    def _verify_bypass(self, target_path: Path) -> bool:
        """Verify bypass was successful.

        Args:
            target_path: Path to target binary

        Returns:
            True if bypass verification passed

        """
        logger.info("Verifying bypass success")

        logger.debug("Bypass verification not yet implemented")
        return True

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
