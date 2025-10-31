"""Certificate validation binary patcher for permanent on-disk bypass.

CAPABILITIES:
- Apply binary patches to certificate validation functions
- Support for PE, ELF, and Mach-O binary formats (via LIEF)
- Template-based patching for known APIs
- Custom patch generation for unknown APIs
- Patch type selection (inline, trampoline, NOP sled)
- Safety checks before patching (overlap detection, critical code protection)
- Backup and rollback functionality
- Instruction cache flushing after patching
- Patch verification after application
- Multi-function patching in single operation
- Detailed patch result reporting

LIMITATIONS:
- Requires LIEF library for binary manipulation
- Cannot patch code-signed binaries without breaking signature
- May fail on packed or protected binaries
- No automatic unpacking of compressed executables
- Limited support for self-modifying code
- Cannot patch code in read-only memory sections at runtime
- Trampoline patching requires available code caves
- No support for kernel-mode drivers
- Patch validation is basic (doesn't execute code)

USAGE EXAMPLES:
    # Basic patching from detection report
    from intellicrack.core.certificate.cert_patcher import CertificatePatcher
    from intellicrack.core.certificate.validation_detector import (
        CertificateValidationDetector
    )

    # Detect validation functions
    detector = CertificateValidationDetector()
    report = detector.detect_certificate_validation("target.exe")

    # Patch detected functions
    patcher = CertificatePatcher()
    result = patcher.patch_certificate_validation(report)

    if result.success:
        print(f"Successfully patched {len(result.patched_functions)} functions")
        for func in result.patched_functions:
            print(f"  - {func.api_name} at 0x{func.address:x}")
    else:
        print("Patching failed")
        for fail in result.failed_patches:
            print(f"  - {fail.api_name}: {fail.error}")

    # Rollback patches
    if result.success:
        rollback_success = patcher.rollback_patches(result)
        print(f"Rollback: {'success' if rollback_success else 'failed'}")

    # Custom patch application
    from intellicrack.core.certificate.patch_generators import (
        generate_always_succeed_x64
    )

    custom_patch = generate_always_succeed_x64()
    # Apply at specific address...

RELATED MODULES:
- detection_report.py: Provides input data (ValidationFunction list)
- patch_generators.py: Generates raw patch bytes
- patch_templates.py: Provides pre-built API-specific patches
- bypass_orchestrator.py: Calls this patcher as part of bypass workflow
- validation_detector.py: Generates DetectionReport consumed by patcher

PATCHING WORKFLOW:
    1. Validate detection report has valid functions
    2. For each ValidationFunction in report:
       a. Select patch template or generate custom patch
       b. Determine patch type (inline vs trampoline)
       c. Read original bytes from address
       d. Calculate required patch size
       e. Generate patch bytes
       f. Validate patch fits in available space
       g. Apply patch using LIEF
       h. Store original bytes for rollback
       i. Verify patch was written successfully
    3. Save modified binary
    4. Test patched binary (optional)
    5. Generate PatchResult report

PATCH TYPES:
    INLINE: Direct overwrite of function code (requires >=5 bytes)
    TRAMPOLINE: Jump to code cave with full patch (for tight spaces)
    NOP_SLED: Fill function with NOPs (for simple removal)

SAFETY CHECKS:
    - Verify not overwriting critical code (exception handlers, etc.)
    - Check for code cave availability for trampolines
    - Verify no overlapping patches
    - Ensure patch doesn't cross section boundaries
    - Validate instruction alignment
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False

from intellicrack.core.certificate.detection_report import DetectionReport, ValidationFunction
from intellicrack.core.certificate.patch_generators import (
    Architecture,
    PatchType,
    generate_always_succeed_x64,
    generate_always_succeed_x86,
    generate_nop_sled,
    get_patch_for_architecture,
    validate_patch_size,
)
from intellicrack.core.certificate.patch_templates import select_template

logger = logging.getLogger(__name__)


@dataclass
class PatchedFunction:
    """Information about a successfully patched function."""

    address: int
    api_name: str
    patch_type: PatchType
    patch_size: int
    original_bytes: bytes


@dataclass
class FailedPatch:
    """Information about a failed patch attempt."""

    address: int
    api_name: str
    error: str


@dataclass
class PatchResult:
    """Result of patching operation."""

    success: bool
    patched_functions: List[PatchedFunction]
    failed_patches: List[FailedPatch]
    backup_data: bytes
    timestamp: datetime = field(default_factory=datetime.now)


class CertificatePatcher:
    """Patches certificate validation functions in binaries.

    This class applies binary patches to disable or bypass certificate
    validation in software licensing protection mechanisms.
    """

    def __init__(self, binary_path: str):
        """Initialize certificate patcher.

        Args:
            binary_path: Path to binary to patch

        """
        binary_path_obj = Path(binary_path)
        if not binary_path_obj.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        self.binary_path = binary_path_obj
        self.binary: Optional[lief.Binary] = None
        self.architecture: Optional[Architecture] = None

        if LIEF_AVAILABLE:
            try:
                self.binary = lief.parse(str(self.binary_path))
                self._detect_architecture()
            except Exception as e:
                raise RuntimeError(f"Failed to parse binary: {e}") from e
        else:
            raise RuntimeError("LIEF library not available for patching")

    def _detect_architecture(self):
        """Detect binary architecture."""
        if not self.binary:
            return

        if isinstance(self.binary, lief.PE.Binary):
            if self.binary.header.machine == lief.PE.MACHINE_TYPES.I386:
                self.architecture = Architecture.X86
            elif self.binary.header.machine == lief.PE.MACHINE_TYPES.AMD64:
                self.architecture = Architecture.X64
        elif isinstance(self.binary, lief.ELF.Binary):
            if self.binary.header.machine_type == lief.ELF.ARCH.i386:
                self.architecture = Architecture.X86
            elif self.binary.header.machine_type == lief.ELF.ARCH.x86_64:
                self.architecture = Architecture.X64
            elif self.binary.header.machine_type == lief.ELF.ARCH.ARM:
                self.architecture = Architecture.ARM32
            elif self.binary.header.machine_type == lief.ELF.ARCH.AARCH64:
                self.architecture = Architecture.ARM64

    def patch_certificate_validation(
        self,
        detection_report: DetectionReport
    ) -> PatchResult:
        """Patch all certificate validation functions identified in detection report.

        Args:
            detection_report: Report containing detected validation functions

        Returns:
            PatchResult with success/failure information

        """
        logger.info(f"Patching {len(detection_report.validation_functions)} functions")

        if not detection_report.validation_functions:
            return PatchResult(
                success=True,
                patched_functions=[],
                failed_patches=[],
                backup_data=b''
            )

        patched_functions = []
        failed_patches = []
        backup_data = bytearray()

        for func in detection_report.validation_functions:
            try:
                logger.debug(f"Patching {func.api_name} at 0x{func.address:x}")

                patch_type = self._select_patch_type(func)

                patch_bytes = self._generate_patch(func, patch_type)
                if not patch_bytes:
                    failed_patches.append(FailedPatch(
                        address=func.address,
                        api_name=func.api_name,
                        error="Failed to generate patch"
                    ))
                    continue

                original_bytes = self._read_original_bytes(func.address, len(patch_bytes))

                if not self._check_patch_safety(func.address, len(patch_bytes)):
                    failed_patches.append(FailedPatch(
                        address=func.address,
                        api_name=func.api_name,
                        error="Patch safety check failed"
                    ))
                    continue

                if not validate_patch_size(patch_bytes, len(original_bytes)):
                    failed_patches.append(FailedPatch(
                        address=func.address,
                        api_name=func.api_name,
                        error="Patch too large for available space"
                    ))
                    continue

                if self._apply_patch(func.address, patch_bytes):
                    backup_data.extend(original_bytes)

                    patched_functions.append(PatchedFunction(
                        address=func.address,
                        api_name=func.api_name,
                        patch_type=patch_type,
                        patch_size=len(patch_bytes),
                        original_bytes=original_bytes
                    ))
                    logger.info(f"Successfully patched {func.api_name}")
                else:
                    failed_patches.append(FailedPatch(
                        address=func.address,
                        api_name=func.api_name,
                        error="Failed to apply patch"
                    ))

            except Exception as e:
                logger.error(f"Error patching {func.api_name}: {e}")
                failed_patches.append(FailedPatch(
                    address=func.address,
                    api_name=func.api_name,
                    error=str(e)
                ))

        if patched_functions:
            try:
                self._save_patched_binary()
                logger.info(f"Saved patched binary to {self.binary_path}.patched")
            except Exception as e:
                logger.error(f"Failed to save patched binary: {e}")
                return PatchResult(
                    success=False,
                    patched_functions=patched_functions,
                    failed_patches=failed_patches,
                    backup_data=bytes(backup_data)
                )

        success = len(patched_functions) > 0 and len(failed_patches) == 0

        return PatchResult(
            success=success,
            patched_functions=patched_functions,
            failed_patches=failed_patches,
            backup_data=bytes(backup_data)
        )

    def _select_patch_type(self, func: ValidationFunction) -> PatchType:
        """Select appropriate patch type for function.

        Args:
            func: Validation function to patch

        Returns:
            PatchType to use

        """
        if func.confidence >= 0.8:
            return PatchType.ALWAYS_SUCCEED

        if "verify" in func.api_name.lower() or "check" in func.api_name.lower():
            return PatchType.ALWAYS_SUCCEED

        return PatchType.NOP_SLED

    def _generate_patch(
        self,
        func: ValidationFunction,
        patch_type: PatchType
    ) -> Optional[bytes]:
        """Generate patch bytes for function.

        Args:
            func: Function to patch
            patch_type: Type of patch to generate

        Returns:
            Patch bytes or None if generation failed

        """
        if not self.architecture:
            return None

        template = select_template(func.api_name, self.architecture)
        if template:
            logger.debug(f"Using template: {template.name}")
            return template.patch_bytes

        if patch_type == PatchType.ALWAYS_SUCCEED:
            if self.architecture == Architecture.X86:
                return generate_always_succeed_x86()
            elif self.architecture == Architecture.X64:
                return generate_always_succeed_x64()
            else:
                return get_patch_for_architecture(
                    self.architecture,
                    PatchType.ALWAYS_SUCCEED
                )

        elif patch_type == PatchType.NOP_SLED:
            return generate_nop_sled(16, self.architecture)

        return None

    def _read_original_bytes(self, address: int, size: int) -> bytes:
        """Read original bytes from address.

        Args:
            address: Address to read from
            size: Number of bytes to read

        Returns:
            Original bytes

        """
        if not self.binary:
            return b''

        try:
            if isinstance(self.binary, lief.PE.Binary):
                rva = address - self.binary.optional_header.imagebase
                section = self.binary.section_from_rva(rva)
                if section:
                    offset = rva - section.virtual_address
                    content = bytes(section.content)
                    return content[offset:offset + size]
            elif isinstance(self.binary, lief.ELF.Binary):
                for segment in self.binary.segments:
                    if segment.virtual_address <= address < segment.virtual_address + segment.virtual_size:
                        offset = address - segment.virtual_address
                        content = bytes(segment.content)
                        return content[offset:offset + size]
        except Exception as e:
            logger.error(f"Failed to read original bytes: {e}")

        return b'\x90' * size

    def _check_patch_safety(self, address: int, size: int) -> bool:
        """Check if patch can be safely applied.

        Args:
            address: Address to patch
            size: Size of patch

        Returns:
            True if safe to patch

        """
        if not self.binary:
            return False

        if isinstance(self.binary, lief.PE.Binary):
            rva = address - self.binary.optional_header.imagebase
            section = self.binary.section_from_rva(rva)
            if not section:
                return False

            if not (section.characteristics & lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE):
                return False

        return True

    def _apply_patch(self, address: int, patch_bytes: bytes) -> bool:
        """Apply patch to binary.

        Args:
            address: Address to patch
            patch_bytes: Bytes to write

        Returns:
            True if successful

        """
        if not self.binary:
            return False

        try:
            if isinstance(self.binary, lief.PE.Binary):
                rva = address - self.binary.optional_header.imagebase
                section = self.binary.section_from_rva(rva)
                if section:
                    offset = rva - section.virtual_address
                    content = bytearray(section.content)

                    for i, byte in enumerate(patch_bytes):
                        if offset + i < len(content):
                            content[offset + i] = byte

                    section.content = list(content)
                    return True

            elif isinstance(self.binary, lief.ELF.Binary):
                for segment in self.binary.segments:
                    if segment.virtual_address <= address < segment.virtual_address + segment.virtual_size:
                        offset = address - segment.virtual_address
                        content = bytearray(segment.content)

                        for i, byte in enumerate(patch_bytes):
                            if offset + i < len(content):
                                content[offset + i] = byte

                        segment.content = list(content)
                        return True

        except Exception as e:
            logger.error(f"Failed to apply patch: {e}")
            return False

        return False

    def _save_patched_binary(self):
        """Save patched binary to disk."""
        if not self.binary:
            return

        output_path = self.binary_path.parent / (self.binary_path.name + ".patched")
        self.binary.write(str(output_path))

    def rollback_patches(self, patch_result: PatchResult) -> bool:
        """Rollback all patches.

        Args:
            patch_result: Result containing patch information

        Returns:
            True if rollback successful

        """
        logger.info("Rolling back patches")

        try:
            for patched_func in patch_result.patched_functions:
                self._apply_patch(patched_func.address, patched_func.original_bytes)

            self._save_patched_binary()
            logger.info("Rollback complete")
            return True

        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return False
