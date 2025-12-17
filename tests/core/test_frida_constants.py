"""Production tests for Frida constants and enumerations.

Tests validate enum structure and values for Frida integration:
- ProtectionType enum completeness and values
- HookCategory enum priority levels
- Enum value consistency and uniqueness
- Module-level exports
"""

import pytest

from intellicrack.core.frida_constants import HookCategory, ProtectionType


class TestProtectionTypeEnum:
    """Test ProtectionType enumeration structure and values."""

    def test_protection_type_enum_exists(self) -> None:
        """ProtectionType enum is defined and importable."""
        assert ProtectionType is not None

    def test_protection_type_has_anti_debug(self) -> None:
        """ProtectionType includes ANTI_DEBUG protection."""
        assert hasattr(ProtectionType, "ANTI_DEBUG")
        assert ProtectionType.ANTI_DEBUG.value == "Anti-Debugging"

    def test_protection_type_has_anti_vm(self) -> None:
        """ProtectionType includes ANTI_VM protection."""
        assert hasattr(ProtectionType, "ANTI_VM")
        assert ProtectionType.ANTI_VM.value == "Anti-VM/Sandbox"

    def test_protection_type_has_anti_attach(self) -> None:
        """ProtectionType includes ANTI_ATTACH protection."""
        assert hasattr(ProtectionType, "ANTI_ATTACH")
        assert ProtectionType.ANTI_ATTACH.value == "Anti-Attach"

    def test_protection_type_has_ssl_pinning(self) -> None:
        """ProtectionType includes SSL_PINNING protection."""
        assert hasattr(ProtectionType, "SSL_PINNING")
        assert ProtectionType.SSL_PINNING.value == "SSL Pinning"

    def test_protection_type_has_packing(self) -> None:
        """ProtectionType includes PACKING protection."""
        assert hasattr(ProtectionType, "PACKING")
        assert ProtectionType.PACKING.value == "Packing/Obfuscation"

    def test_protection_type_has_license(self) -> None:
        """ProtectionType includes LICENSE protection."""
        assert hasattr(ProtectionType, "LICENSE")
        assert ProtectionType.LICENSE.value == "License Verification"

    def test_protection_type_has_integrity(self) -> None:
        """ProtectionType includes INTEGRITY protection."""
        assert hasattr(ProtectionType, "INTEGRITY")
        assert ProtectionType.INTEGRITY.value == "Code Integrity"

    def test_protection_type_has_hardware(self) -> None:
        """ProtectionType includes HARDWARE protection."""
        assert hasattr(ProtectionType, "HARDWARE")
        assert ProtectionType.HARDWARE.value == "Hardware Binding"

    def test_protection_type_has_cloud(self) -> None:
        """ProtectionType includes CLOUD protection."""
        assert hasattr(ProtectionType, "CLOUD")
        assert ProtectionType.CLOUD.value == "Cloud Verification"

    def test_protection_type_has_time(self) -> None:
        """ProtectionType includes TIME protection."""
        assert hasattr(ProtectionType, "TIME")
        assert ProtectionType.TIME.value == "Time-based Protection"

    def test_protection_type_has_memory(self) -> None:
        """ProtectionType includes MEMORY protection."""
        assert hasattr(ProtectionType, "MEMORY")
        assert ProtectionType.MEMORY.value == "Memory Protection"

    def test_protection_type_has_memory_protection(self) -> None:
        """ProtectionType includes MEMORY_PROTECTION protection."""
        assert hasattr(ProtectionType, "MEMORY_PROTECTION")
        assert ProtectionType.MEMORY_PROTECTION.value == "Memory Protection Flags"

    def test_protection_type_has_kernel(self) -> None:
        """ProtectionType includes KERNEL protection."""
        assert hasattr(ProtectionType, "KERNEL")
        assert ProtectionType.KERNEL.value == "Kernel-mode Protection"

    def test_protection_type_has_behavior(self) -> None:
        """ProtectionType includes BEHAVIOR protection."""
        assert hasattr(ProtectionType, "BEHAVIOR")
        assert ProtectionType.BEHAVIOR.value == "Behavioral Analysis"

    def test_protection_type_has_root_detection(self) -> None:
        """ProtectionType includes ROOT_DETECTION protection."""
        assert hasattr(ProtectionType, "ROOT_DETECTION")
        assert ProtectionType.ROOT_DETECTION.value == "Root Detection"

    def test_protection_type_has_integrity_check(self) -> None:
        """ProtectionType includes INTEGRITY_CHECK protection."""
        assert hasattr(ProtectionType, "INTEGRITY_CHECK")
        assert ProtectionType.INTEGRITY_CHECK.value == "Integrity Check"

    def test_protection_type_has_unknown(self) -> None:
        """ProtectionType includes UNKNOWN protection."""
        assert hasattr(ProtectionType, "UNKNOWN")
        assert ProtectionType.UNKNOWN.value == "Unknown Protection"

    def test_protection_type_enum_count(self) -> None:
        """ProtectionType enum contains all expected protection types."""
        protection_types = list(ProtectionType)
        assert len(protection_types) == 17

    def test_protection_type_values_are_strings(self) -> None:
        """ProtectionType enum values are human-readable strings."""
        for prot_type in ProtectionType:
            assert isinstance(prot_type.value, str)
            assert len(prot_type.value) > 0

    def test_protection_type_values_unique(self) -> None:
        """ProtectionType enum values are unique."""
        values = [prot.value for prot in ProtectionType]
        assert len(values) == len(set(values))

    def test_protection_type_names_unique(self) -> None:
        """ProtectionType enum names are unique."""
        names = [prot.name for prot in ProtectionType]
        assert len(names) == len(set(names))

    def test_protection_type_iteration(self) -> None:
        """ProtectionType enum is iterable."""
        count = 0
        for prot_type in ProtectionType:
            assert isinstance(prot_type, ProtectionType)
            count += 1
        assert count == 17

    def test_protection_type_comparison(self) -> None:
        """ProtectionType enum members can be compared."""
        assert ProtectionType.ANTI_DEBUG == ProtectionType.ANTI_DEBUG
        assert ProtectionType.ANTI_DEBUG != ProtectionType.LICENSE


class TestHookCategoryEnum:
    """Test HookCategory enumeration structure and values."""

    def test_hook_category_enum_exists(self) -> None:
        """HookCategory enum is defined and importable."""
        assert HookCategory is not None

    def test_hook_category_has_critical(self) -> None:
        """HookCategory includes CRITICAL priority."""
        assert hasattr(HookCategory, "CRITICAL")
        assert HookCategory.CRITICAL.value == "critical"

    def test_hook_category_has_high(self) -> None:
        """HookCategory includes HIGH priority."""
        assert hasattr(HookCategory, "HIGH")
        assert HookCategory.HIGH.value == "high"

    def test_hook_category_has_medium(self) -> None:
        """HookCategory includes MEDIUM priority."""
        assert hasattr(HookCategory, "MEDIUM")
        assert HookCategory.MEDIUM.value == "medium"

    def test_hook_category_has_low(self) -> None:
        """HookCategory includes LOW priority."""
        assert hasattr(HookCategory, "LOW")
        assert HookCategory.LOW.value == "low"

    def test_hook_category_has_monitoring(self) -> None:
        """HookCategory includes MONITORING priority."""
        assert hasattr(HookCategory, "MONITORING")
        assert HookCategory.MONITORING.value == "monitoring"

    def test_hook_category_enum_count(self) -> None:
        """HookCategory enum contains all expected categories."""
        categories = list(HookCategory)
        assert len(categories) == 5

    def test_hook_category_values_are_strings(self) -> None:
        """HookCategory enum values are strings."""
        for category in HookCategory:
            assert isinstance(category.value, str)
            assert len(category.value) > 0

    def test_hook_category_values_unique(self) -> None:
        """HookCategory enum values are unique."""
        values = [cat.value for cat in HookCategory]
        assert len(values) == len(set(values))

    def test_hook_category_names_unique(self) -> None:
        """HookCategory enum names are unique."""
        names = [cat.name for cat in HookCategory]
        assert len(names) == len(set(names))

    def test_hook_category_iteration(self) -> None:
        """HookCategory enum is iterable."""
        count = 0
        for category in HookCategory:
            assert isinstance(category, HookCategory)
            count += 1
        assert count == 5

    def test_hook_category_comparison(self) -> None:
        """HookCategory enum members can be compared."""
        assert HookCategory.CRITICAL == HookCategory.CRITICAL
        assert HookCategory.CRITICAL != HookCategory.LOW


class TestModuleExports:
    """Test module-level exports."""

    def test_module_exports_protection_type(self) -> None:
        """Module __all__ exports ProtectionType."""
        from intellicrack.core.frida_constants import __all__

        assert "ProtectionType" in __all__

    def test_module_exports_hook_category(self) -> None:
        """Module __all__ exports HookCategory."""
        from intellicrack.core.frida_constants import __all__

        assert "HookCategory" in __all__

    def test_module_exports_count(self) -> None:
        """Module __all__ exports exactly 2 items."""
        from intellicrack.core.frida_constants import __all__

        assert len(__all__) == 2


class TestEnumUsage:
    """Test practical enum usage patterns."""

    def test_protection_type_access_by_name(self) -> None:
        """ProtectionType members accessible by name."""
        prot = ProtectionType.ANTI_DEBUG
        assert prot.name == "ANTI_DEBUG"
        assert prot.value == "Anti-Debugging"

    def test_protection_type_access_by_value(self) -> None:
        """ProtectionType members accessible by value."""
        prot = ProtectionType("Anti-Debugging")
        assert prot == ProtectionType.ANTI_DEBUG

    def test_hook_category_access_by_name(self) -> None:
        """HookCategory members accessible by name."""
        cat = HookCategory.CRITICAL
        assert cat.name == "CRITICAL"
        assert cat.value == "critical"

    def test_hook_category_access_by_value(self) -> None:
        """HookCategory members accessible by value."""
        cat = HookCategory("critical")
        assert cat == HookCategory.CRITICAL

    def test_protection_type_in_set(self) -> None:
        """ProtectionType members can be used in sets."""
        protection_set = {ProtectionType.ANTI_DEBUG, ProtectionType.LICENSE}
        assert ProtectionType.ANTI_DEBUG in protection_set
        assert ProtectionType.ANTI_VM not in protection_set

    def test_hook_category_in_dict(self) -> None:
        """HookCategory members can be used as dictionary keys."""
        hook_delays = {
            HookCategory.CRITICAL: 0,
            HookCategory.HIGH: 100,
            HookCategory.MEDIUM: 500,
            HookCategory.LOW: 2000,
            HookCategory.MONITORING: 5000,
        }
        assert hook_delays[HookCategory.CRITICAL] == 0
        assert hook_delays[HookCategory.LOW] == 2000
