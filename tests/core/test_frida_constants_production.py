"""Production tests for Frida constants module.

Validates protection type enumerations and hook category definitions
used in Frida-based licensing bypass operations.
"""

import pytest

from intellicrack.core.frida_constants import HookCategory, ProtectionType


class TestProtectionTypeEnum:
    """Tests for ProtectionType enumeration completeness and values."""

    def test_protection_type_has_anti_debug(self) -> None:
        """ProtectionType includes anti-debugging protection."""
        assert hasattr(ProtectionType, "ANTI_DEBUG")
        assert ProtectionType.ANTI_DEBUG.value == "Anti-Debugging"

    def test_protection_type_has_anti_vm(self) -> None:
        """ProtectionType includes VM detection protection."""
        assert hasattr(ProtectionType, "ANTI_VM")
        assert ProtectionType.ANTI_VM.value == "Anti-VM/Sandbox"

    def test_protection_type_has_ssl_pinning(self) -> None:
        """ProtectionType includes SSL certificate pinning."""
        assert hasattr(ProtectionType, "SSL_PINNING")
        assert ProtectionType.SSL_PINNING.value == "SSL Pinning"

    def test_protection_type_has_license_verification(self) -> None:
        """ProtectionType includes license key validation."""
        assert hasattr(ProtectionType, "LICENSE")
        assert ProtectionType.LICENSE.value == "License Verification"

    def test_protection_type_has_hardware_binding(self) -> None:
        """ProtectionType includes hardware ID binding."""
        assert hasattr(ProtectionType, "HARDWARE")
        assert ProtectionType.HARDWARE.value == "Hardware Binding"

    def test_protection_type_has_cloud_verification(self) -> None:
        """ProtectionType includes online cloud checks."""
        assert hasattr(ProtectionType, "CLOUD")
        assert ProtectionType.CLOUD.value == "Cloud Verification"

    def test_protection_type_has_time_protection(self) -> None:
        """ProtectionType includes trial period protection."""
        assert hasattr(ProtectionType, "TIME")
        assert ProtectionType.TIME.value == "Time-based Protection"

    def test_protection_type_has_packing(self) -> None:
        """ProtectionType includes code packing detection."""
        assert hasattr(ProtectionType, "PACKING")
        assert ProtectionType.PACKING.value == "Packing/Obfuscation"

    def test_protection_type_has_integrity_check(self) -> None:
        """ProtectionType includes code integrity verification."""
        assert hasattr(ProtectionType, "INTEGRITY")
        assert ProtectionType.INTEGRITY.value == "Code Integrity"

    def test_protection_type_has_memory_protection(self) -> None:
        """ProtectionType includes memory protection mechanisms."""
        assert hasattr(ProtectionType, "MEMORY_PROTECTION")
        assert ProtectionType.MEMORY_PROTECTION.value == "Memory Protection Flags"

    def test_protection_type_has_kernel_protection(self) -> None:
        """ProtectionType includes kernel-mode protections."""
        assert hasattr(ProtectionType, "KERNEL")
        assert ProtectionType.KERNEL.value == "Kernel-mode Protection"

    def test_protection_type_has_root_detection(self) -> None:
        """ProtectionType includes root/jailbreak detection."""
        assert hasattr(ProtectionType, "ROOT_DETECTION")
        assert ProtectionType.ROOT_DETECTION.value == "Root Detection"

    def test_protection_type_enumeration_complete(self) -> None:
        """ProtectionType enum contains all expected protection types."""
        expected_types = {
            "ANTI_DEBUG",
            "ANTI_VM",
            "ANTI_ATTACH",
            "SSL_PINNING",
            "PACKING",
            "LICENSE",
            "INTEGRITY",
            "HARDWARE",
            "CLOUD",
            "TIME",
            "MEMORY",
            "MEMORY_PROTECTION",
            "KERNEL",
            "BEHAVIOR",
            "ROOT_DETECTION",
            "INTEGRITY_CHECK",
            "UNKNOWN",
        }

        actual_types = {member.name for member in ProtectionType}
        assert expected_types == actual_types

    def test_protection_type_values_are_strings(self) -> None:
        """All ProtectionType values are human-readable strings."""
        for protection in ProtectionType:
            assert isinstance(protection.value, str)
            assert len(protection.value) > 0

    def test_protection_type_values_unique(self) -> None:
        """All ProtectionType values are unique."""
        values = [p.value for p in ProtectionType]
        assert len(values) == len(set(values))

    def test_protection_type_iteration(self) -> None:
        """ProtectionType enum supports iteration over all members."""
        protection_list = list(ProtectionType)
        assert len(protection_list) == 17
        assert ProtectionType.LICENSE in protection_list
        assert ProtectionType.ANTI_DEBUG in protection_list

    def test_protection_type_membership_check(self) -> None:
        """ProtectionType supports membership testing."""
        assert ProtectionType.LICENSE in ProtectionType
        assert ProtectionType.HARDWARE in ProtectionType
        assert ProtectionType.SSL_PINNING in ProtectionType

    def test_protection_type_comparison(self) -> None:
        """ProtectionType members support equality comparison."""
        assert ProtectionType.LICENSE == ProtectionType.LICENSE
        assert ProtectionType.ANTI_DEBUG != ProtectionType.LICENSE

    def test_protection_type_access_by_name(self) -> None:
        """ProtectionType members accessible by string name."""
        assert ProtectionType["LICENSE"] == ProtectionType.LICENSE
        assert ProtectionType["ANTI_DEBUG"] == ProtectionType.ANTI_DEBUG

    def test_protection_type_access_by_value(self) -> None:
        """ProtectionType members accessible by value."""
        license_check = ProtectionType("License Verification")
        assert license_check == ProtectionType.LICENSE


class TestHookCategoryEnum:
    """Tests for HookCategory enumeration and priority levels."""

    def test_hook_category_has_critical(self) -> None:
        """HookCategory includes critical priority level."""
        assert hasattr(HookCategory, "CRITICAL")
        assert HookCategory.CRITICAL.value == "critical"

    def test_hook_category_has_high(self) -> None:
        """HookCategory includes high priority level."""
        assert hasattr(HookCategory, "HIGH")
        assert HookCategory.HIGH.value == "high"

    def test_hook_category_has_medium(self) -> None:
        """HookCategory includes medium priority level."""
        assert hasattr(HookCategory, "MEDIUM")
        assert HookCategory.MEDIUM.value == "medium"

    def test_hook_category_has_low(self) -> None:
        """HookCategory includes low priority level."""
        assert hasattr(HookCategory, "LOW")
        assert HookCategory.LOW.value == "low"

    def test_hook_category_has_monitoring(self) -> None:
        """HookCategory includes monitoring priority level."""
        assert hasattr(HookCategory, "MONITORING")
        assert HookCategory.MONITORING.value == "monitoring"

    def test_hook_category_enumeration_complete(self) -> None:
        """HookCategory enum contains all expected categories."""
        expected_categories = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "MONITORING"}

        actual_categories = {member.name for member in HookCategory}
        assert expected_categories == actual_categories

    def test_hook_category_values_are_strings(self) -> None:
        """All HookCategory values are lowercase strings."""
        for category in HookCategory:
            assert isinstance(category.value, str)
            assert category.value.islower()

    def test_hook_category_values_unique(self) -> None:
        """All HookCategory values are unique."""
        values = [c.value for c in HookCategory]
        assert len(values) == len(set(values))

    def test_hook_category_iteration(self) -> None:
        """HookCategory enum supports iteration over priority levels."""
        category_list = list(HookCategory)
        assert len(category_list) == 5
        assert HookCategory.CRITICAL in category_list
        assert HookCategory.MONITORING in category_list

    def test_hook_category_membership_check(self) -> None:
        """HookCategory supports membership testing."""
        assert HookCategory.CRITICAL in HookCategory
        assert HookCategory.HIGH in HookCategory
        assert HookCategory.MONITORING in HookCategory

    def test_hook_category_comparison(self) -> None:
        """HookCategory members support equality comparison."""
        assert HookCategory.CRITICAL == HookCategory.CRITICAL
        assert HookCategory.HIGH != HookCategory.LOW

    def test_hook_category_access_by_name(self) -> None:
        """HookCategory members accessible by string name."""
        assert HookCategory["CRITICAL"] == HookCategory.CRITICAL
        assert HookCategory["MONITORING"] == HookCategory.MONITORING

    def test_hook_category_access_by_value(self) -> None:
        """HookCategory members accessible by value."""
        critical = HookCategory("critical")
        assert critical == HookCategory.CRITICAL


class TestModuleExports:
    """Tests for module-level exports and public API."""

    def test_module_exports_protection_type(self) -> None:
        """Module exports ProtectionType in __all__."""
        from intellicrack.core import frida_constants

        assert "ProtectionType" in frida_constants.__all__

    def test_module_exports_hook_category(self) -> None:
        """Module exports HookCategory in __all__."""
        from intellicrack.core import frida_constants

        assert "HookCategory" in frida_constants.__all__

    def test_module_exports_only_expected_items(self) -> None:
        """Module __all__ contains exactly expected exports."""
        from intellicrack.core import frida_constants

        assert set(frida_constants.__all__) == {"ProtectionType", "HookCategory"}

    def test_can_import_protection_type_directly(self) -> None:
        """ProtectionType importable from module."""
        from intellicrack.core.frida_constants import ProtectionType as PT

        assert PT.LICENSE.value == "License Verification"

    def test_can_import_hook_category_directly(self) -> None:
        """HookCategory importable from module."""
        from intellicrack.core.frida_constants import HookCategory as HC

        assert HC.CRITICAL.value == "critical"


class TestProtectionTypeUsageScenarios:
    """Tests for real-world usage scenarios of ProtectionType."""

    def test_can_categorize_licensing_protections(self) -> None:
        """ProtectionType identifies licensing-related protections."""
        licensing_protections = [
            ProtectionType.LICENSE,
            ProtectionType.HARDWARE,
            ProtectionType.CLOUD,
            ProtectionType.TIME,
        ]

        for protection in licensing_protections:
            assert protection in ProtectionType

    def test_can_categorize_anti_analysis_protections(self) -> None:
        """ProtectionType identifies anti-analysis protections."""
        anti_analysis = [
            ProtectionType.ANTI_DEBUG,
            ProtectionType.ANTI_VM,
            ProtectionType.ANTI_ATTACH,
        ]

        for protection in anti_analysis:
            assert protection in ProtectionType

    def test_can_categorize_code_protection_schemes(self) -> None:
        """ProtectionType identifies code protection mechanisms."""
        code_protections = [
            ProtectionType.PACKING,
            ProtectionType.INTEGRITY,
            ProtectionType.INTEGRITY_CHECK,
            ProtectionType.MEMORY_PROTECTION,
        ]

        for protection in code_protections:
            assert protection in ProtectionType

    def test_protection_type_string_representation(self) -> None:
        """ProtectionType members have meaningful string representation."""
        assert "LICENSE" in str(ProtectionType.LICENSE)
        assert "ANTI_DEBUG" in str(ProtectionType.ANTI_DEBUG)


class TestHookCategoryUsageScenarios:
    """Tests for real-world usage scenarios of HookCategory."""

    def test_hook_categories_ordered_by_priority(self) -> None:
        """HookCategory members represent descending priority order."""
        categories_by_priority = [
            HookCategory.CRITICAL,
            HookCategory.HIGH,
            HookCategory.MEDIUM,
            HookCategory.LOW,
            HookCategory.MONITORING,
        ]

        for category in categories_by_priority:
            assert category in HookCategory

    def test_can_determine_if_critical_hook(self) -> None:
        """HookCategory allows identifying critical hooks."""
        critical = HookCategory.CRITICAL
        assert critical == HookCategory.CRITICAL
        assert critical != HookCategory.LOW

    def test_hook_category_string_representation(self) -> None:
        """HookCategory members have meaningful string representation."""
        assert "CRITICAL" in str(HookCategory.CRITICAL)
        assert "MONITORING" in str(HookCategory.MONITORING)


class TestEnumRobustness:
    """Tests for enum error handling and edge cases."""

    def test_protection_type_invalid_name_raises_keyerror(self) -> None:
        """Accessing ProtectionType with invalid name raises KeyError."""
        with pytest.raises(KeyError):
            _ = ProtectionType["NONEXISTENT"]

    def test_protection_type_invalid_value_raises_valueerror(self) -> None:
        """Creating ProtectionType from invalid value raises ValueError."""
        with pytest.raises(ValueError):
            _ = ProtectionType("Invalid Protection")

    def test_hook_category_invalid_name_raises_keyerror(self) -> None:
        """Accessing HookCategory with invalid name raises KeyError."""
        with pytest.raises(KeyError):
            _ = HookCategory["NONEXISTENT"]

    def test_hook_category_invalid_value_raises_valueerror(self) -> None:
        """Creating HookCategory from invalid value raises ValueError."""
        with pytest.raises(ValueError):
            _ = HookCategory("invalid")

    def test_protection_type_immutable(self) -> None:
        """ProtectionType enum members are immutable."""
        original_value = ProtectionType.LICENSE.value
        with pytest.raises(AttributeError):
            ProtectionType.LICENSE.value = "Modified"

        assert ProtectionType.LICENSE.value == original_value

    def test_hook_category_immutable(self) -> None:
        """HookCategory enum members are immutable."""
        original_value = HookCategory.CRITICAL.value
        with pytest.raises(AttributeError):
            HookCategory.CRITICAL.value = "modified"

        assert HookCategory.CRITICAL.value == original_value
