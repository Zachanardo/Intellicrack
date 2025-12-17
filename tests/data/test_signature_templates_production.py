import re
from typing import Any

import pytest

from intellicrack.data.signature_templates import (
    SignatureTemplates,
    get_signature_template,
    get_template_description,
)


class TestSignatureTemplatesCategories:
    def test_get_all_categories_returns_list(self) -> None:
        categories = SignatureTemplates.get_all_categories()

        assert isinstance(categories, list)
        assert len(categories) > 0

    def test_get_all_categories_contains_expected(self) -> None:
        categories = SignatureTemplates.get_all_categories()

        assert "Basic Patterns" in categories
        assert "PE Headers" in categories
        assert "Section Signatures" in categories
        assert "Import Signatures" in categories
        assert "String Signatures" in categories
        assert "Packer Signatures" in categories
        assert "Protector Signatures" in categories
        assert "Cryptor Signatures" in categories
        assert "Complex Rules" in categories

    def test_all_categories_are_unique(self) -> None:
        categories = SignatureTemplates.get_all_categories()

        assert len(categories) == len(set(categories))

    def test_categories_are_non_empty_strings(self) -> None:
        categories = SignatureTemplates.get_all_categories()

        for category in categories:
            assert isinstance(category, str)
            assert len(category) > 0


class TestSignatureTemplatesForCategory:
    def test_get_templates_for_valid_category(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("Basic Patterns")

        assert isinstance(templates, dict)
        assert len(templates) > 0

    def test_get_templates_for_invalid_category(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("Invalid Category")

        assert isinstance(templates, dict)
        assert len(templates) == 0

    def test_all_categories_have_templates(self) -> None:
        categories = SignatureTemplates.get_all_categories()

        for category in categories:
            templates = SignatureTemplates.get_templates_for_category(category)
            assert len(templates) > 0


class TestBasicPatternsTemplates:
    def test_simple_hex_pattern_template(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("Basic Patterns")

        assert "Simple Hex Pattern" in templates
        assert "template" in templates["Simple Hex Pattern"]
        assert "description" in templates["Simple Hex Pattern"]

    def test_simple_hex_pattern_content(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("Basic Patterns")
        template = templates["Simple Hex Pattern"]["template"]

        assert "init:" in template
        assert "ep:" in template
        assert "hex =" in template
        assert "48 65 6C 6C 6F" in template

    def test_wildcard_pattern_template(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("Basic Patterns")

        assert "Wildcard Pattern" in templates
        template = templates["Wildcard Pattern"]["template"]

        assert "??" in template
        assert "4D 5A" in template
        assert "50 45" in template

    def test_multiple_patterns_template(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("Basic Patterns")

        assert "Multiple Patterns" in templates
        template = templates["Multiple Patterns"]["template"]

        pattern_count = template.count('hex =')
        assert pattern_count >= 3


class TestPEHeadersTemplates:
    def test_dos_header_check_template(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("PE Headers")

        assert "DOS Header Check" in templates
        template = templates["DOS Header Check"]["template"]

        assert "4D 5A" in template
        assert "header:" in template
        assert "offset = 0" in template

    def test_pe_header_check_template(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("PE Headers")

        assert "PE Header Check" in templates
        template = templates["PE Header Check"]["template"]

        assert "50 45 00 00" in template
        assert "PE_OFFSET" in template

    def test_rich_header_template(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("PE Headers")

        assert "Rich Header" in templates
        template = templates["Rich Header"]["template"]

        assert "52 69 63 68" in template
        assert "44 61 6E 53" in template


class TestSectionSignaturesTemplates:
    def test_code_section_template(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("Section Signatures")

        assert "Code Section" in templates
        template = templates["Code Section"]["template"]

        assert "section:" in template
        assert ".text" in template
        assert "55 8B EC" in template

    def test_upx_sections_template(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("Section Signatures")

        assert "UPX Sections" in templates
        template = templates["UPX Sections"]["template"]

        assert "UPX0" in template
        assert "UPX1" in template
        assert ".rsrc" in template

    def test_high_entropy_section_template(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("Section Signatures")

        assert "High Entropy Section" in templates
        template = templates["High Entropy Section"]["template"]

        assert "entropy =" in template
        assert "> 7.0" in template
        assert "characteristics" in template


class TestImportSignaturesTemplates:
    def test_crypto_apis_template(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("Import Signatures")

        assert "Crypto APIs" in templates
        template = templates["Crypto APIs"]["template"]

        assert "import:" in template
        assert "advapi32.dll" in template
        assert "CryptAcquireContext" in template
        assert "CryptCreateHash" in template
        assert "CryptHashData" in template
        assert "CryptDeriveKey" in template

    def test_debug_apis_template(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("Import Signatures")

        assert "Debug APIs" in templates
        template = templates["Debug APIs"]["template"]

        assert "kernel32.dll" in template
        assert "ntdll.dll" in template
        assert "IsDebuggerPresent" in template
        assert "NtQueryInformationProcess" in template

    def test_injection_apis_template(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("Import Signatures")

        assert "Injection APIs" in templates
        template = templates["Injection APIs"]["template"]

        assert "VirtualAllocEx" in template
        assert "WriteProcessMemory" in template
        assert "CreateRemoteThread" in template
        assert "OpenProcess" in template


class TestStringSignaturesTemplates:
    def test_ascii_strings_template(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("String Signatures")

        assert "ASCII Strings" in templates
        template = templates["ASCII Strings"]["template"]

        assert "string:" in template
        assert "ascii =" in template

    def test_unicode_strings_template(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("String Signatures")

        assert "Unicode Strings" in templates
        template = templates["Unicode Strings"]["template"]

        assert "unicode =" in template

    def test_regex_patterns_template(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("String Signatures")

        assert "Regex Patterns" in templates
        template = templates["Regex Patterns"]["template"]

        assert "regex =" in template
        assert re.search(r"regex.*=", template)


class TestPackerSignaturesTemplates:
    def test_upx_packer_template(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("Packer Signatures")

        assert "UPX Packer" in templates
        template = templates["UPX Packer"]["template"]

        assert "name = \"UPX\"" in template
        assert "type = \"Packer\"" in template
        assert "UPX0" in template
        assert "UPX1" in template
        assert "60 BE ?? ?? ?? ??" in template

    def test_aspack_template(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("Packer Signatures")

        assert "ASPack" in templates
        template = templates["ASPack"]["template"]

        assert "ASPack" in template
        assert "aPLib" in template

    def test_pecompact_template(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("Packer Signatures")

        assert "PECompact" in templates
        template = templates["PECompact"]["template"]

        assert "PEC2TO" in template


class TestProtectorSignaturesTemplates:
    def test_themida_template(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("Protector Signatures")

        assert "Themida" in templates
        template = templates["Themida"]["template"]

        assert ".themida" in template
        assert "WinLicense" in template
        assert "SecureEngine" in template
        assert "VirtualProtect" in template

    def test_vmprotect_template(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("Protector Signatures")

        assert "VMProtect" in templates
        template = templates["VMProtect"]["template"]

        assert ".vmp0" in template
        assert ".vmp1" in template
        assert "VMProtectSDK.dll" in template

    def test_code_virtualizer_template(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("Protector Signatures")

        assert "Code Virtualizer" in templates
        template = templates["Code Virtualizer"]["template"]

        assert ".cv" in template
        assert "Oreans" in template


class TestCryptorSignaturesTemplates:
    def test_custom_cryptor_template(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("Cryptor Signatures")

        assert "Custom Cryptor" in templates
        template = templates["Custom Cryptor"]["template"]

        assert "CryptAcquireContext" in template
        assert "entropy =" in template
        assert "> 7.5" in template

    def test_xor_cryptor_template(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("Cryptor Signatures")

        assert "XOR Cryptor" in templates
        template = templates["XOR Cryptor"]["template"]

        assert "XOR" in template or "xor" in template.lower()


class TestComplexRulesTemplates:
    def test_conditional_logic_template(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("Complex Rules")

        assert "Conditional Logic" in templates
        template = templates["Conditional Logic"]["template"]

        assert "rule:" in template
        assert "condition =" in template
        assert "and" in template or "or" in template

    def test_size_constraints_template(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("Complex Rules")

        assert "Size Constraints" in templates
        template = templates["Size Constraints"]["template"]

        assert "filesize =" in template
        assert "sections =" in template
        assert "imports =" in template
        assert "exports =" in template

    def test_multi_stage_detection_template(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("Complex Rules")

        assert "Multi-Stage Detection" in templates
        template = templates["Multi-Stage Detection"]["template"]

        assert "stage1:" in template
        assert "stage2:" in template
        assert "stage3:" in template


class TestSampleSignatures:
    def test_get_sample_signatures_returns_dict(self) -> None:
        samples = SignatureTemplates.get_sample_signatures()

        assert isinstance(samples, dict)
        assert len(samples) > 0

    def test_sample_signatures_keys(self) -> None:
        samples = SignatureTemplates.get_sample_signatures()

        assert "upx_packer.sg" in samples
        assert "vmprotect.sg" in samples
        assert "debug_detection.sg" in samples

    def test_upx_sample_signature_content(self) -> None:
        samples = SignatureTemplates.get_sample_signatures()
        upx_sig = samples["upx_packer.sg"]

        assert "name = \"UPX\"" in upx_sig
        assert "type = \"Packer\"" in upx_sig
        assert "UPX0" in upx_sig
        assert "UPX1" in upx_sig
        assert "60 BE ?? ?? ?? ??" in upx_sig
        assert "UPX!" in upx_sig

    def test_vmprotect_sample_signature_content(self) -> None:
        samples = SignatureTemplates.get_sample_signatures()
        vmp_sig = samples["vmprotect.sg"]

        assert "VMProtect" in vmp_sig
        assert ".vmp0" in vmp_sig
        assert ".vmp1" in vmp_sig
        assert "VMProtectSDK32.dll" in vmp_sig or "VMProtectSDK64.dll" in vmp_sig
        assert "VMProtectBegin" in vmp_sig
        assert "VMProtectEnd" in vmp_sig

    def test_debug_detection_sample_signature_content(self) -> None:
        samples = SignatureTemplates.get_sample_signatures()
        debug_sig = samples["debug_detection.sg"]

        assert "Anti-Debug" in debug_sig
        assert "IsDebuggerPresent" in debug_sig
        assert "CheckRemoteDebuggerPresent" in debug_sig
        assert "NtQueryInformationProcess" in debug_sig

    def test_sample_signatures_are_valid_format(self) -> None:
        samples = SignatureTemplates.get_sample_signatures()

        for filename, signature in samples.items():
            assert filename.endswith(".sg")
            assert "init:" in signature
            assert "name =" in signature
            assert "type =" in signature


class TestGetSignatureTemplate:
    def test_get_signature_template_valid(self) -> None:
        template = get_signature_template("Basic Patterns", "Simple Hex Pattern")

        assert len(template) > 0
        assert "init:" in template
        assert "ep:" in template

    def test_get_signature_template_invalid_category(self) -> None:
        template = get_signature_template("Invalid Category", "Simple Hex Pattern")

        assert template == ""

    def test_get_signature_template_invalid_name(self) -> None:
        template = get_signature_template("Basic Patterns", "Invalid Name")

        assert template == ""

    def test_get_signature_template_all_categories(self) -> None:
        categories = SignatureTemplates.get_all_categories()

        for category in categories:
            templates = SignatureTemplates.get_templates_for_category(category)
            for template_name in templates.keys():
                template = get_signature_template(category, template_name)
                assert len(template) > 0


class TestGetTemplateDescription:
    def test_get_template_description_valid(self) -> None:
        description = get_template_description("Basic Patterns", "Simple Hex Pattern")

        assert len(description) > 0
        assert description == "Basic hexadecimal pattern matching"

    def test_get_template_description_invalid_category(self) -> None:
        description = get_template_description("Invalid Category", "Simple Hex Pattern")

        assert description == ""

    def test_get_template_description_invalid_name(self) -> None:
        description = get_template_description("Basic Patterns", "Invalid Name")

        assert description == ""

    def test_get_template_description_all_templates(self) -> None:
        categories = SignatureTemplates.get_all_categories()

        for category in categories:
            templates = SignatureTemplates.get_templates_for_category(category)
            for template_name in templates.keys():
                description = get_template_description(category, template_name)
                assert len(description) > 0


class TestTemplateStructureValidity:
    def test_all_templates_have_init_section(self) -> None:
        categories = SignatureTemplates.get_all_categories()

        for category in categories:
            templates = SignatureTemplates.get_templates_for_category(category)
            for template_name, template_data in templates.items():
                template = template_data["template"]
                assert "init:" in template

    def test_all_templates_have_name_field(self) -> None:
        categories = SignatureTemplates.get_all_categories()

        for category in categories:
            templates = SignatureTemplates.get_templates_for_category(category)
            for template_name, template_data in templates.items():
                template = template_data["template"]
                assert "name =" in template

    def test_all_templates_have_type_field(self) -> None:
        categories = SignatureTemplates.get_all_categories()

        for category in categories:
            templates = SignatureTemplates.get_templates_for_category(category)
            for template_name, template_data in templates.items():
                template = template_data["template"]
                assert "type =" in template

    def test_all_templates_have_description(self) -> None:
        categories = SignatureTemplates.get_all_categories()

        for category in categories:
            templates = SignatureTemplates.get_templates_for_category(category)
            for template_name, template_data in templates.items():
                assert "description" in template_data
                assert len(template_data["description"]) > 0


class TestTemplateContentValidation:
    def test_hex_patterns_are_valid_format(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("Basic Patterns")

        for template_name, template_data in templates.items():
            template = template_data["template"]
            if "hex =" in template:
                hex_matches = re.findall(r'hex = "([^"]+)"', template)
                for hex_pattern in hex_matches:
                    parts = hex_pattern.split()
                    for part in parts:
                        assert re.match(r"^([0-9A-Fa-f]{2}|\?\?)$", part)

    def test_section_names_are_strings(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("Section Signatures")

        for template_name, template_data in templates.items():
            template = template_data["template"]
            if 'name =' in template and 'section:' in template:
                section_names = re.findall(r'name = "([^"]+)"', template)
                for name in section_names:
                    assert isinstance(name, str)
                    assert len(name) > 0


class TestProtectionTypeValidation:
    def test_packer_templates_have_packer_type(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("Packer Signatures")

        for template_name, template_data in templates.items():
            template = template_data["template"]
            assert 'type = "Packer"' in template

    def test_protector_templates_have_protector_type(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("Protector Signatures")

        for template_name, template_data in templates.items():
            template = template_data["template"]
            assert 'type = "Protector"' in template

    def test_cryptor_templates_have_cryptor_type(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("Cryptor Signatures")

        for template_name, template_data in templates.items():
            template = template_data["template"]
            assert 'type = "Cryptor"' in template


class TestRealWorldSignatureMatching:
    def test_upx_signature_matches_known_pattern(self) -> None:
        samples = SignatureTemplates.get_sample_signatures()
        upx_sig = samples["upx_packer.sg"]

        assert "60 BE ?? ?? ?? ??" in upx_sig
        assert "UPX0" in upx_sig
        assert "UPX1" in upx_sig

    def test_vmprotect_signature_has_sdk_imports(self) -> None:
        samples = SignatureTemplates.get_sample_signatures()
        vmp_sig = samples["vmprotect.sg"]

        assert "VMProtectSDK" in vmp_sig
        assert "VMProtectBegin" in vmp_sig
        assert "VMProtectEnd" in vmp_sig

    def test_anti_debug_signature_covers_common_apis(self) -> None:
        samples = SignatureTemplates.get_sample_signatures()
        debug_sig = samples["debug_detection.sg"]

        common_debug_apis = [
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
        ]

        for api in common_debug_apis:
            assert api in debug_sig


class TestTemplateCompleteness:
    def test_all_template_categories_have_multiple_templates(self) -> None:
        categories = SignatureTemplates.get_all_categories()

        for category in categories:
            templates = SignatureTemplates.get_templates_for_category(category)
            assert len(templates) >= 2

    def test_import_signatures_cover_critical_apis(self) -> None:
        templates = SignatureTemplates.get_templates_for_category("Import Signatures")

        critical_api_categories = ["Crypto APIs", "Debug APIs", "Injection APIs"]

        for api_category in critical_api_categories:
            assert api_category in templates
